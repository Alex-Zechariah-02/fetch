// The flow demo up runs on a host that runs the gateway: the one-machine
// demonstration or the gateway host of a two-host setup. It builds, creates
// the deployment on the first run, starts everything, gives a new deployment
// its administrator and baseline, and runs until stopped.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

// gatewayHost is a host demo up runs the gateway on: the whole one-machine
// demonstration, or the gateway host of a two-host setup.
type gatewayHost struct {
	state     string   // the deployment's directory
	addresses []string // every address it listens on, free before it starts
	shopURL   string   // where browsers open the shop
	reused    string   // printed when a later run reuses the state
	build     func(source sources) (builtPrograms, error)
	create    func(programs builtPrograms, out io.Writer) error
	run       func(ctx context.Context, programs builtPrograms, ready func()) error
}

// localHost is the one-machine demonstration with its state in home.
func localHost(home string) gatewayHost {
	state, web := filepath.Join(home, "state"), filepath.Join(home, "web")
	return gatewayHost{
		state:     state,
		addresses: localAddresses(),
		shopURL:   "http://" + dataListen + "/",
		build: func(source sources) (builtPrograms, error) {
			programs, err := buildPrograms(source, filepath.Join(home, "bin"))
			if err != nil {
				return programs, err
			}
			return programs, buildWebsites(source, web)
		},
		create: func(programs builtPrograms, out io.Writer) error {
			return createDemo(state, web, programs.gateway, upAdmin, out)
		},
		run: func(ctx context.Context, programs builtPrograms, ready func()) error {
			return runDemo(ctx, state, web, programs.gateway, programs.services, programs.accounts, ready)
		},
	}
}

// up builds the host's programs and websites from the current sources,
// creates the deployment the first time and then establishes its baseline
// policy through the Admin API, prints the public demo accounts and runs
// everything until interrupted. Later runs reuse the administrator and
// policy; services restart from seed.
func (h gatewayHost) up(apiward string, fresh, stdin bool) error {
	// A running demonstration holds the ports and its program files.
	if err := checkFree(h.addresses); err != nil {
		return err
	}
	source, err := findSources(apiward)
	if err != nil {
		return err
	}
	if fresh {
		if err := removeState(h.state); err != nil {
			return err
		}
	}
	_, err = os.Stat(h.state)
	firstRun := errors.Is(err, os.ErrNotExist)
	if err != nil && !firstRun {
		return err
	}
	earlierSetup := false
	if !firstRun {
		if err := checkDemo(h.state); err != nil {
			lock, earlierErr := lockUnfinishedEarlierDemo(h.state)
			if earlierErr != nil {
				return errors.Join(err, earlierErr)
			}
			lock.Close()
			firstRun, earlierSetup = true, true
		}
	}
	if !firstRun && h.reused != "" {
		fmt.Println(h.reused)
	}

	// The password is chosen before anything is created, so stopping here
	// leaves nothing half set up.
	password := ""
	if firstRun {
		fmt.Println("First run: choose the password for the Dashboard administrator", upAdmin+".")
		if password, err = choosePassword(); err != nil {
			return err
		}
	}

	programs, err := h.build(source)
	if err != nil {
		return err
	}
	secret := ""
	if firstRun {
		if earlierSetup {
			preserved, err := preserveUnfinishedEarlierDemo(h.state)
			if err != nil {
				return err
			}
			fmt.Println("Preserved the unfinished earlier setup in", preserved)
		}
		var install bytes.Buffer
		if err := h.create(programs, &install); err != nil {
			return err
		}
		if secret, err = enrolmentSecret(install.String()); err != nil {
			os.RemoveAll(h.state)
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	running, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- h.run(running, programs, func() { close(ready) })
	}()
	select {
	case <-ready:
	case err := <-finished:
		return err
	}

	if err := prepareGateway(h.state, firstRun, secret, password); err != nil {
		cancel()
		return errors.Join(err, <-finished)
	}
	printSignIns()
	fmt.Printf("\nDashboard: http://%s/  (sign in as %s)\nShop:      %s\nPress Ctrl+C to stop.\n", adminListen, upAdmin, h.shopURL)
	if stdin {
		// Every password prompt is answered; the rest of the input only
		// signals the stop.
		go func() {
			io.Copy(io.Discard, stdinLines)
			stop()
		}()
	}
	return <-finished
}
