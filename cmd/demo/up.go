// Demo up: the one-command local demonstration, from finding the sources and
// asking for the administrator password to running everything until stopped.

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
)

// The administrator enrolled by the one-command launcher.
const upAdmin = "root"

// sources are the two checkouts up builds from: APIWard (the gateway and its
// Dashboard) and this Fetch repository (the services, Accounts and the shop).
type sources struct{ apiward, fetch string }

// up runs the whole local demonstration with one command. It builds the
// gateway, the services and both websites from the current sources, creates
// the demonstration the first time and then establishes its baseline policy
// through the Admin API, prints the public demo accounts and runs everything until
// interrupted. Later runs reuse the administrator and policy; services restart from seed.
func up(args []string) error {
	set := flag.NewFlagSet("up", flag.ContinueOnError)
	home := set.String("home", defaultHome(), "folder for the built programs, websites and demonstration state")
	fresh := set.Bool("fresh", false, "delete the earlier demonstration state, including its administrator and policy, and start over")
	stdin := set.Bool("stdin", false, "also stop when standard input closes")
	apiward := set.String("apiward", "", "APIWard checkout that builds the gateway and the Dashboard (default: ../apiward beside this repository)")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("up takes no arguments\n" + usage)
	}
	homeDir, err := filepath.Abs(*home)
	if err != nil {
		return err
	}
	state := filepath.Join(homeDir, "state")
	bin := filepath.Join(homeDir, "bin")
	web := filepath.Join(homeDir, "web")

	// A running demonstration holds the ports and its program files.
	if err := checkPortsFree(); err != nil {
		return err
	}
	source, err := findSources(*apiward)
	if err != nil {
		return err
	}
	if *fresh {
		if err := removeState(state); err != nil {
			return err
		}
	}
	_, err = os.Stat(state)
	firstRun := errors.Is(err, os.ErrNotExist)
	if err != nil && !firstRun {
		return err
	}
	earlierSetup := false
	if !firstRun {
		if err := checkDemo(state); err != nil {
			lock, earlierErr := lockUnfinishedEarlierDemo(state)
			if earlierErr != nil {
				return errors.Join(err, earlierErr)
			}
			lock.Close()
			firstRun, earlierSetup = true, true
		}
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

	programs, err := buildPrograms(source, bin)
	if err != nil {
		return err
	}
	if err := buildWebsites(source, web); err != nil {
		return err
	}
	secret := ""
	if firstRun {
		if earlierSetup {
			preserved, err := preserveUnfinishedEarlierDemo(state)
			if err != nil {
				return err
			}
			fmt.Println("Preserved the unfinished earlier setup in", preserved)
		}
		var install bytes.Buffer
		if err := createDemo(state, web, programs.gateway, upAdmin, &install); err != nil {
			return err
		}
		if secret, err = enrolmentSecret(install.String()); err != nil {
			os.RemoveAll(state)
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
		finished <- runDemo(running, state, web, programs.gateway, programs.services, programs.accounts, func() { close(ready) })
	}()
	select {
	case <-ready:
	case err := <-finished:
		return err
	}

	if err := prepareGateway(state, firstRun, secret, password); err != nil {
		cancel()
		return errors.Join(err, <-finished)
	}
	printSignIns()
	fmt.Printf("\nDashboard: http://%s/  (sign in as %s)\nShop:      http://%s/\nPress Ctrl+C to stop.\n", adminListen, upAdmin, dataListen)
	if *stdin {
		// Every password prompt is answered; the rest of the input only
		// signals the stop.
		go func() {
			io.Copy(io.Discard, stdinLines)
			stop()
		}()
	}
	return <-finished
}

func defaultHome() string {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "EAT40005-demo"
	}
	return filepath.Join(cache, "EAT40005-demo")
}

// findSources finds this Fetch repository from the working directory's module,
// so up builds the sources it is run from, and the APIWard checkout: apiward,
// or else the folder apiward beside this repository.
func findSources(apiward string) (sources, error) {
	output, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return sources{}, fmt.Errorf("finding the Fetch repository with the go command: %w", err)
	}
	mod := strings.TrimSpace(string(output))
	if mod == "" || mod == os.DevNull {
		return sources{}, errors.New("run up from the Fetch repository: go run ./cmd/demo up")
	}
	fetch := filepath.Dir(mod)
	if _, err := os.Stat(filepath.Join(fetch, "cmd", "demo")); err != nil {
		return sources{}, fmt.Errorf("%s is not the Fetch repository", fetch)
	}
	if apiward == "" {
		apiward = filepath.Join(fetch, "..", "apiward")
	}
	if apiward, err = filepath.Abs(apiward); err != nil {
		return sources{}, err
	}
	if _, err := os.Stat(filepath.Join(apiward, "cmd", "gateway")); err != nil {
		return sources{}, fmt.Errorf("%s is not an APIWard checkout: clone github.com/Alex-Zechariah-02/apiward there or pass -apiward <folder>", apiward)
	}
	return sources{apiward: apiward, fetch: fetch}, nil
}

// removeState deletes an earlier demonstration directory, after checking it
// is one.
func removeState(state string) error {
	if _, err := os.Stat(state); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkDemo(state); err != nil {
		// Earlier native state is never run or migrated. An explicit -fresh
		// may replace it only when its original directory/file binding holds.
		if oldErr := checkEarlierDemoForFresh(state); oldErr != nil {
			return fmt.Errorf("not deleting %s: %w", state, errors.Join(err, oldErr))
		}
	}
	if err := os.RemoveAll(state); err != nil {
		return err
	}
	fmt.Println("Deleted the earlier demonstration state.")
	return nil
}

var stdinLines = bufio.NewReader(os.Stdin)

func readLine() (string, error) {
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// choosePassword asks for a new password twice. The gateway decides whether
// it is acceptable; the length check here only saves a failed enrolment.
func choosePassword() (string, error) {
	for {
		first, err := readSecretLine("Password (15 to 256 bytes, not shown): ")
		if err != nil {
			return "", err
		}
		second, err := readSecretLine("Repeat the password: ")
		if err != nil {
			return "", err
		}
		switch {
		case len(first) < 15 || len(first) > 256 || !utf8.ValidString(first):
			fmt.Println("Use 15 to 256 bytes. A phrase of at least 15 plain characters works.")
		case first != second:
			fmt.Println("The two passwords differ. Please enter them again.")
		default:
			return first, nil
		}
	}
}

func executable(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
