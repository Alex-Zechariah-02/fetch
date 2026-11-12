// Demo run: starts the Fetch services and the gateway, waits until they listen
// and the gateway reports its admission, and stops every child it started.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// run starts the five Fetch services and the gateway, reports when all of them
// accept connections, and stops them all on interrupt, when the gateway
// exits, or with -stdin when standard input closes. A service that stops is
// reported and left stopped, so the gateway's answer for an unavailable API
// can be shown. Process output goes to log files in the demonstration
// directory.
func run(args []string) (runErr error) {
	set := flag.NewFlagSet("run", flag.ContinueOnError)
	web := set.String("web", "", "built frontend directory holding demo/, the shop")
	gateway := set.String("gateway", "", "the apiward binary that plays the gateway")
	serviceBinary := set.String("services", "", "Fetch services binary")
	accountsBinary := set.String("accounts", "", "Fetch Accounts binary")
	stdin := set.Bool("stdin", false, "also stop when standard input closes")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if *web == "" || *gateway == "" || *serviceBinary == "" || *accountsBinary == "" {
		return errors.New("-web, -gateway, -services and -accounts are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *stdin {
		go func() {
			io.Copy(io.Discard, os.Stdin)
			stop()
		}()
	}
	return runDemo(ctx, dir, *web, *gateway, *serviceBinary, *accountsBinary, nil)
}

// runDemo is run's work: it serves the shop in web/demo itself and stops
// everything when ctx ends. ready, if not nil, is called once every process
// listens and the gateway has reported its admission status.
func runDemo(ctx context.Context, dir, web, gateway, serviceBinary, accountsBinary string, ready func()) (runErr error) {
	if err := checkDemo(dir); err != nil {
		return err
	}
	if err := checkFree(localAddresses()); err != nil {
		return err
	}
	shop := filepath.Join(web, "demo")
	if _, err := os.Stat(filepath.Join(shop, "index.html")); err != nil {
		return fmt.Errorf("-web %s has no demo/index.html: build the shop first", web)
	}
	siteListener, err := services.Listen(siteListen, services.Ingress{})
	if err != nil {
		return fmt.Errorf("the website address: %w", err)
	}
	siteCtx, stopSite := context.WithCancel(context.Background())
	siteDone := make(chan error, 1)
	go func() { siteDone <- serveWebsite(siteCtx, siteListener, os.DirFS(shop)) }()
	// The website stops last, after every child, so the gateway never
	// forwards to a closed shop while it still admits requests.
	defer func() {
		stopSite()
		if err := <-siteDone; err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("the website stopped: %w", err))
		}
	}()

	running := newChildren(dir, len(fetchServices)+1)
	defer func() { runErr = errors.Join(runErr, running.stop()) }()
	// The APIs require the gateway's assertion while its key set is in the
	// directory; without the file they answer direct requests too, which a
	// direct measurement of an API needs.
	if _, err := os.Stat(filepath.Join(dir, assertionSetFile)); err == nil {
		running.keySet = filepath.Join(dir, assertionSetFile)
	}
	addresses, err := running.startServices(dir, serviceBinary, accountsBinary, nil, false)
	if err != nil {
		return err
	}
	shopURL := fmt.Sprintf("http://%s/ (served from %s through the gateway)", dataListen, siteListen)
	return running.runGateway(ctx, gateway, addresses, siteDone, shopURL, ready)
}

// runGateway starts the gateway with the settings in the children's
// directory, waits until it and every one of addresses listen and the gateway
// reports its admission, calls ready (if not nil), and then supervises until
// ctx ends, the gateway exits or the website stops (siteDone, nil when this
// host serves none). A service that stops is reported and left stopped.
func (c *children) runGateway(ctx context.Context, gateway string, addresses []string, siteDone chan error, shopURL string, ready func()) error {
	logStart, err := c.start("gateway", gateway, "run", "--config", filepath.Join(c.dir, configFile))
	if err != nil {
		return err
	}
	addresses = append(addresses, adminListen, dataListen, metricsListen)
	deadline := time.Now().Add(30 * time.Second)
	if err := c.awaitListening(ctx, addresses, deadline); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}
	admission := ""
	for admission == "" {
		var err error
		admission, err = readAdmission(filepath.Join(c.dir, "gateway.log"), logStart)
		if err != nil {
			return err
		}
		if admission != "" {
			break
		}
		select {
		case result := <-c.exited:
			c.received()
			return fmt.Errorf("%s exited before admission status (%v); see its log in %s", result.name, result.err, c.dir)
		case <-ctx.Done():
			return nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("gateway did not report native admission status; see gateway.log")
		}
	}
	fmt.Printf("listening; protected admission: %s\n", admission)
	fmt.Printf("  dashboard: http://%s/\n  website:   %s\n", adminListen, shopURL)
	c.printProcesses()
	if ready != nil {
		ready()
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("stopping")
			return nil
		case err := <-siteDone:
			siteDone <- err
			return fmt.Errorf("the website stopped (%v)", err)
		case result := <-c.exited:
			c.received()
			if result.name == "gateway" {
				return fmt.Errorf("the gateway exited (%v); see %s", result.err, filepath.Join(c.dir, "gateway.log"))
			}
			fmt.Printf("service %s stopped (%v); its gateway requests can now fail\n", result.name, result.err)
		}
	}
}

// localAddresses are every address of the one-machine demonstration.
func localAddresses() []string {
	addresses := []string{adminListen, dataListen, metricsListen, siteListen}
	for _, service := range fetchServices {
		addresses = append(addresses, service.listen, service.control)
	}
	return addresses
}

// checkFree refuses a second demonstration on any of the same addresses.
func checkFree(addresses []string) error {
	for _, address := range addresses {
		if dialable(address) {
			return fmt.Errorf("%s is already in use; refusing to start a second demonstration", address)
		}
	}
	return nil
}

func dialable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
