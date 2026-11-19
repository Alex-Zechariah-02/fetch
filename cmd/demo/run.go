// Demo run: starts the Fetch services and the gateway, waits until they listen
// and the gateway reports its admission, and stops every child it started.

package main

import (
	"context"
	"encoding/json"
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
	site, err := loadWebsite(os.DirFS(shop))
	if err != nil {
		return err
	}
	siteListener, err := services.Listen(siteListen, services.Ingress{})
	if err != nil {
		return fmt.Errorf("the website address: %w", err)
	}
	siteCtx, stopSite := context.WithCancel(context.Background())
	served := &stopped{done: make(chan struct{})}
	go func() {
		served.err = serveWebsite(siteCtx, siteListener, site)
		close(served.done)
	}()
	// The website stops last, after every child, so the gateway never
	// forwards to a closed shop while it still admits requests.
	defer func() {
		stopSite()
		<-served.done
		if served.err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("the website stopped: %w", served.err))
		}
	}()

	running := newChildren(dir, len(fetchServices)+1)
	defer func() { runErr = errors.Join(runErr, running.stop()) }()
	// The APIs require the gateway's assertion while its key set is in the
	// directory; without the file they answer direct requests too, which a
	// direct measurement of an API needs.
	_, err = os.Stat(filepath.Join(dir, assertionSetFile))
	switch {
	case err == nil:
		running.keySet = filepath.Join(dir, assertionSetFile)
	case errors.Is(err, os.ErrNotExist):
		fmt.Printf("no %s in %s: the APIs answer direct requests without the gateway's assertion\n", assertionSetFile, dir)
	default:
		return err
	}
	addresses, err := running.startServices(dir, serviceBinary, accountsBinary, nil, false)
	if err != nil {
		return err
	}
	shopURL := fmt.Sprintf("http://%s/ (served from %s through the gateway)", dataListen, siteListen)
	return running.runGateway(ctx, gateway, addresses, served, shopURL, ready)
}

// stopped is the result of a server goroutine: done closes once err is set,
// so any number of readers can wait for it and read err.
type stopped struct {
	done chan struct{}
	err  error
}

// wait is done, or nil (never ready) when there is no server.
func (s *stopped) wait() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

// runGateway starts the gateway with the settings in the children's
// directory, waits until it and every one of addresses listen and the gateway
// reports its admission, calls ready (if not nil), and then supervises until
// ctx ends, the gateway exits or the website stops (site, nil when this host
// serves none). A service that stops is reported and left stopped, and so is
// every later change of the gateway's protected admission.
func (c *children) runGateway(ctx context.Context, gateway string, addresses []string, site *stopped, shopURL string, ready func()) error {
	if err := checkOffset(c.dir); err != nil {
		return err
	}
	logStart, err := c.start("gateway", gateway, "run", "--config", filepath.Join(c.dir, configFile))
	if err != nil {
		return err
	}
	addresses = append(addresses, adminListen, dataListen, metricsListen)
	// Gives up instead of waiting forever when the gateway or a service never listens.
	deadline := time.Now().Add(30 * time.Second)
	if err := c.awaitListening(ctx, addresses, deadline); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}
	log := &gatewayLog{path: filepath.Join(c.dir, "gateway.log"), offset: logStart}
	status := ""
	for status == "" {
		events, err := log.next()
		if err != nil {
			return err
		}
		if status = admission(events); status != "" {
			break
		}
		select {
		case result := <-c.exited:
			c.received()
			return fmt.Errorf("%s exited before admission status (%v); see its log in %s", result.name, result.err, c.dir)
		case <-ctx.Done():
			return nil
		// Reads the new part of gateway.log every 50 ms, often enough to notice admission without spinning.
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("gateway did not report native admission status; see gateway.log")
		}
	}
	fmt.Printf("listening; protected admission: %s\n", status)
	fmt.Printf("  dashboard: http://%s/\n  website:   %s\n", adminListen, shopURL)
	c.printProcesses()
	if ready != nil {
		ready()
	}
	return c.supervise(ctx, log, site)
}

// supervise waits until ctx ends, the gateway exits or the website stops,
// reporting each service that stops and, every two seconds, each change of
// protected admission the gateway logs. A child that exits once ctx has
// ended is part of the requested stop, not a failure.
func (c *children) supervise(ctx context.Context, log *gatewayLog, site *stopped) error {
	// Two seconds: a change of admission shows promptly, and the log is read rarely.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("stopping")
			return nil
		case <-site.wait():
			return errors.New("the website stopped; stopping the demonstration")
		case result := <-c.exited:
			c.received()
			if ctx.Err() != nil {
				fmt.Println("stopping")
				return nil
			}
			if result.name == "gateway" {
				return fmt.Errorf("the gateway exited (%v); see %s", result.err, filepath.Join(c.dir, "gateway.log"))
			}
			fmt.Printf("service %s stopped (%v); its gateway requests can now fail\n", result.name, result.err)
		case <-ticker.C:
			events, err := log.next()
			if err != nil {
				fmt.Printf("gateway.log could not be read (%v); admission changes are not reported\n", err)
				continue
			}
			for _, line := range admissionChanges(events) {
				fmt.Println(line)
			}
		}
	}
}

// checkOffset refuses a deployment whose gateway settings listen elsewhere
// than this process's addresses: it was made under another EAT_PORT_OFFSET,
// and its policy's upstreams point at ports where nothing listens.
func checkOffset(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return err
	}
	var settings struct {
		Gateway struct {
			Admin string `json:"admin_listen"`
		} `json:"gateway"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	if settings.Gateway.Admin != adminListen {
		return fmt.Errorf("this deployment's gateway listens on %s, this run on %s: it was made with another EAT_PORT_OFFSET; set that offset again, or start over with -fresh", settings.Gateway.Admin, adminListen)
	}
	return nil
}

// localAddresses are every address of the one-machine demonstration.
func localAddresses() []string {
	addresses := []string{adminListen, dataListen, metricsListen, siteListen}
	for _, service := range fetchServices {
		addresses = append(addresses, service.listen, service.control)
	}
	return addresses
}

// checkFree refuses a second demonstration on any of the same addresses:
// one that cannot be bound now, or that answers a connection (on Windows a
// listener on every interface does not stop a bind to one address).
func checkFree(addresses []string) error {
	for _, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("%s cannot be bound (%v); refusing to start a second demonstration", address, err)
		}
		listener.Close()
		if dialable(address) {
			return fmt.Errorf("%s is already in use; refusing to start a second demonstration", address)
		}
	}
	return nil
}

// dialable reports whether address accepts a connection within 200 ms.
func dialable(address string) bool {
	// 200 ms keeps the check quick; a listener that slow to accept is not the demonstration's.
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
