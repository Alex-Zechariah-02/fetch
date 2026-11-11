// The child processes of demo run and of the modes without a gateway: started
// with their output in log files, each reaped exactly once, stopped together.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// processExit is one child's exit.
type processExit struct {
	name string
	err  error
}

// children are the processes started for one demonstration. running counts
// those whose exit has not been received yet, so stop waits for exactly the
// rest; whoever receives from exited must call received.
type children struct {
	dir       string
	exited    chan processExit
	processes []*exec.Cmd
	names     []string
	running   int
	// keySet, when set, is the gateway's public key file: the four APIs
	// then answer only requests carrying its signed assertion.
	keySet string
}

func newChildren(dir string, capacity int) *children {
	return &children{dir: dir, exited: make(chan processExit, capacity)}
}

// start runs binary with its output appended to <dir>/<name>.log and returns
// the log's size before the start, where this run's output begins.
func (c *children) start(name, binary string, args ...string) (int64, error) {
	logFile, err := os.OpenFile(filepath.Join(c.dir, name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	info, err := logFile.Stat()
	if err != nil {
		logFile.Close()
		return 0, err
	}
	cmd := exec.Command(binary, args...)
	newProcessGroup(cmd)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("starting %s: %w", name, err)
	}
	c.processes = append(c.processes, cmd)
	c.names = append(c.names, name)
	c.running++
	go func() {
		err := cmd.Wait()
		logFile.Close()
		c.exited <- processExit{name: name, err: err}
	}()
	return info.Size(), nil
}

func (c *children) received() { c.running-- }

// stop interrupts every child, waits up to 12 seconds for all of them and then
// kills the rest. It returns every child's failure.
func (c *children) stop() error {
	var stopErr error
	for _, process := range c.processes {
		// A process that already exited cannot be signalled. Its exit is
		// still received below, so every child is reaped exactly once.
		if err := interruptProcess(process); err != nil && !errors.Is(err, os.ErrProcessDone) {
			process.Process.Kill()
		}
	}
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	for c.running > 0 {
		select {
		case result := <-c.exited:
			c.received()
			if result.err != nil {
				stopErr = errors.Join(stopErr, fmt.Errorf("%s stopped: %w; see its log in %s", result.name, result.err, c.dir))
			}
		case <-timer.C:
			for _, process := range c.processes {
				process.Process.Kill()
			}
			return errors.Join(stopErr, errors.New("child shutdown exceeded 12s; remaining processes killed"))
		}
	}
	return stopErr
}

// fetchHost is how the Fetch host of a two-host setup serves the APIs,
// Accounts and the shop: on the address bind, over TLS that admits only the
// gateway's client certificate, the four APIs answering only requests that
// carry the assertion the gateway signed for them.
type fetchHost struct {
	bind    netip.Addr
	ingress services.Ingress
	keySet  string // the gateway's public key file from demo certs
	measure bool   // the services and Accounts run in measurement mode
}

// startServices starts the four Fetch APIs and Accounts with the secret and
// signing settings in dir, on this machine's loopback addresses or, with host,
// on the Fetch host's address, and returns every address they listen on. The
// calls between services stay on loopback either way. With protect, each
// checks requests itself with the settings in dir (built-in protection).
func (c *children) startServices(dir, serviceBinary, accountsBinary string, host *fetchHost, protect bool) ([]string, error) {
	secret := filepath.Join(dir, secretFile)
	if host != nil {
		c.keySet = host.keySet
	}
	var addresses []string
	for _, f := range fetchServices {
		binary := serviceBinary
		listen := f.listen
		args := []string{"-control", f.control, "-secret-file", secret}
		if host != nil {
			listen = deployedAddress(f.listen, host.bind)
			args = append(args, "-tls-cert", host.ingress.Certificate, "-tls-key", host.ingress.Key, "-client-ca", host.ingress.ClientCA)
		}
		args = append(args, "-listen", listen)
		if protect {
			args = append(args, "-local-security", dir)
		}
		// Accounts asks for no assertion in any setup: on one machine the
		// demo commands sign in there directly.
		if c.keySet != "" && f.name != "accounts" {
			args = append(args, "-gateway-key", c.keySet)
		}
		if host != nil && host.measure {
			args = append(args, "-measure")
		}
		switch f.name {
		case "accounts":
			binary = accountsBinary
			args = append(args, "-signing-settings", filepath.Join(dir, signingFile))
		case "orders":
			args = append(args, "-service", f.name, "-inventory", "http://"+fetchServices[0].listen)
		case "reports":
			args = append(args, "-service", f.name, "-orders", "http://"+fetchServices[1].listen)
		default:
			args = append(args, "-service", f.name)
		}
		if _, err := c.start(f.name, binary, args...); err != nil {
			return nil, err
		}
		addresses = append(addresses, listen, f.control)
	}
	return addresses, nil
}

// awaitListening waits until every address accepts connections. It fails
// when a child exits first or the deadline passes; a cancelled ctx returns
// errCancelled.
func (c *children) awaitListening(ctx context.Context, addresses []string, deadline time.Time) error {
	for _, address := range addresses {
		for !dialable(address) {
			select {
			case result := <-c.exited:
				c.received()
				return fmt.Errorf("%s exited during startup (%v); see %s", result.name, result.err, filepath.Join(c.dir, result.name+".log"))
			case <-ctx.Done():
				return errCancelled
			case <-time.After(50 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not start listening; see the logs in %s", address, c.dir)
			}
		}
	}
	return nil
}

// printProcesses lists every child with its process ID.
func (c *children) printProcesses() {
	for i, p := range c.processes {
		fmt.Printf("  %-9s process %d\n", c.names[i], p.Process.Pid)
	}
}

// errCancelled reports a startup stopped by the demonstration's own stop.
var errCancelled = errors.New("stopped during startup")
