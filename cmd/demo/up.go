// Demo up: the one-command demonstration and its modes (one machine,
// standalone, built-in protection, either host of a two-host setup), the
// sources it builds from, and the administrator password prompts.

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"
)

// The administrator enrolled by the one-command launcher.
const upAdmin = "root"

// sources are the two checkouts up builds from: APIWard (the gateway and its
// Dashboard) and this Fetch repository (the services, Accounts and the shop).
type sources struct{ apiward, fetch string }

// up runs the demonstration with one command: on one machine by default,
// with -standalone or -local without a gateway, or as one host of a two-host
// setup with -role.
func up(args []string) error {
	set := flag.NewFlagSet("up", flag.ContinueOnError)
	home := set.String("home", "", "folder for the built programs, websites and demonstration state (default: EAT40005-demo in the user's data folder)")
	fresh := set.Bool("fresh", false, "delete the earlier demonstration state, including its administrator and policy, and start over")
	stdin := set.Bool("stdin", false, "also stop when standard input closes")
	apiward := set.String("apiward", "", "APIWard checkout that builds the gateway and the Dashboard (default: ../apiward beside this repository)")
	standalone := set.Bool("standalone", false, "run the shop and services with no gateway: nothing is checked (unprotected); with -role fetch, the APIs believe the identity headers (for measurement)")
	local := set.Bool("local", false, "run the shop and services with no gateway, each API checking requests itself (built-in protection); also with -role fetch")
	role := set.String("role", "", "run one host of a two-host setup: fetch (the shop, APIs and Accounts) or gateway (APIWard)")
	bind := set.String("bind", "", "-role fetch: this host's IP address, which the gateway connects to")
	fetch := set.String("fetch", "", "-role gateway: the Fetch host's IP address")
	certs := set.String("certs", "", "-role: this host's folder from demo certs")
	tlsCert := set.String("tls-cert", "", "-role gateway: the shop's certificate chain instead of the folder's data.pem, such as certbot's fullchain.pem")
	tlsKey := set.String("tls-key", "", "-role gateway: the private key of -tls-cert")
	measure := set.Bool("measure", false, "-role fetch: measurement mode (receipts as counts with no cap, and the load-0001 to load-10000 accounts)")
	programs := set.String("programs", "", "-role fetch: run the services, Accounts and shop already built in this folder (as in the container image) instead of building them")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("up takes no arguments\n" + usage)
	}
	homeDir, err := homeFolder(*home)
	if err != nil {
		return err
	}
	switch {
	case *role == "fetch":
		if err := onlyFlags(set, "home", "stdin", "role", "bind", "certs", "programs", "measure", "standalone", "local"); err != nil {
			return err
		}
		checks, err := checksOf(*standalone, *local)
		if err != nil {
			return err
		}
		return upFetch(homeDir, *bind, *certs, *programs, checks, *measure, *stdin)
	case *standalone:
		// The standalone mode has no gateway state to delete or build.
		if err := onlyFlags(set, "home", "stdin", "standalone"); err != nil {
			return err
		}
		return upStandalone(homeDir, *stdin)
	case *local:
		if err := onlyFlags(set, "home", "stdin", "local"); err != nil {
			return err
		}
		return upLocal(homeDir, *stdin)
	case *role == "gateway":
		if err := onlyFlags(set, "home", "fresh", "stdin", "apiward", "role", "fetch", "certs", "tls-cert", "tls-key"); err != nil {
			return err
		}
		host, err := gatewayRole(homeDir, *fetch, *certs, *tlsCert, *tlsKey)
		if err != nil {
			return err
		}
		return host.up(*apiward, *fresh, *stdin)
	case *role != "":
		return errors.New("-role is fetch or gateway")
	}
	if err := onlyFlags(set, "home", "fresh", "stdin", "apiward"); err != nil {
		return err
	}
	return localHost(homeDir).up(*apiward, *fresh, *stdin)
}

// onlyFlags refuses every flag given that is not one of names.
func onlyFlags(set *flag.FlagSet, names ...string) error {
	var extra []string
	set.Visit(func(f *flag.Flag) {
		if !slices.Contains(names, f.Name) {
			extra = append(extra, "-"+f.Name)
		}
	})
	if len(extra) > 0 {
		return fmt.Errorf("this mode does not take %s\n%s", strings.Join(extra, ", "), usage)
	}
	return nil
}

// homeFolder is the absolute path of home or, when home is empty, of the
// default: EAT40005-demo in the user's data folder. It names an earlier
// default folder that still exists, so its state is not silently left behind.
func homeFolder(home string) (string, error) {
	if home != "" {
		return filepath.Abs(home)
	}
	data, err := dataFolder()
	if err != nil {
		return "", fmt.Errorf("no folder for the demonstration's state (%w): pass -home", err)
	}
	home = filepath.Join(data, "EAT40005-demo")
	if cache, err := os.UserCacheDir(); err == nil && filepath.Join(cache, "EAT40005-demo") != home {
		if _, err := os.Stat(filepath.Join(cache, "EAT40005-demo")); err == nil {
			fmt.Printf("An earlier demonstration is in %s; pass -home with that folder to use it.\n", filepath.Join(cache, "EAT40005-demo"))
		}
	}
	return home, nil
}

// dataFolder is where the user's application data lives: %LocalAppData% on
// Windows, ~/Library/Application Support on macOS, and $XDG_DATA_HOME or
// ~/.local/share elsewhere (XDG Base Directory). Unlike a cache folder,
// nothing purges it, and the state holds the policy database and audit log.
func dataFolder() (string, error) {
	switch runtime.GOOS {
	case "windows":
		// UserCacheDir is %LocalAppData% on Windows, which is local application data, never roamed.
		return os.UserCacheDir()
	case "darwin":
		return os.UserConfigDir()
	}
	// The XDG specification ignores a relative value.
	if data := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(data) {
		return data, nil
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(user, ".local", "share"), nil
}

// findSources finds this Fetch repository from the working directory's module,
// so up builds the sources it is run from, and the APIWard checkout: apiward,
// or else the folder apiward beside this repository.
func findSources(apiward string) (sources, error) {
	fetch, err := fetchRepository()
	if err != nil {
		return sources{}, err
	}
	if apiward == "" {
		apiward = filepath.Join(fetch, "..", "apiward")
	}
	if apiward, err = filepath.Abs(apiward); err != nil {
		return sources{}, err
	}
	if _, err := os.Stat(filepath.Join(apiward, "cmd", "apiward")); err != nil {
		return sources{}, fmt.Errorf("%s is not an APIWard checkout: clone github.com/Alex-Zechariah-02/apiward there or pass -apiward <folder>", apiward)
	}
	return sources{apiward: apiward, fetch: fetch}, nil
}

// fetchRepository is the Fetch repository of the working directory's module.
func fetchRepository() (string, error) {
	output, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("finding the Fetch repository with the go command: %w", err)
	}
	mod := strings.TrimSpace(string(output))
	if mod == "" || mod == os.DevNull {
		return "", errors.New("run up from the Fetch repository: go run ./cmd/demo up")
	}
	fetch := filepath.Dir(mod)
	if _, err := os.Stat(filepath.Join(fetch, "cmd", "demo")); err != nil {
		return "", fmt.Errorf("%s is not the Fetch repository", fetch)
	}
	return fetch, nil
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

func readLineFrom(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// choosePassword asks for a new password twice. The gateway decides whether
// it is acceptable; the length check here only saves a failed enrolment.
func choosePassword() (string, error) {
	return choosePasswordFrom(stdinLines)
}

func choosePasswordFrom(r *bufio.Reader) (string, error) {
	for {
		first, err := readSecretLineFrom("Password (15 to 256 bytes, not shown): ", r)
		if err != nil {
			return "", err
		}
		second, err := readSecretLineFrom("Repeat the password: ", r)
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
