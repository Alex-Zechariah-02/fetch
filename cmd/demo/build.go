// The build and first-run steps of demo up: the gateway, services and Accounts
// programs, both websites, and a new deployment's administrator and baseline.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// builtPrograms are the program files demo up runs.
type builtPrograms struct{ gateway, services, accounts string }

// buildPrograms builds the gateway, services and Accounts programs into bin,
// every time, so the demonstration always runs the current sources.
func buildPrograms(source sources, bin string) (builtPrograms, error) {
	gateway, err := buildProgram("apiward", source.apiward, bin)
	if err != nil {
		return builtPrograms{}, err
	}
	services, accounts, err := buildServices(source.fetch, bin)
	return builtPrograms{gateway, services, accounts}, err
}

// buildServices builds this repository's services and Accounts programs.
func buildServices(fetch, bin string) (services, accounts string, err error) {
	if services, err = buildProgram("services", fetch, bin); err != nil {
		return "", "", err
	}
	accounts, err = buildProgram("accounts", fetch, bin)
	return services, accounts, err
}

// fetchPrograms are the services and Accounts programs and the shop's folder
// a Fetch host runs: built into home from this checkout, or, when programs is
// set, the ones already built in that folder (the container image's), which
// holds services, accounts and shop/.
func fetchPrograms(home, programs string) (services, accounts, shop string, err error) {
	if programs != "" {
		services, accounts, shop = filepath.Join(programs, executable("services")), filepath.Join(programs, executable("accounts")), filepath.Join(programs, "shop")
		for _, file := range []string{services, accounts, filepath.Join(shop, "index.html")} {
			if _, err := os.Stat(file); err != nil {
				return "", "", "", fmt.Errorf("-programs: %w", err)
			}
		}
		// 0700: other local users cannot read the built programs, copied websites or keys.
		return services, accounts, shop, os.MkdirAll(home, 0o700)
	}
	fetch, err := fetchRepository()
	if err != nil {
		return "", "", "", err
	}
	shop = filepath.Join(home, "web", "demo")
	if services, accounts, err = buildServices(fetch, filepath.Join(home, "bin")); err != nil {
		return "", "", "", err
	}
	return services, accounts, shop, buildWebsite(filepath.Join(fetch, "client"), shop)
}

// buildProgram builds ./cmd/<name> of the module in folder into bin.
func buildProgram(name, folder, bin string) (string, error) {
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return "", err
	}
	fmt.Println("Building the", name, "program...")
	output := filepath.Join(bin, executable(name))
	build := exec.Command("go", "build", "-trimpath", "-o", output, "./cmd/"+name)
	build.Dir = folder
	if log, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building %s: %w\n%s", name, err, log)
	}
	return output, nil
}

// buildWebsites builds the Dashboard (APIWard's dashboard folder) and the shop
// (this repository's client folder) into web: admin/ is served by the
// gateway, demo/ by the demo process.
func buildWebsites(source sources, web string) error {
	if err := buildWebsite(filepath.Join(source.apiward, "dashboard"), filepath.Join(web, "admin")); err != nil {
		return err
	}
	return buildWebsite(filepath.Join(source.fetch, "client"), filepath.Join(web, "demo"))
}

// buildWebsite builds the website in folder and replaces target with a copy
// of its build.
func buildWebsite(folder, target string) error {
	// Install only when node_modules is absent: a full reinstall on every build is slow.
	if _, err := os.Stat(filepath.Join(folder, "node_modules")); errors.Is(err, os.ErrNotExist) {
		fmt.Println("Installing the", folder, "packages...")
		if err := npm(folder, "ci", "--no-audit", "--no-fund"); err != nil {
			return err
		}
	}
	fmt.Println("Building the", folder+"...")
	if err := npm(folder, "run", "build"); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	case info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
		// A link, such as a junction to an old build folder: removing it
		// removes only the link, never the folder it points to.
		if err := os.Remove(target); err != nil {
			return err
		}
	default:
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	if err := os.CopyFS(target, os.DirFS(filepath.Join(folder, "dist"))); err != nil {
		return fmt.Errorf("copying the %s build: %w", folder, err)
	}
	return nil
}

func npm(dir string, args ...string) error {
	command := exec.Command("npm", args...)
	command.Dir = dir
	if log, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("npm %s in %s: %w\n%s", strings.Join(args, " "), dir, err, log)
	}
	return nil
}

// enrolmentLine starts the line of apiward install's output that holds the
// first administrator's secret, as APIWard prints it
// (internal/operator/commands.go there); TestEnrolmentSecret and the
// gateway's own demo test fail if the wording changes.
const enrolmentLine = "enrolment secret for " + upAdmin + ","

// enrolmentSecret reads the first administrator's one-time enrolment secret
// from the gateway's install output.
func enrolmentSecret(install string) (string, error) {
	for line := range strings.Lines(install) {
		if strings.HasPrefix(line, enrolmentLine) {
			if _, secret, found := strings.Cut(strings.TrimSpace(line), ": "); found && secret != "" {
				return secret, nil
			}
		}
	}
	return "", errors.New("the apiward install output holds no enrolment secret")
}

// prepareGateway gives a deployment without a policy its administrator and
// baseline policy, the steps an administrator would take in the Dashboard.
func prepareGateway(state string, firstRun bool, secret, password string) error {
	admin := newAdminClient()
	mode, err := admin.health()
	if err != nil {
		return err
	}
	switch mode {
	case "normal":
		return nil
	case "recovery_required":
		fmt.Println("The gateway needs recovery: sign in to the Dashboard and establish a recovery base on the Changes page.")
		return nil
	case "bootstrap_locked":
	default:
		return fmt.Errorf("the gateway reports state %q", mode)
	}

	if firstRun {
		if err := admin.enrol(secret, password); err != nil {
			return err
		}
	} else {
		fmt.Println("This demonstration has no policy yet.")
		if password, err = readSecretLine("Password of the Dashboard administrator " + upAdmin + " (not shown): "); err != nil {
			return err
		}
	}
	if err := admin.signIn(password); err != nil {
		if firstRun {
			return err
		}
		return fmt.Errorf("%w\nIf the earlier setup never finished, start over with: go run ./cmd/demo up -fresh", err)
	}
	defer admin.signOut(os.Stderr)
	fmt.Println("Establishing the baseline policy...")
	return admin.establishBaseline(state)
}

// checkReused compares a deployment a later run reuses with what this run
// would create. It refuses when the stored baseline sends the APIs to another
// host or the settings name another certificate folder, since the gateway
// would then reach the wrong Fetch or with old certificates; it notes when
// only the baseline's content differs, as the confirmed policy stays as it is.
func checkReused(state string, baseline map[string]any, ca string) error {
	stored, err := os.ReadFile(filepath.Join(state, baselineFile))
	if err != nil {
		return err
	}
	want := indented(baseline)
	if before, now := upstreamHost(stored), upstreamHost(want); before != now {
		return fmt.Errorf("this deployment sends its APIs to %s, this run to %s: run with the earlier address, or start over with -fresh", before, now)
	}
	if ca != "" {
		if named := settingsCA(state); named != ca {
			return fmt.Errorf("this deployment's settings name the certificates in %s, this run %s: pass the earlier folder, or start over with -fresh", filepath.Dir(named), filepath.Dir(ca))
		}
	}
	if !bytes.Equal(stored, want) {
		fmt.Println("Note: this version's baseline policy differs from the one this deployment started with; its confirmed policy is unchanged (compare them in the Dashboard's Changes page, or start over with -fresh).")
	}
	return nil
}

// upstreamHost is the host of the first upstream in a baseline document, or "".
func upstreamHost(document []byte) string {
	var policy struct {
		Upstreams []struct {
			Dial string `json:"dial"`
			URL  string `json:"url"`
		} `json:"upstreams"`
	}
	if json.Unmarshal(document, &policy) != nil || len(policy.Upstreams) == 0 {
		return ""
	}
	address := strings.TrimPrefix(policy.Upstreams[0].URL, "https://") + policy.Upstreams[0].Dial
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// settingsCA is the CA file the first upstream TLS profile of state's
// settings names, or "".
func settingsCA(state string) string {
	data, err := os.ReadFile(filepath.Join(state, configFile))
	if err != nil {
		return ""
	}
	var settings struct {
		Upstream struct {
			Profiles []tlsProfile `json:"tls_profiles"`
		} `json:"upstream"`
	}
	if json.Unmarshal(data, &settings) != nil || len(settings.Upstream.Profiles) == 0 {
		return ""
	}
	return settings.Upstream.Profiles[0].CAFile
}

// printSignIns prints only the deliberately public fictional demo credentials.
func printSignIns() {
	fmt.Println("\nFetch demo accounts (all fictional). Password: FetchDemo2026!")
	fmt.Printf("%-14s %-22s %-24s %-20s %-8s %s\n", "Subject", "Name", "Email", "Roles", "Merchant", "Home")
	for _, user := range services.Users() {
		merchant := ""
		if user.Merchant != nil {
			merchant = *user.Merchant
		}
		fmt.Printf("%-14s %-22s %-24s %-20s %-8s %s\n", user.ID, user.Name, user.Email, strings.Join(user.Roles, ","), merchant, user.Home)
	}
}
