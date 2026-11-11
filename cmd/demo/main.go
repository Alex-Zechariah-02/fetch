// Command demo prepares and runs the demonstration of the gateway, on one
// machine or on two hosts (Fetch and the gateway). It writes private
// demonstration configuration and certificates, runs Fetch Accounts, the four
// business APIs and the gateway, resets synthetic data and prints security
// events. Policy and key commands use the protected Admin API as the signed-in
// operator. Application tokens are issued only by Fetch Accounts.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/ports"
)

// The demonstration addresses. The administrator dashboard and the data plane
// are on different loopback hosts because browsers scope cookies by host, not
// port: the administrator's session cookie must never accompany a data-plane
// request forwarded to a business service.
var (
	adminListen   = "127.0.0.1:9440"
	dataListen    = "127.0.0.2:9480"
	metricsListen = "127.0.0.1:9450"
	// siteListen is the shop's own upstream, reached only through the
	// gateway's public website operations.
	siteListen = "127.0.0.1:9506"
)

const (
	issuerName  = "fetch-accounts"
	audience    = "fetch-gateway"
	maxTokenTTL = 15 * time.Minute
)

// demoService is one Fetch API and its control listener.
type demoService struct {
	name, listen, control string
}

var fetchServices = []demoService{
	{"inventory", "127.0.0.1:9501", "127.0.0.1:9601"},
	{"orders", "127.0.0.1:9502", "127.0.0.1:9602"},
	{"reports", "127.0.0.1:9503", "127.0.0.1:9603"},
	{"support", "127.0.0.1:9504", "127.0.0.1:9604"},
	{"accounts", "127.0.0.1:9505", "127.0.0.1:9605"},
}

// Resolve the process's environment once. Invalid offsets stop the command
// before it opens deployment state or starts any process.
var portSetupError = applyDemoPortOffset()

func applyDemoPortOffset() error {
	addresses := []*string{&adminListen, &dataListen, &metricsListen, &siteListen}
	for i := range fetchServices {
		addresses = append(addresses, &fetchServices[i].listen, &fetchServices[i].control)
	}
	for _, address := range addresses {
		value, err := ports.Offset(*address)
		if err != nil {
			return err
		}
		*address = value
	}
	return nil
}

// Files inside the demonstration directory.
const (
	configFile     = "gateway.json"
	privateKeyFile = "issuer-key.pem"
	publicKeyFile  = "issuer.pem"
	secretFile     = "service.secret"
	signingFile    = "accounts.json"
	auditFile      = "audit.log"
	databaseFile   = "state.db"
	baselineFile   = "baseline.json"
	denyAllFile    = "deny-all.json"
	// The key the gateway signs its identity assertion with, and the public
	// key set the services verify it with.
	assertionKeyFile = "assertion-key.pem"
	assertionSetFile = "assertion-keys.json"
)

const usage = `usage:
  demo up     [-home H] [-fresh] [-stdin] [-apiward DIR]
  demo up     -standalone [-home H] [-stdin]   (no gateway: unprotected)
  demo up     -local [-home H] [-stdin]   (no gateway: built-in protection in each API)
  demo block  -local [-home H] [-unblock] ACCOUNT   (blocked list of every API of demo up -local)
  demo certs  -out DIR -fetch IP -gateway NAME[,NAME]   (files for two hosts)
  demo up     -role fetch -bind IP -certs DIR [-programs DIR] [-measure] [-home H] [-stdin]
  demo up     -role gateway -fetch IP -certs DIR [-tls-cert F -tls-key F] [-home H] [-fresh] [-stdin] [-apiward DIR]
  demo prepare -certs DIR   (a new gateway from the APIWard image: administrator and baseline)
  demo health   (the Fetch services on this host answer)
  demo migrate -out F [-apiward DIR] [-openapi DIR] [-fetch IP]
  demo setup  -dir D -web W -gateway G [-admin NAME]
  demo run    -dir D -web W -gateway G -services S -accounts A [-stdin]
  demo token  -dir D -subject ID [-ttl 15m]
  demo reset  -dir D
  demo attack -dir D -scenario flood-search|flood-login|flood-orders [-from 127.0.0.50] [-count N]
  demo attack -target https://HOST:PORT -scenario ... [-ca F] [-count N]
  demo keys rotate -dir D
  demo keys retire -dir D -kid K
  demo policy export -dir D -out F
  demo policy stage -dir D -file F
  demo events -dir D [-request ID] [-last N]`

func main() {
	if portSetupError != nil {
		fmt.Fprintln(os.Stderr, "demo:", portSetupError)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	commands := map[string]func([]string) error{
		"up":      up,
		"certs":   certs,
		"prepare": prepare,
		"health":  health,
		"migrate": migrate,
		"setup":   setup,
		"run":     run,
		"token":   token,
		"reset":   reset,
		"events":  events,
		"attack":  attack,
		"keys":    keys,
		"policy":  policy,
		"block":   block,
	}
	command, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := command(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

// parse reads a command's flags and requires -dir.
func parse(set *flag.FlagSet, args []string) (string, error) {
	dir := set.String("dir", "", "demonstration directory")
	if err := set.Parse(args); err != nil {
		return "", err
	}
	if *dir == "" || set.NArg() != 0 {
		return "", errors.New("-dir is required and no other arguments are accepted\n" + usage)
	}
	return filepath.Abs(*dir)
}
