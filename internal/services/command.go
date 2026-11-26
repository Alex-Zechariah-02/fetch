// The command line of one Fetch service or Accounts: its addresses, control
// secret, internal call keys, signing settings, internal call origins, the API's TLS files, the gateway's
// public keys and the folder of built-in protection.

package services

import (
	"context"
	"flag"
	"fmt"
	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/fetch/internal/ports"
)

// Command starts one service. Explicit addresses are already resolved by the
// operator; defaults apply the process port offset exactly once.
func Command(ctx context.Context, fixedName string, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("services", flag.ContinueOnError)
	flags.SetOutput(output)
	name := fixedName
	if fixedName == "" {
		flags.StringVar(&name, "service", "", "inventory, orders, reports or support")
	}
	listen := flags.String("listen", "", "API address: loopback, or another literal IP address with the three TLS settings")
	control := flags.String("control", "", "control loopback address")
	var ingress Ingress
	flags.StringVar(&ingress.Certificate, "tls-cert", "", "API certificate chain (PEM)")
	flags.StringVar(&ingress.Key, "tls-key", "", "API private key (PEM)")
	flags.StringVar(&ingress.ClientCA, "client-ca", "", "CA certificate (PEM) of the only client certificates the API admits: the gateway's")
	secretFile := flags.String("control-secret", "", "control listener secret file (receipts, state and reset)")
	keysFolder := flags.String("keys", "", "folder of the internal call key files: <service>.key for this service's own calls and for each service that calls it")
	inventoryURL := flags.String("inventory", "", "Inventory internal HTTP origin")
	ordersURL := flags.String("orders", "", "Orders internal HTTP origin")
	signingFile := flags.String("signing-settings", "", "Accounts signing settings file")
	protection := flags.String("local-security", "", "built-in protection: check tokens, roles, blocked accounts, rates and bodies here, with the trusted keys and blocked list in this folder and the security log written there")
	trustedProxy := flags.String("local-security-trusted-proxy", "", "literal IP address of the proxy whose X-Forwarded-For header built-in protection trusts; empty trusts none")
	var storage guard.Storage
	flags.StringVar(&storage.Archive, "local-security-archive", "", "folder rotated security log files are compressed into (default: archive in the -local-security folder)")
	flags.Int64Var(&storage.ArchiveBytes, "local-security-archive-bytes", guard.DefaultArchiveBytes, "size bound of this API's archived security log files; the oldest is deleted after a record of it")
	whenFull := flags.String("local-security-when-full", "evict_oldest", "evict_oldest deletes the oldest security log files, each after a record of it; refuse deletes nothing and refuses requests once the log folder is full")
	gatewayKey := flags.String("gateway-key", "", "the gateway's public keys (JSON Web Key Set, from gateway jwks): answer only requests carrying the gateway's signed identity assertion")
	measure := flags.Bool("measure", false, "measurement mode: receipts kept as counts with no cap, and the accounts load-0001 to load-10000 seeded")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *whenFull != "evict_oldest" && *whenFull != "refuse" {
		return fmt.Errorf("-local-security-when-full must be evict_oldest or refuse")
	}
	if storage.ArchiveBytes < 64<<20 {
		return fmt.Errorf("-local-security-archive-bytes must be at least 64 MiB")
	}
	if storage.Archive != "" && !filepath.IsAbs(storage.Archive) {
		return fmt.Errorf("-local-security-archive must be an absolute path")
	}
	storage.Refuse = *whenFull == "refuse"
	bases := map[string]int{"inventory": 9501, "orders": 9502, "reports": 9503, "support": 9504, "accounts": 9505}
	base, found := bases[name]
	if !found {
		return fmt.Errorf("choose a known service")
	}
	if fixedName == "" && name == "accounts" {
		return fmt.Errorf("use the accounts command for Fetch Accounts")
	}
	defaultAddress, err := ports.Offset("127.0.0.1:" + strconv.Itoa(base))
	if err != nil {
		return err
	}
	// The control default is the API port plus 100, so the two listeners never collide.
	defaultControl, err := ports.Offset("127.0.0.1:" + strconv.Itoa(base+100))
	if err != nil {
		return err
	}
	if *listen == "" {
		*listen = defaultAddress
	}
	if *control == "" {
		*control = defaultControl
	}
	if name == "orders" && *inventoryURL == "" {
		address, err := ports.Offset("127.0.0.1:9501")
		if err != nil {
			return err
		}
		*inventoryURL = "http://" + address
	}
	if (name == "reports" || name == "support") && *ordersURL == "" {
		address, err := ports.Offset("127.0.0.1:9502")
		if err != nil {
			return err
		}
		*ordersURL = "http://" + address
	}
	secret, err := readBoundedFile(*secretFile, private)
	if err != nil {
		return fmt.Errorf("reading the control secret: %w", err)
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	keys, err := commandKeys(*keysFolder, name)
	if err != nil {
		return err
	}
	service, err := New(Config{Name: name, Keys: keys, InventoryURL: *inventoryURL, OrdersURL: *ordersURL, SigningSettingsFile: *signingFile, Protection: *protection, TrustedProxy: *trustedProxy, Storage: storage, GatewayKey: *gatewayKey, Measure: *measure})
	if err != nil {
		return err
	}
	transport := "HTTP"
	if ingress != (Ingress{}) {
		transport = "TLS, client certificate required"
	}
	if *protection != "" {
		transport += ", built-in protection"
	}
	if *gatewayKey != "" {
		transport += ", gateway assertion required, key IDs " + strings.Join(service.gateway.keyIDs(), " ")
	}
	if *protection == "" && *gatewayKey == "" {
		transport += ", standalone (unprotected): identity headers are trusted as sent"
	}
	if *measure {
		transport += ", measurement mode"
	}
	fmt.Fprintf(output, "starting %s; api %s (%s); control %s\n", name, *listen, transport, *control)
	return Run(ctx, service, *listen, *control, secret, ingress)
}

// commandKeys reads service name's internal call keys from folder, which a
// service that makes and takes no internal calls (Accounts) must not name.
func commandKeys(folder, name string) (map[string][]byte, error) {
	if len(needs(name)) == 0 {
		if folder != "" {
			return nil, fmt.Errorf("%s makes and takes no internal calls: do not give -keys", name)
		}
		return nil, nil
	}
	if folder == "" {
		return nil, fmt.Errorf("%s needs -keys, the folder of its internal call keys", name)
	}
	return ReadKeys(folder, name)
}
