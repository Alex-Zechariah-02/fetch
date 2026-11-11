// The command line of one Fetch service or Accounts: its addresses, secret,
// signing settings, internal call origins, the API's TLS files, the gateway's
// public keys and the folder of built-in protection.

package services

import (
	"context"
	"flag"
	"fmt"
	"io"
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
	secretFile := flags.String("secret-file", "", "service/control secret file")
	inventoryURL := flags.String("inventory", "", "Inventory internal HTTP origin")
	ordersURL := flags.String("orders", "", "Orders internal HTTP origin")
	signingFile := flags.String("signing-settings", "", "Accounts signing settings file")
	protection := flags.String("local-security", "", "built-in protection: check tokens, roles, blocked accounts, rates and bodies here, with the trusted keys and blocked list in this folder and the security log written there")
	gatewayKey := flags.String("gateway-key", "", "the gateway's public keys (JSON Web Key Set, from gateway jwks): answer only requests carrying the gateway's signed identity assertion")
	measure := flags.Bool("measure", false, "measurement mode: receipts kept as counts with no cap, and the accounts load-0001 to load-1000 seeded")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
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
	if name == "reports" && *ordersURL == "" {
		address, err := ports.Offset("127.0.0.1:9502")
		if err != nil {
			return err
		}
		*ordersURL = "http://" + address
	}
	secret, err := readBoundedFile(*secretFile)
	if err != nil {
		return fmt.Errorf("reading service secret: %w", err)
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	service, err := New(Config{Name: name, Secret: secret, InventoryURL: *inventoryURL, OrdersURL: *ordersURL, SigningSettingsFile: *signingFile, Protection: *protection, GatewayKey: *gatewayKey, Measure: *measure})
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
		transport += ", gateway assertion required"
	}
	if *measure {
		transport += ", measurement mode"
	}
	fmt.Fprintf(output, "starting %s; api %s (%s); control %s\n", name, *listen, transport, *control)
	return Run(ctx, service, *listen, *control, secret, ingress)
}
