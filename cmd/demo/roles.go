// The two hosts of demo up -role. The Fetch host runs the shop, the APIs and
// Accounts on one address, over TLS that admits only the gateway's client
// certificate; the gateway host runs APIWard, reaching them with that
// certificate and serving the shop over TLS on every interface. demo certs
// makes both hosts' files; the Accounts public key travels in them.

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// tlsProfile is an upstream TLS profile of the gateway's settings.
type tlsProfile struct {
	ID          string `json:"id"`
	CAFile      string `json:"ca_file"`
	Certificate string `json:"client_certificate_file"`
	Key         string `json:"client_key_file"`
}

// upFetch is demo up -role fetch: it builds the services, Accounts and the
// shop (or takes them from programs), makes a new folder in home for this run
// and serves everything on bindIP, with checks, until interrupted. Services
// restart from seed on every run; with measure, in measurement mode.
func upFetch(home, bindIP, certs, programs string, checks hostChecks, measure, stdin bool) error {
	bind, err := netip.ParseAddr(bindIP)
	if err != nil || bind.IsUnspecified() {
		return errors.New("-role fetch takes -bind: this host's IP address, which the gateway connects to")
	}
	// The services reach each other on 127.0.0.1 at the same ports; another
	// loopback address such as 127.0.0.3 keeps Fetch on this host only.
	if bind.Unmap() == services.InternalHost {
		return errors.New("-bind takes another address than 127.0.0.1, where the services call each other")
	}
	folder, err := certFolder(certs, caFile, serverCertFile, serverKeyFile, privateKeyFile, assertionSetFile)
	if err != nil {
		return err
	}
	if err := checkIssued(folder, serverCertFile, x509.ExtKeyUsageServerAuth, bind.String()); err != nil {
		return err
	}
	host := &fetchHost{bind: bind, ingress: services.Ingress{
		Certificate: filepath.Join(folder, serverCertFile),
		Key:         filepath.Join(folder, serverKeyFile),
		ClientCA:    filepath.Join(folder, caFile),
	}, measure: measure}
	if checks == gatewayChecks {
		host.keySet = filepath.Join(folder, assertionSetFile)
	}
	site := deployedAddress(siteListen, bind)
	// The Inventory and Orders loopback addresses carry the internal calls.
	addresses := []string{site, fetchServices[0].listen, fetchServices[1].listen}
	for _, service := range fetchServices {
		addresses = append(addresses, deployedAddress(service.listen, bind), service.control)
	}
	if err := checkFree(addresses); err != nil {
		return err
	}
	kid, err := signingKeyID(filepath.Join(folder, privateKeyFile))
	if err != nil {
		return err
	}

	serviceBinary, accountsBinary, shop, err := fetchPrograms(home, programs)
	if err != nil {
		return err
	}
	dir := filepath.Join(home, "fetch")
	files, err := hostFiles(dir, folder, kid, checks)
	if err != nil {
		return err
	}
	if err := prepareFolder(dir, files); err != nil {
		return err
	}
	shopSite, err := loadWebsite(os.DirFS(shop))
	if err != nil {
		return err
	}
	listener, err := services.Listen(site, host.ingress)
	if err != nil {
		return fmt.Errorf("the shop address: %w", err)
	}
	ctx, stop := stopContext(stdin)
	defer stop()
	first, last := deployedAddress(fetchServices[0].listen, bind), deployedAddress(fetchServices[len(fetchServices)-1].listen, bind)
	banner := hostBanner(checks, first, last, site, bind.String())
	return serveFetch(ctx, dir, listener, shopSite, serviceBinary, accountsBinary, host, checks == builtinChecks, banner)
}

// gatewayRole is demo up -role gateway: the gateway alone, with its state in
// home/gateway, reaching the Fetch host at fetchIP with the certs folder's
// client certificate and serving the shop with the folder's data certificate,
// or with tlsCert and tlsKey when given.
func gatewayRole(home, fetchIP, certs, tlsCert, tlsKey string) (gatewayHost, error) {
	fetch, err := netip.ParseAddr(fetchIP)
	if err != nil || fetch.IsUnspecified() {
		return gatewayHost{}, errors.New("-role gateway takes -fetch: the Fetch host's IP address")
	}
	if (tlsCert == "") != (tlsKey == "") {
		return gatewayHost{}, errors.New("-tls-cert and -tls-key are set together")
	}
	required := []string{caFile, clientCertFile, clientKeyFile, publicKeyFile, assertionKeyFile}
	if tlsCert == "" {
		required = append(required, dataCertFile, dataKeyFile)
	}
	folder, err := certFolder(certs, required...)
	if err != nil {
		return gatewayHost{}, err
	}
	if err := checkIssued(folder, clientCertFile, x509.ExtKeyUsageClientAuth, ""); err != nil {
		return gatewayHost{}, err
	}
	if tlsCert == "" {
		tlsCert, tlsKey = filepath.Join(folder, dataCertFile), filepath.Join(folder, dataKeyFile)
	}
	if tlsCert, err = filepath.Abs(tlsCert); err != nil {
		return gatewayHost{}, err
	}
	if tlsKey, err = filepath.Abs(tlsKey); err != nil {
		return gatewayHost{}, err
	}
	shopURL, err := certificateURL(tlsCert)
	if err != nil {
		return gatewayHost{}, err
	}
	state, web := filepath.Join(home, "gateway"), filepath.Join(home, "web")
	return gatewayHost{
		state:     state,
		addresses: []string{adminListen, dataListen, metricsListen},
		shopURL:   shopURL,
		reused:    "Reusing the gateway host set up earlier in " + state + ".",
		baseline:  deployedBaseline(fetch),
		ca:        filepath.Join(folder, caFile),
		build: func(source sources) (builtPrograms, error) {
			gateway, err := buildProgram("apiward", source.apiward, filepath.Join(home, "bin"))
			if err != nil {
				return builtPrograms{}, err
			}
			return builtPrograms{gateway: gateway}, buildWebsite(filepath.Join(source.apiward, "dashboard"), filepath.Join(web, "admin"))
		},
		create: func(programs builtPrograms, out io.Writer) error {
			return createGatewayState(state, web, programs.gateway, fetch, folder, tlsCert, tlsKey, out)
		},
		run: func(ctx context.Context, programs builtPrograms, ready func()) error {
			return runGatewayHost(ctx, state, programs.gateway, shopURL, ready)
		},
	}, nil
}

// createGatewayState makes the gateway host's new deployment directory. Its
// settings trust the Accounts public key from the certs folder, reach Fetch
// with the folder's CA and client certificate and serve the data listener
// over TLS on every interface; its baseline sends every API and the shop to
// the Fetch host.
func createGatewayState(dir, web, gateway string, fetch netip.Addr, folder, tlsCert, tlsKey string, out io.Writer) error {
	if _, err := os.Stat(filepath.Join(web, "admin", "index.html")); err != nil {
		return fmt.Errorf("%s has no admin/index.html: build the Dashboard first", web)
	}
	kid, err := signingKeyID(filepath.Join(folder, publicKeyFile))
	if err != nil {
		return err
	}
	in := func(name string) string { return filepath.Join(folder, name) }
	settings := hostSettings(stateFiles(dir, web), kid, in, tlsCert, tlsKey)
	return createState(dir, map[string][]byte{configFile: indented(settings)}, deployedBaseline(fetch), gateway, upAdmin, out)
}

// hostSettings are the settings of a two-host setup's gateway: in names a
// file of the gateway folder from demo certs where the gateway reads it; the
// data listener serves certificate and key over TLS on every interface and
// the Accounts key is identified by kid.
func hostSettings(files gatewayFiles, kid string, in func(string) string, certificate, key string) map[string]any {
	port := strconv.Itoa(int(netip.MustParseAddrPort(dataListen).Port()))
	data := map[string]any{
		// Other hosts reach the shop over TLS on the data port, so every interface is offered.
		"listen":                net.JoinHostPort("0.0.0.0", port),
		"listen_all_interfaces": true,
		"tls":                   map[string]any{"files": map[string]string{"certificate_file": certificate, "key_file": key}},
	}
	profile := tlsProfile{fetchProfile, in(caFile), in(clientCertFile), in(clientKeyFile)}
	keys := gatewayKeys{trustedKey{kid, in(publicKeyFile)}, in(assertionKeyFile)}
	return gatewaySettings(files, keys, data, []tlsProfile{profile})
}

// runGatewayHost runs the gateway alone with the settings in dir until ctx
// ends or it exits.
func runGatewayHost(ctx context.Context, dir, gateway, shopURL string, ready func()) (runErr error) {
	if err := checkDemo(dir); err != nil {
		return err
	}
	// Only the gateway runs in this role, so one exit report is enough.
	running := newChildren(dir, 1)
	defer func() { runErr = errors.Join(runErr, running.stop()) }()
	return running.runGateway(ctx, gateway, nil, nil, shopURL, ready)
}
