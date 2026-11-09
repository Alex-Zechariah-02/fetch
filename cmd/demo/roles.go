// The two hosts of demo up -role. The Fetch host runs the shop, the APIs and
// Accounts on one address, over TLS that admits only the gateway's client
// certificate; the gateway host runs APIWard, reaching them with that
// certificate and serving the shop over TLS on every interface. demo certs
// makes both hosts' files; the Accounts public key travels in them.

package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
// shop, makes a new folder in home for this run and serves everything on
// bindIP until interrupted. Services restart from seed on every run.
func upFetch(home, bindIP, certs string, stdin bool) error {
	bind, err := netip.ParseAddr(bindIP)
	if err != nil || bind.IsUnspecified() {
		return errors.New("-role fetch takes -bind: this host's IP address, which the gateway connects to")
	}
	if bind == netip.AddrFrom4([4]byte{127, 0, 0, 1}) {
		return errors.New("-bind 127.0.0.1 is where the services call each other; use this host's network address")
	}
	folder, err := certFolder(certs, caFile, serverCertFile, serverKeyFile, privateKeyFile)
	if err != nil {
		return err
	}
	host := &fetchHost{bind: bind, ingress: services.Ingress{
		Certificate: filepath.Join(folder, serverCertFile),
		Key:         filepath.Join(folder, serverKeyFile),
		ClientCA:    filepath.Join(folder, caFile),
	}}
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

	fetch, err := fetchRepository()
	if err != nil {
		return err
	}
	bin, shop := filepath.Join(home, "bin"), filepath.Join(home, "web", "demo")
	serviceBinary, accountsBinary, err := buildServices(fetch, bin)
	if err != nil {
		return err
	}
	if err := buildWebsite(filepath.Join(fetch, "client"), shop); err != nil {
		return err
	}
	dir := filepath.Join(home, "fetch")
	files := map[string][]byte{secretFile: newSecret(), signingFile: signingSettings(kid, filepath.Join(folder, privateKeyFile))}
	if err := prepareFolder(dir, files); err != nil {
		return err
	}
	listener, err := services.Listen(site, host.ingress)
	if err != nil {
		return fmt.Errorf("the shop address: %w", err)
	}
	ctx, stop := stopContext(stdin)
	defer stop()
	first, last := deployedAddress(fetchServices[0].listen, bind), deployedAddress(fetchServices[len(fetchServices)-1].listen, bind)
	banner := fmt.Sprintf("Fetch admits only the gateway's client certificate:\n  APIs and Accounts: https://%s to %s\n  shop:              https://%s/\n"+
		"On the gateway host: go run ./cmd/demo up -role gateway -fetch %s -certs <gateway folder>\nPress Ctrl+C to stop.", first, last, site, bind)
	return serveFetch(ctx, dir, listener, website(os.DirFS(shop)), serviceBinary, accountsBinary, host, banner)
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
	required := []string{caFile, clientCertFile, clientKeyFile, publicKeyFile}
	if tlsCert == "" {
		required = append(required, dataCertFile, dataKeyFile)
	}
	folder, err := certFolder(certs, required...)
	if err != nil {
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
		reused:    "Reusing the gateway host set up earlier in " + state + ": its Fetch address and certificate files stay as first set (-fresh starts over).",
		build: func(source sources) (builtPrograms, error) {
			gateway, err := buildProgram("gateway", source.apiward, filepath.Join(home, "bin"))
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
	port := strconv.Itoa(int(netip.MustParseAddrPort(dataListen).Port()))
	data := map[string]any{
		"listen":                net.JoinHostPort("0.0.0.0", port),
		"listen_all_interfaces": true,
		"tls":                   map[string]any{"files": map[string]string{"certificate_file": tlsCert, "key_file": tlsKey}},
	}
	profile := tlsProfile{fetchProfile, filepath.Join(folder, caFile), filepath.Join(folder, clientCertFile), filepath.Join(folder, clientKeyFile)}
	settings := gatewaySettings(dir, web, trustedKey{kid, filepath.Join(folder, publicKeyFile)}, data, []tlsProfile{profile})
	return createState(dir, map[string][]byte{configFile: indented(settings)}, deployedBaseline(fetch), gateway, upAdmin, out)
}

// runGatewayHost runs the gateway alone with the settings in dir until ctx
// ends or it exits.
func runGatewayHost(ctx context.Context, dir, gateway, shopURL string, ready func()) (runErr error) {
	if err := checkDemo(dir); err != nil {
		return err
	}
	running := newChildren(dir, 1)
	defer func() { runErr = errors.Join(runErr, running.stop()) }()
	return running.runGateway(ctx, gateway, nil, nil, shopURL, ready)
}

// certFolder is the absolute path of dir, a host's folder from demo certs,
// once it holds every one of files.
func certFolder(dir string, files ...string) (string, error) {
	if dir == "" {
		return "", errors.New("-role takes -certs: this host's folder from demo certs")
	}
	folder, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for _, name := range files {
		if info, err := os.Stat(filepath.Join(folder, name)); err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s has no file %s: pass this host's folder from demo certs", folder, name)
		}
	}
	return folder, nil
}

// signingKeyID names the Accounts signing key in the PEM file at path, its
// private (PKCS #8) or public (PKIX) half, after its public key, so each host
// derives the same ID from its own file.
func signingKeyID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s holds no PEM key", path)
	}
	var public any
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		signer, ok := key.(crypto.Signer)
		if err != nil || !ok {
			return "", fmt.Errorf("%s: not a private signing key", path)
		}
		public = signer.Public()
	case "PUBLIC KEY":
		if public, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
	default:
		return "", fmt.Errorf("%s holds a %s, not a key", path, block.Type)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "fetch-" + hex.EncodeToString(sum[:8]), nil
}

// certificateURL is the shop's address on the gateway host: the first name in
// the certificate chain at path, on the data listener's port.
func certificateURL(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s holds no certificate", path)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	host := "<this host>"
	switch {
	case len(leaf.DNSNames) > 0:
		host = leaf.DNSNames[0]
	case len(leaf.IPAddresses) > 0:
		host = leaf.IPAddresses[0].String()
	}
	port := strconv.Itoa(int(netip.MustParseAddrPort(dataListen).Port()))
	return "https://" + net.JoinHostPort(host, port) + "/", nil
}
