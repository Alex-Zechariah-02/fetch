// Demo certs: the files of a two-host setup, made once and then copied. A new
// private CA signs Fetch's server certificate (for the Fetch host's address),
// the gateway's client certificate, which Fetch admits, and the gateway's
// certificate for the shop's address; a new Accounts signing key pair splits
// between the hosts. The CA's key is never written, so nothing else can be
// issued from it.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certLifetime keeps the private certificates short-lived: a later setup runs
// demo certs again instead of renewing them.
const certLifetime = 30 * 24 * time.Hour

// clockSkew backdates every certificate so a host whose clock runs slightly
// behind still accepts it.
const clockSkew = 5 * time.Minute

// The files of the two folders demo certs writes. Both hold the CA
// certificate; fetch/ also holds the Accounts private key (privateKeyFile)
// and gateway/ its public key (publicKeyFile) and the APIWard image's files
// (addImageFiles).
const (
	caFile         = "ca.pem"
	serverCertFile = "server.pem"     // fetch/: the APIs' and the shop's
	serverKeyFile  = "server-key.pem" // fetch/
	clientCertFile = "client.pem"     // gateway/: presented to Fetch
	clientKeyFile  = "client-key.pem" // gateway/
	dataCertFile   = "data.pem"       // gateway/: the data listener's
	dataKeyFile    = "data-key.pem"   // gateway/
)

// certs writes the new folder -out with fetch/ for the Fetch host and gateway/
// for the gateway host.
func certs(args []string) error {
	set := flag.NewFlagSet("certs", flag.ContinueOnError)
	out := set.String("out", "", "new folder to write fetch/ and gateway/ into")
	fetchIP := set.String("fetch", "", "the Fetch host's IP address, which the gateway connects to")
	names := set.String("gateway", "", "the gateway's IP addresses or DNS names that browsers use, comma-separated")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *out == "" {
		return errors.New("certs takes -out, -fetch and -gateway\n" + usage)
	}
	fetch, err := netip.ParseAddr(*fetchIP)
	if err != nil || fetch.IsUnspecified() {
		return errors.New("-fetch must be the Fetch host's IP address")
	}
	ips, dns, err := hostNames(*names)
	if err != nil {
		return err
	}
	folders, err := deploymentFiles(fetch, ips, dns, time.Now())
	if err != nil {
		return err
	}
	if err := addImageFiles(folders["gateway"], fetch); err != nil {
		return err
	}
	if err := writeFolders(*out, folders); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Copy its fetch folder to the Fetch host and its gateway folder to the gateway host, then run:\n", *out)
	fmt.Printf("  Fetch host:   go run ./cmd/demo up -role fetch -bind %s -certs <fetch folder>\n", fetch)
	fmt.Printf("  gateway host: go run ./cmd/demo up -role gateway -fetch %s -certs <gateway folder>\n", fetch)
	fmt.Printf("or run the container images with these folders (README, \"Containers\").\n")
	fmt.Printf("The certificates expire on %s.\n", time.Now().Add(certLifetime).UTC().Format(time.DateOnly))
	return nil
}

// writeFolders writes the new private folder out with one private folder per
// host. A failed write removes out, so no half-written set of keys is left to
// be copied.
func writeFolders(out string, folders map[string]map[string][]byte) (err error) {
	if err := privateDirectory(out); err != nil {
		return fmt.Errorf("creating a new folder: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(out)
		}
	}()
	for folder, files := range folders {
		if err := privateDirectory(filepath.Join(out, folder)); err != nil {
			return err
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(out, folder, name), content, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// hostNames splits the gateway's comma-separated addresses and DNS names.
func hostNames(list string) ([]net.IP, []string, error) {
	var ips []net.IP
	var dns []string
	names := strings.Split(list, ",")
	if list == "" || len(names) > 8 {
		return nil, nil, errors.New("-gateway takes 1 to 8 IP addresses or DNS names, comma-separated")
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if address, err := netip.ParseAddr(name); err == nil {
			if address.IsUnspecified() {
				return nil, nil, fmt.Errorf("-gateway: %s names no host", name)
			}
			ips = append(ips, address.AsSlice())
			continue
		}
		if !isDNSName(name) {
			return nil, nil, fmt.Errorf("-gateway: %q is neither an IP address nor a lower-case DNS name", name)
		}
		dns = append(dns, name)
	}
	return ips, dns, nil
}

// isDNSName accepts lower-case labels of letters, digits and '-', joined by dots.
func isDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// deploymentFiles makes the CA, the three certificates and the signing key
// pair, keyed by folder and file name.
func deploymentFiles(fetch netip.Addr, gatewayIPs []net.IP, gatewayDNS []string, now time.Time) (map[string]map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Fetch deployment CA " + now.UTC().Format(time.DateOnly)},
		NotBefore: now.Add(-clockSkew), NotAfter: now.Add(certLifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	issue := func(name string, usage x509.ExtKeyUsage, ips []net.IP, dns []string) ([]byte, []byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		leaf := &x509.Certificate{
			Subject: pkix.Name{CommonName: name}, NotBefore: template.NotBefore, NotAfter: template.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips, DNSNames: dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", private), err
	}
	server, serverKey, err := issue("Fetch", x509.ExtKeyUsageServerAuth, []net.IP{fetch.AsSlice()}, nil)
	if err != nil {
		return nil, err
	}
	client, clientKey, err := issue("APIWard gateway", x509.ExtKeyUsageClientAuth, nil, nil)
	if err != nil {
		return nil, err
	}
	data, dataKey, err := issue("Fetch shop", x509.ExtKeyUsageServerAuth, gatewayIPs, gatewayDNS)
	if err != nil {
		return nil, err
	}
	signing, verifying, err := signingKeys()
	if err != nil {
		return nil, err
	}
	caPEM := pemBlock("CERTIFICATE", caDER)
	return map[string]map[string][]byte{
		"fetch":   {caFile: caPEM, serverCertFile: server, serverKeyFile: serverKey, privateKeyFile: signing},
		"gateway": {caFile: caPEM, clientCertFile: client, clientKeyFile: clientKey, dataCertFile: data, dataKeyFile: dataKey, publicKeyFile: verifying},
	}, nil
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
