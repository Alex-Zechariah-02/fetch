// A host's folder from demo certs as demo up reads it: every file present,
// no certificate expired or about to, each certificate issued by the
// folder's CA for this host's use, and the Accounts key named alike on both
// hosts.

package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

// certificateFiles are the files of a certs folder that hold certificates.
var certificateFiles = []string{caFile, serverCertFile, clientCertFile, dataCertFile}

// expiryMargin refuses a certificate that expires within a day, so a started
// demonstration does not fail its handshakes part way through.
const expiryMargin = 24 * time.Hour

// certFolder is the absolute path of dir, a host's folder from demo certs,
// once it holds every one of files and none of its certificates has expired
// or expires within expiryMargin.
func certFolder(dir string, files ...string) (string, error) {
	if dir == "" {
		return "", errors.New("-certs is required: this host's folder from demo certs")
	}
	folder, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for _, name := range files {
		if info, err := os.Stat(filepath.Join(folder, name)); err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s has no file %s: pass this host's folder from demo certs", folder, name)
		}
		if !slices.Contains(certificateFiles, name) {
			continue
		}
		if err := checkExpiry(filepath.Join(folder, name), time.Now()); err != nil {
			return "", err
		}
	}
	return folder, nil
}

// checkExpiry refuses the certificate file at path when a certificate in it
// has expired or expires within expiryMargin of now.
func checkExpiry(path string, now time.Time) error {
	leaf, err := readCertificate(path)
	if err != nil {
		return err
	}
	if now.Add(expiryMargin).After(leaf.NotAfter) {
		return fmt.Errorf("%s expires %s: make new folders with demo certs", path, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// readCertificate is the first certificate in the PEM file at path.
func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return leaf, nil
}

// checkIssued refuses the certificate name in folder unless the folder's CA
// issued it for usage and, when host is set, it names host: a folder made
// for another address, or the other host's folder, fails here and not at
// the first handshake.
func checkIssued(folder, name string, usage x509.ExtKeyUsage, host string) error {
	leaf, err := readCertificate(filepath.Join(folder, name))
	if err != nil {
		return err
	}
	authority, err := readCertificate(filepath.Join(folder, caFile))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return fmt.Errorf("%s was not issued by this folder's CA for this host: %w", filepath.Join(folder, name), err)
	}
	if host == "" {
		return nil
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return fmt.Errorf("%s names %v %v, not %s: pass the folder demo certs made for this address", filepath.Join(folder, name), leaf.IPAddresses, leaf.DNSNames, host)
	}
	return nil
}

// signingKeyID names the Accounts signing key in the PEM file at path, its
// private (PKCS #8) or public (PKIX) half, after its public key, so each host
// derives the same ID from its own file.
func signingKeyID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	kid, err := keyID(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return kid, nil
}

// keyID is signingKeyID for the PEM key in data.
func keyID(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("no PEM key")
	}
	var public any
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("not a readable private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return "", errors.New("not a private signing key")
		}
		public = signer.Public()
	case "PUBLIC KEY":
		var err error
		if public, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("a %s, not a key", block.Type)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	// Eight bytes, 64 bits, keep the ID short and still tell different keys apart.
	return "fetch-" + hex.EncodeToString(sum[:8]), nil
}

// certificateURL is the shop's address on the gateway host: the first name in
// the certificate chain at path, on the data listener's port.
func certificateURL(path string) (string, error) {
	leaf, err := readCertificate(path)
	if err != nil {
		return "", err
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
