// A host's certs folder is refused before anything starts when a
// certificate has expired or is about to, when its server certificate names
// another address, or when it is the other host's folder; a key that cannot
// be parsed is named as such.

package main

import (
	"crypto/x509"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertFolderRefusesExpiry(t *testing.T) {
	t.Parallel()
	fresh := filepath.Join(writeDeployment(t, "fresh"), "fetch")
	if _, err := certFolder(fresh, caFile, serverCertFile); err != nil {
		t.Fatalf("a new folder: %v", err)
	}
	folders, err := deploymentFiles(netip.MustParseAddr("127.0.0.1"), nil, []string{"shop.example"}, time.Now().Add(-certLifetime+time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	old := t.TempDir()
	for name, content := range folders["fetch"] {
		if err := os.WriteFile(filepath.Join(old, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := certFolder(old, caFile, serverCertFile); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("a certificate expiring within the hour: %v", err)
	}
	// Key files are not certificates and are not read for dates.
	if _, err := certFolder(old, privateKeyFile); err != nil {
		t.Fatalf("a key file: %v", err)
	}
}

func TestCheckIssuedNamesTheHost(t *testing.T) {
	t.Parallel()
	root := writeDeployment(t, "issued")
	fetch, gateway := filepath.Join(root, "fetch"), filepath.Join(root, "gateway")
	if err := checkIssued(fetch, serverCertFile, x509.ExtKeyUsageServerAuth, "127.0.0.1"); err != nil {
		t.Fatalf("the server certificate for its own address: %v", err)
	}
	if err := checkIssued(fetch, serverCertFile, x509.ExtKeyUsageServerAuth, "127.0.0.3"); err == nil || !strings.Contains(err.Error(), "127.0.0.3") {
		t.Fatalf("another -bind: %v", err)
	}
	if err := checkIssued(gateway, clientCertFile, x509.ExtKeyUsageClientAuth, ""); err != nil {
		t.Fatalf("the gateway's client certificate: %v", err)
	}
	// The other deployment's CA did not issue this folder's certificate.
	other := filepath.Join(writeDeployment(t, "other"), "gateway")
	data, err := os.ReadFile(filepath.Join(other, caFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gateway, caFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkIssued(gateway, clientCertFile, x509.ExtKeyUsageClientAuth, ""); err == nil || !strings.Contains(err.Error(), "not issued") {
		t.Fatalf("a certificate of another CA: %v", err)
	}
}

func TestKeyIDNamesAParseFailure(t *testing.T) {
	t.Parallel()
	corrupt := pemBlock("PRIVATE KEY", []byte("not a key"))
	if _, err := keyID(corrupt); err == nil || !strings.Contains(err.Error(), "not a readable private key") {
		t.Fatalf("corrupt key: %v", err)
	}
}
