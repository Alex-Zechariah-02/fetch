// The two-host files: Fetch's listener admits the gateway's client
// certificate and nothing else, the gateway can verify Fetch's certificate,
// and both hosts name the Accounts key alike.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

func TestCertsAdmitOnlyGateway(t *testing.T) {
	dir := writeDeployment(t, "first")
	other := writeDeployment(t, "other")
	fetch, gateway := filepath.Join(dir, "fetch"), filepath.Join(dir, "gateway")
	listener, err := services.Listen("127.0.0.1:0", services.Ingress{
		Certificate: filepath.Join(fetch, serverCertFile), Key: filepath.Join(fetch, serverKeyFile), ClientCA: filepath.Join(fetch, caFile),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go server.Serve(listener)
	defer server.Close()
	roots := x509.NewCertPool()
	if data, err := os.ReadFile(filepath.Join(gateway, caFile)); err != nil || !roots.AppendCertsFromPEM(data) {
		t.Fatal("reading the gateway's copy of the CA")
	}
	// call connects as the gateway does: checking Fetch's certificate for its
	// IP address and presenting the certificate in folder, if any.
	call := func(folder, certificate, key string) error {
		config := &tls.Config{RootCAs: roots}
		if certificate != "" {
			pair, err := tls.LoadX509KeyPair(filepath.Join(folder, certificate), filepath.Join(folder, key))
			if err != nil {
				t.Fatal(err)
			}
			config.Certificates = []tls.Certificate{pair}
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}}
		response, err := client.Get("https://" + listener.Addr().String() + "/")
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		return nil
	}
	if err := call(gateway, clientCertFile, clientKeyFile); err != nil {
		t.Fatalf("the gateway's client certificate was refused: %v", err)
	}
	if call(gateway, "", "") == nil {
		t.Error("a client without a certificate was admitted")
	}
	if call(gateway, dataCertFile, dataKeyFile) == nil {
		t.Error("the gateway's server certificate was admitted as a client certificate")
	}
	if call(filepath.Join(other, "gateway"), clientCertFile, clientKeyFile) == nil {
		t.Error("a client certificate from another CA was admitted")
	}

	private, err := signingKeyID(filepath.Join(fetch, privateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	public, err := signingKeyID(filepath.Join(gateway, publicKeyFile))
	if err != nil || public != private {
		t.Fatalf("the hosts name the signing key %q and %q (%v)", private, public, err)
	}
}

// writeDeployment writes a new pair of host folders for a Fetch host on
// 127.0.0.1 and returns their parent.
func writeDeployment(t *testing.T, name string) string {
	t.Helper()
	folders, err := deploymentFiles(netip.MustParseAddr("127.0.0.1"), nil, []string{"shop.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), name)
	for folder, files := range folders {
		if err := os.MkdirAll(filepath.Join(dir, folder), 0o700); err != nil {
			t.Fatal(err)
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(dir, folder, file), content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}
