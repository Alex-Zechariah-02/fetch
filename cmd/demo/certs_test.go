// The two-host files: Fetch's listener admits the gateway's client
// certificate and nothing else, the gateway can verify Fetch's certificate,
// both hosts name the Accounts key alike, and the APIWard image's settings
// in the gateway folder are a configuration the gateway accepts.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward"
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

// The APIWard image's settings from demo certs are a configuration the
// gateway accepts once the folder is where the image reads it, and they
// trust the key Accounts signs with.
func TestCertsImageSettings(t *testing.T) {
	dir := writeDeployment(t, "image")
	gateway := filepath.Join(dir, "gateway")
	data, err := os.ReadFile(filepath.Join(gateway, imageSettings))
	if err != nil {
		t.Fatal(err)
	}
	// Mount the folder and a state folder where the image has them.
	settings := string(data)
	for image, local := range map[string]string{imageConfig: gateway, imageState: t.TempDir()} {
		quoted, _ := json.Marshal(local)
		settings = strings.ReplaceAll(settings, `"`+image+`/`, strings.TrimSuffix(string(quoted), `"`)+`/`)
	}
	if strings.Contains(settings, `"/etc/`) || strings.Contains(settings, `"/var/`) {
		t.Fatalf("a path is outside the image's folders:\n%s", settings)
	}
	mounted := filepath.Join(t.TempDir(), imageSettings)
	if err := os.WriteFile(mounted, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := apiward.LoadConfig(mounted); err != nil {
		t.Fatalf("the gateway refuses the image settings: %v", err)
	}
	var parsed struct {
		Gateway struct {
			JWT struct {
				Keys []trustedKey `json:"keys"`
			} `json:"jwt"`
		} `json:"gateway"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Gateway.JWT.Keys) != 1 {
		t.Fatalf("trusted keys: %v %+v", err, parsed)
	}
	signing, err := signingKeyID(filepath.Join(dir, "fetch", privateKeyFile))
	if err != nil || parsed.Gateway.JWT.Keys[0].Kid != signing {
		t.Fatalf("the image trusts %q, Accounts signs as %q (%v)", parsed.Gateway.JWT.Keys[0].Kid, signing, err)
	}
}

// writeDeployment writes a new pair of host folders for a Fetch host on
// 127.0.0.1, as demo certs does, and returns their parent.
func writeDeployment(t *testing.T, name string) string {
	t.Helper()
	fetch := netip.MustParseAddr("127.0.0.1")
	folders, err := deploymentFiles(fetch, nil, []string{"shop.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := addImageFiles(folders["gateway"], fetch); err != nil {
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
