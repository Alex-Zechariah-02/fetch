// The two-host files: Fetch's listener admits the gateway's client
// certificate and nothing else, the gateway can verify Fetch's certificate,
// an API verifies the gateway's assertion, both hosts name the Accounts key
// alike, and the APIWard image's settings
// in the gateway folder are a configuration the gateway accepts.

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward"
	"github.com/Alex-Zechariah-02/fetch/internal/services"
	"github.com/go-jose/go-jose/v4"
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

	// An API started with the Fetch folder's key set answers a request the
	// gateway folder's assertion key signed, and no request without one.
	support, err := services.New(services.Config{Name: "support", Secret: []byte("0123456789abcdef0123456789abcdef"), GatewayKey: filepath.Join(fetch, assertionSetFile)})
	if err != nil {
		t.Fatal(err)
	}
	for assertion, want := range map[string]int{signedAssertion(t, filepath.Join(gateway, assertionKeyFile)): http.StatusOK, "": http.StatusUnauthorized} {
		request := httptest.NewRequest(http.MethodGet, "/support/mine", nil)
		if assertion != "" {
			request.Header.Set("X-Gateway-Assertion", assertion)
		}
		recorder := httptest.NewRecorder()
		support.ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Errorf("assertion %q: status %d, want %d", assertion, recorder.Code, want)
		}
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

// signedAssertion signs, as the gateway does with the PKCS #8 key at path, an
// assertion for a customer reading their own Support tickets now.
func signedAssertion(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The gateway names its key by the RFC 7638 thumbprint.
	thumbprint, err := (&jose.JSONWebKey{Key: key}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", base64.RawURLEncoding.EncodeToString(thumbprint)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{"aud": "support", "sub": "cust-001", "roles": []string{"CUSTOMER"},
		"method": "GET", "path": "/support/mine", "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix()})
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
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
