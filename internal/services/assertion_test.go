package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A service given the gateway's keys answers only requests whose assertion
// those keys verify, made for it, for the request's method and path, and
// still fresh, and reads the account from the assertion: plain identity
// headers alone, or beside it, count for nothing.
func TestServiceRequiresGatewayAssertion(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	gateway, other := newKey(), newKey()
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &gateway.PublicKey, KeyID: "gateway-a", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keyFile, set, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Name: "support", Secret: testSecret, GatewayKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	sign := func(key *ecdsa.PrivateKey, audience, method, path string, issued time.Time) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "gateway-a"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"iss": "apiward", "aud": audience, "sub": "cust-001", "roles": []string{"CUSTOMER"},
			"method": method, "path": path, "iat": issued.Unix(), "exp": issued.Add(30 * time.Second).Unix(), "jti": "request-1"})
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
	valid := sign(gateway, "support", "GET", "/support/mine", now)
	for _, tc := range []struct {
		name       string
		assertions []string
		status     int
	}{
		{"valid", []string{valid}, 200},
		{"none, identity headers only", nil, 401},
		{"made for another API", []string{sign(gateway, "orders", "GET", "/support/mine", now)}, 401},
		{"made for another method", []string{sign(gateway, "support", "POST", "/support/mine", now)}, 401},
		{"made for another path", []string{sign(gateway, "support", "GET", "/support/tickets", now)}, 401},
		{"expired", []string{sign(gateway, "support", "GET", "/support/mine", now.Add(-time.Minute))}, 401},
		{"issued in the future", []string{sign(gateway, "support", "GET", "/support/mine", now.Add(time.Minute))}, 401},
		{"signed by another key", []string{sign(other, "support", "GET", "/support/mine", now)}, 401},
		{"two assertions", []string{valid, valid}, 401},
	} {
		// The plain headers claim support staff, to whom a customer's own
		// ticket list does not exist; the assertion names a customer.
		r := httptest.NewRequest("GET", "/support/mine", nil)
		r.Header.Set("X-Gateway-Subject", "sup-001")
		r.Header.Set("X-Gateway-Roles", "SUPPORT")
		for _, assertion := range tc.assertions {
			r.Header.Add("X-Gateway-Assertion", assertion)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s: %d %s, want %d", tc.name, w.Code, w.Body, tc.status)
		}
		if tc.status == 200 && (r.Header.Get("X-Gateway-Subject") != "cust-001" || r.Header.Get("X-Gateway-Roles") != "CUSTOMER") {
			t.Errorf("%s: the handler read subject %q and roles %q", tc.name, r.Header.Get("X-Gateway-Subject"), r.Header.Get("X-Gateway-Roles"))
		}
	}

	// Accounts takes the account for me and refresh from the gateway, so a
	// plain identity header is refused there; signing in needs none.
	dir := t.TempDir()
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(signing)
	settings, _ := json.Marshal(map[string]string{"kid": "fetch-test-a", "private_key_file": filepath.Join(dir, "issuer-key.pem")})
	if os.WriteFile(filepath.Join(dir, "issuer-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600) != nil ||
		os.WriteFile(filepath.Join(dir, "accounts.json"), settings, 0o600) != nil {
		t.Fatal("writing the signing settings")
	}
	accounts, err := New(Config{Name: "accounts", Secret: testSecret, SigningSettingsFile: filepath.Join(dir, "accounts.json"), GatewayKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	me := httptest.NewRequest("GET", "/accounts/me", nil)
	me.Header.Set("X-Gateway-Subject", "cust-001")
	w := httptest.NewRecorder()
	accounts.ServeHTTP(w, me)
	if w.Code != 401 {
		t.Errorf("me without an assertion: %d %s", w.Code, w.Body)
	}
	login := httptest.NewRequest("POST", "/accounts/login", strings.NewReader(`{"email":"customer1@fetch.test","password":"FetchDemo2026!"}`))
	login.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	accounts.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Errorf("login without an assertion: %d %s", w.Code, w.Body)
	}
}
