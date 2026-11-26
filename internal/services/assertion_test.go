// The gateway's assertion: what a service admits, what it refuses, and the
// bounded record of its refusals.

package services

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
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
	var refusals bytes.Buffer
	s := newService(t, Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders, GatewayKey: keyFile, Log: slog.New(slog.NewTextHandler(&refusals, nil))})

	now := time.Now()
	issuer := "apiward"
	sign := func(key *ecdsa.PrivateKey, audience, method, path string, issued time.Time) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "gateway-a"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": "cust-001", "roles": []string{"CUSTOMER"},
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
	issuer = "another-gateway"
	foreign := sign(gateway, "support", "GET", "/support/mine", now)
	issuer = "apiward"
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
		{"made by another issuer", []string{foreign}, 401},
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

	// Nine refusals within a second leave one log line; a refusal a second
	// later counts itself and the eight not logged.
	if lines := strings.Count(refusals.String(), "gateway assertion refused"); lines != 1 || !strings.Contains(refusals.String(), "reason=") {
		t.Fatalf("%d refusal lines: %s", lines, refusals.String())
	}
	r := httptest.NewRequest("GET", "/support/mine", nil)
	if s.gateway.check(r, time.Now().Add(2*refusalGap)) || !strings.Contains(refusals.String(), "refused=9") {
		t.Fatalf("the next refusal line: %s", refusals.String())
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
	accounts, err := New(Config{Name: "accounts", Keys: testKeys("accounts"), SigningSettingsFile: filepath.Join(dir, "accounts.json"), GatewayKey: keyFile})
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

func TestAssertionRefusesCritNullAndDuplicateMembers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "g1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keyFile, set, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newService(t, Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders, GatewayKey: keyFile})

	signRaw := func(headerJSON, payloadJSON string) string {
		h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
		p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		input := h + "." + p
		sum := sha256.Sum256([]byte(input))
		r, sv, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	now := time.Now().Unix()
	validHdr := `{"alg":"ES256","kid":"g1"}`
	validPay := fmt.Sprintf(`{"iss":"apiward","aud":"support","sub":"cust-001","roles":["CUSTOMER"],"method":"GET","path":"/support/mine","iat":%d,"exp":%d,"jti":"r1"}`, now, now+30)
	dupPay := fmt.Sprintf(`{"iss":"apiward","aud":"support","sub":"cust-001","sub":"cust-002","roles":["CUSTOMER"],"method":"GET","path":"/support/mine","iat":%d,"exp":%d,"jti":"r1"}`, now, now+30)

	cases := []struct {
		name, hdr, pay string
		want           int
	}{
		{"valid", validHdr, validPay, http.StatusOK},
		{"crit null", `{"alg":"ES256","kid":"g1","crit":null}`, validPay, http.StatusUnauthorized},
		{"duplicate header member", `{"alg":"ES256","kid":"g1","kid":"g1"}`, validPay, http.StatusUnauthorized},
		{"duplicate payload member", validHdr, dupPay, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/support/mine", nil)
			req.Header.Set("X-Gateway-Assertion", signRaw(tc.hdr, tc.pay))
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s: status=%d, want %d (body=%s)", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestAssertionSizeAtBound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "g12", Algorithm: "ES256", Use: "sig"},
		{Key: &key.PublicKey, KeyID: "g123", Algorithm: "ES256", Use: "sig"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keyFile, set, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newService(t, Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders, GatewayKey: keyFile, Log: slog.New(slog.DiscardHandler)})

	signSized := func(kid string, payloadBytes int) string {
		now := time.Now().Unix()
		prefix := fmt.Sprintf(`{"iss":"apiward","aud":"support","sub":"cust-001","roles":["CUSTOMER"],"method":"GET","path":"/support/mine","iat":%d,"exp":%d,"jti":"`, now, now+30)
		suffix := `"}`
		pad := payloadBytes - len(prefix) - len(suffix)
		if pad < 0 {
			t.Fatalf("payload target %d too small", payloadBytes)
		}
		hdr := fmt.Sprintf(`{"alg":"ES256","kid":%q}`, kid)
		pay := prefix + strings.Repeat("x", pad) + suffix
		input := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." + base64.RawURLEncoding.EncodeToString([]byte(pay))
		sum := sha256.Sum256([]byte(input))
		rv, sv, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		rv.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	atBound := signSized("g12", 2979)
	overBound := signSized("g123", 2978)
	if len(atBound) != maxAssertion || len(overBound) != maxAssertion+1 {
		t.Fatalf("assertion lengths = %d and %d, want %d and %d", len(atBound), len(overBound), maxAssertion, maxAssertion+1)
	}
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"at bound", atBound, http.StatusOK},
		{"one byte over", overBound, http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, "/support/mine", nil)
		req.Header.Set("X-Gateway-Assertion", tc.token)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s (%d bytes): status=%d, want %d", tc.name, len(tc.token), rec.Code, tc.want)
		}
	}
}
