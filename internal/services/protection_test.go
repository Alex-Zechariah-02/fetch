// Built-in protection on real services: each control refuses before the
// handler runs (no receipt), tokens issued by the real Accounts pass, the
// blocked list changes through the control listener, rates and bodies are
// enforced, and the admission is in the security log when the answer leaves.

package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"github.com/go-jose/go-jose/v4"
)

// protectedStack is Accounts and Orders with built-in protection sharing one
// settings folder, as demo up -local runs them.
type protectedStack struct {
	accounts, orders *Service
	key              *rsa.PrivateKey
	dir              string
}

func newProtectedStack(t *testing.T) protectedStack {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	settings, _ := json.Marshal(map[string]string{"kid": "fetch-test-a", "private_key_file": filepath.Join(dir, "issuer-key.pem")})
	keys, _ := json.Marshal([]guard.Key{{Kid: "fetch-test-a", PublicKeyFile: filepath.Join(dir, "issuer.pem")}})
	for name, content := range map[string][]byte{
		"issuer-key.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		"issuer.pem":      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		"accounts.json":   settings,
		guard.KeysFile:    keys,
		guard.BlockedFile: []byte("[]"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	accounts, err := New(Config{Name: "accounts", Secret: testSecret, SigningSettingsFile: filepath.Join(dir, "accounts.json"), Protection: dir})
	if err != nil {
		t.Fatal(err)
	}
	orders, err := New(Config{Name: "orders", Secret: testSecret, InventoryURL: "http://127.0.0.1:1", Protection: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accounts.guard.Close(); orders.guard.Close() })
	return protectedStack{accounts, orders, key, dir}
}

// call sends one request to s's API handler, optionally with a bearer token.
func call(s *Service, method, path, body, token string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.api().ServeHTTP(w, r)
	return w
}

// login signs in through the protected Accounts and returns its real token.
func (p protectedStack) login(t *testing.T, email string) string {
	t.Helper()
	w := call(p.accounts, "POST", "/accounts/login", `{"email":"`+email+`","password":"FetchDemo2026!"}`, "")
	var reply struct{ Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Token == "" {
		t.Fatalf("login through built-in protection: %d %s", w.Code, w.Body)
	}
	return reply.Token
}

// sign makes a token with claims and extra header members, signed by key.
func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any, header map[jose.HeaderKey]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	for name, value := range header {
		options = options.WithHeader(name, value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := signed.CompactSerialize()
	return token
}

func TestProtectionRefusesBeforeHandler(t *testing.T) {
	p := newProtectedStack(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	claims := func(change map[string]any) map[string]any {
		c := map[string]any{"iss": "fetch-accounts", "aud": "fetch-gateway", "sub": "cust-001", "roles": []string{"CUSTOMER"}, "nbf": now, "exp": now + 600}
		for name, value := range change {
			c[name] = value
		}
		return c
	}
	valid := sign(t, p.key, "fetch-test-a", claims(nil), nil)
	if w := call(p.orders, "GET", "/orders/wallet", "", valid); w.Code != 200 || w.Header().Get("X-Request-Id") == "" {
		t.Fatalf("a valid token was refused: %d %s", w.Code, w.Body)
	}
	p.orders.receipts = nil
	checkout := `{"merchant":"MER-001","items":[{"item":"ITM-001","quantity":0}],"address":{"line1":"1 Jalan","postcode":"50000","city":"KL","state":"Selangor"},"payment":"cash"}`
	for _, c := range []struct {
		name, method, path, body, token string
		headers                         []string
		status                          int
		code                            string
	}{
		{"no token", "GET", "/orders/wallet", "", "", nil, 401, "unauthenticated"},
		{"identity headers only", "GET", "/orders/wallet", "", "", []string{"X-Gateway-Subject", "cust-001", "X-Gateway-Roles", "CUSTOMER"}, 401, "unauthenticated"},
		{"another key", "GET", "/orders/wallet", "", sign(t, other, "fetch-test-a", claims(nil), nil), nil, 401, "unauthenticated"},
		{"unknown key ID", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-b", claims(nil), nil), nil, 401, "unauthenticated"},
		{"expired at exp", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-a", claims(map[string]any{"exp": now}), nil), nil, 401, "unauthenticated"},
		{"not yet valid", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-a", claims(map[string]any{"nbf": now + 300}), nil), nil, 401, "unauthenticated"},
		{"wrong audience", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-a", claims(map[string]any{"aud": "orders"}), nil), nil, 401, "unauthenticated"},
		{"wrong issuer", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-a", claims(map[string]any{"iss": "elsewhere"}), nil), nil, 401, "unauthenticated"},
		{"key URL header", "GET", "/orders/wallet", "", sign(t, p.key, "fetch-test-a", claims(nil), map[jose.HeaderKey]any{"jku": "https://example.com/keys"}), nil, 401, "unauthenticated"},
		{"role only in a header", "GET", "/orders", "", valid, []string{"X-Gateway-Roles", "OPERATIONS"}, 403, "forbidden"},
		{"undefined role", "GET", "/orders", "", sign(t, p.key, "fetch-test-a", claims(map[string]any{"roles": []string{"ADMIN"}}), nil), nil, 403, "forbidden"},
		{"schema", "POST", "/orders", checkout, valid, nil, 400, "bad_request"},
		{"media type", "POST", "/orders", checkout, valid, []string{"Content-Type", "text/plain"}, 415, "unsupported_media_type"},
		{"body on a read", "GET", "/orders/wallet", "{}", valid, nil, 400, "bad_request"},
		{"no operation", "GET", "/orders/unknown", "", valid, nil, 404, "not_found"},
	} {
		w := call(p.orders, c.method, c.path, c.body, c.token, c.headers...)
		var reply struct{ Error string }
		json.Unmarshal(w.Body.Bytes(), &reply)
		if w.Code != c.status || reply.Error != c.code {
			t.Errorf("%s: %d %q, want %d %q", c.name, w.Code, reply.Error, c.status, c.code)
		}
	}
	if len(p.orders.receipts) != 0 {
		t.Fatalf("refused requests reached the handler: %d receipts", len(p.orders.receipts))
	}
}

func TestProtectionAccountsBlockedRateAndLog(t *testing.T) {
	p := newProtectedStack(t)
	token := p.login(t, "customer1@fetch.test")
	// Accounts itself no longer believes an identity header.
	if w := call(p.accounts, "GET", "/accounts/me", "", "", "X-Gateway-Subject", "ops-01"); w.Code != 401 {
		t.Fatalf("forged identity reached Accounts: %d", w.Code)
	}
	if w := call(p.accounts, "GET", "/accounts/me", "", token, "X-Gateway-Subject", "ops-01"); w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"cust-001"`) {
		t.Fatalf("verified identity not used: %d %s", w.Code, w.Body)
	}

	w := call(p.orders, "GET", "/orders/wallet", "", token)
	log, _ := os.ReadFile(filepath.Join(p.dir, guard.LogFile("orders")))
	admitted := `"kind":"request.admitted","request_id":"` + w.Header().Get("X-Request-Id") + `"`
	if w.Code != 200 || !strings.Contains(string(log), admitted) {
		t.Fatalf("admission not synced before the answer: %d", w.Code)
	}

	control := p.orders.Control(testSecret)
	setBlocked := func(list string) {
		r := httptest.NewRequest("PUT", "/blocked", strings.NewReader(list))
		r.Header.Set("Authorization", "Bearer "+string(testSecret))
		rec := httptest.NewRecorder()
		control.ServeHTTP(rec, r)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("blocked list %s refused: %d", list, rec.Code)
		}
	}
	setBlocked(`["cust-001"]`)
	if w := call(p.orders, "GET", "/orders/wallet", "", token); w.Code != 403 || !strings.Contains(w.Body.String(), "account_blocked") {
		t.Fatalf("blocked account admitted: %d", w.Code)
	}
	setBlocked(`[]`)

	// orders.cancel allows 10 per minute per account; only admitted requests count.
	for i := range 11 {
		w := call(p.orders, "POST", "/orders/cancel/ORD-0000", "", token)
		if limited := w.Code == 429; limited != (i == 10) {
			t.Fatalf("cancel %d: status %d", i+1, w.Code)
		}
	}
}
