// Gateway assertion key set hot-reload tests.

package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeEdAssertionKey(t *testing.T) (ed25519.PrivateKey, string, map[string]any) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x))
	kid := base64.RawURLEncoding.EncodeToString(sum[:])
	jwk := map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "use": "sig", "alg": "EdDSA",
	}
	return priv, kid, jwk
}

func signTestAssertion(t *testing.T, priv ed25519.PrivateKey, kid, aud, method, path string, now time.Time) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	pay, _ := json.Marshal(map[string]any{
		"iss": assertionIssuer, "aud": aud, "sub": "alice", "roles": []string{"CUSTOMER"},
		"method": method, "path": path, "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(),
	})
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pay)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAssertionKeysReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv1, kid1, jwk1 := makeEdAssertionKey(t)
	priv2, kid2, jwk2 := makeEdAssertionKey(t)

	writeSet := func(keys ...map[string]any) {
		raw, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSet(jwk1)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := loadAssertions(path, "orders", log)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	req := func(priv ed25519.PrivateKey, kid string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/orders", nil)
		r.Header.Set(assertionHeader, signTestAssertion(t, priv, kid, "orders", http.MethodGet, "/orders", now))
		return r
	}

	if err := a.admit(req(priv1, kid1), now); err != nil {
		t.Fatalf("initial key1 rejected: %v", err)
	}
	if err := a.admit(req(priv2, kid2), now); err == nil {
		t.Fatal("key2 accepted before reload")
	}

	// Replace the file with key2 and advance its mtime past the 1s check window.
	writeSet(jwk2)
	future := now.Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)

	if err := a.admit(req(priv2, kid2), time.Now()); err != nil {
		t.Fatalf("reloaded key2 rejected: %v", err)
	}
	if err := a.admit(req(priv1, kid1), time.Now()); err == nil {
		t.Fatal("removed key1 still accepted after reload")
	}

	// Corrupt the file; previous key2 must stay active.
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := a.admit(req(priv2, kid2), time.Now()); err != nil {
		t.Fatalf("key2 lost after bad reload: %v", err)
	}
}
