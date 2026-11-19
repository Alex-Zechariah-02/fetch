// The gateway's key type fixes the assertion's algorithm: an Ed25519 key
// verifies EdDSA, a P-256 key ES256, and a token naming the other algorithm
// is refused, whatever its signature.

package services

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestAssertionKeyFixesAlgorithm(t *testing.T) {
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: edPublic, KeyID: "ed", Algorithm: "EdDSA", Use: "sig"},
		{Key: &ec.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, set, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := loadAssertions(path, "orders", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"iss":"apiward"}`)
	sign := func(algorithm jose.SignatureAlgorithm, key any, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
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
	for _, tc := range []struct {
		name  string
		token string
		ok    bool
	}{
		{"EdDSA by the Ed25519 key", sign(jose.EdDSA, edPrivate, "ed"), true},
		{"ES256 by the P-256 key", sign(jose.ES256, ec, "ec"), true},
		{"ES256 naming the Ed25519 key", sign(jose.ES256, ec, "ed"), false},
		{"EdDSA naming the P-256 key", sign(jose.EdDSA, edPrivate, "ec"), false},
	} {
		got, err := a.verify(tc.token)
		if tc.ok != (err == nil) || tc.ok && string(got) != string(payload) {
			t.Errorf("%s: %q %v", tc.name, got, err)
		}
	}
	// An assertion is honoured only for its short life: one signed for an
	// hour is refused, however valid its signature.
	claimsFor := func(life time.Duration) []byte {
		now := time.Now()
		payload, _ := json.Marshal(map[string]any{"iss": "apiward", "aud": "orders", "sub": "cust-001", "roles": []string{"CUSTOMER"},
			"method": "GET", "path": "/orders/wallet", "iat": now.Unix(), "exp": now.Add(life).Unix(), "jti": "r1"})
		return payload
	}
	for life, admitted := range map[time.Duration]bool{30 * time.Second: true, time.Hour: false} {
		payload = claimsFor(life)
		r := httptest.NewRequest("GET", "/orders/wallet", nil)
		r.Header.Set(assertionHeader, sign(jose.EdDSA, edPrivate, "ed"))
		if err := a.admit(r, time.Now()); (err == nil) != admitted {
			t.Errorf("assertion living %s: %v", life, err)
		}
	}
	payload = []byte(`{"iss":"apiward"}`)
	// An EdDSA header over a signature of the right length from no key.
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ed"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := a.verify(forged); err == nil {
		t.Error("a forged EdDSA assertion verified")
	}
}
