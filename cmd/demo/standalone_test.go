// The standalone mode's routing and identity: API paths go to their service,
// and only the token's claims, never the client's headers, name the caller.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestStandaloneRoutes(t *testing.T) {
	for path, want := range map[string]string{
		"/orders": "orders", "/orders/mine": "orders", "/inventory/merchants": "inventory", "/accounts/login": "accounts",
		"/reports/summary": "reports", "/support/tickets": "support", "/support": "", "/": "", "/store/MER-001": "", "/assets/app.js": "",
	} {
		if got := apiOf(path); got != want {
			t.Errorf("%s goes to %q, want %q", path, got, want)
		}
	}
}

func TestStandaloneIdentity(t *testing.T) {
	forged := httptest.NewRequest("GET", "/orders/mine", nil)
	forged.Header.Set("X-Gateway-Subject", "ops-001")
	forged.Header.Set("X-Gateway-Roles", "OPERATIONS")
	copyIdentity(forged)
	if forged.Header.Get("X-Gateway-Subject") != "" || forged.Header.Get("X-Gateway-Roles") != "" {
		t.Fatal("identity headers sent by the client reached the service")
	}

	// Any key will do: the standalone mode never verifies the signature.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{"sub": "cust-001", "roles": []string{"CUSTOMER"}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	signed := httptest.NewRequest("GET", "/orders/mine", nil)
	signed.Header.Set("Authorization", "Bearer "+token)
	signed.Header.Set("X-Gateway-Subject", "ops-001")
	copyIdentity(signed)
	if signed.Header.Get("X-Gateway-Subject") != "cust-001" || signed.Header.Get("X-Gateway-Roles") != "CUSTOMER" {
		t.Fatalf("token claims not copied: %v", signed.Header)
	}
}
