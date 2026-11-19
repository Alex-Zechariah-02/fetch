// Built-in protection's token check: only a token the configured key signed,
// unchanged, is accepted; each forged or altered form is refused with its
// reason.

package guard

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestVerifyRefusesForgedTokens(t *testing.T) {
	newKey := func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	trusted, other := newKey(), newKey()
	now := time.Now()
	sign := func(key *rsa.PrivateKey, subject string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": subject, "exp": now.Add(time.Minute).Unix()})
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
	valid := sign(trusted, "cust-001")
	parts := strings.Split(valid, ".")
	otherParts := strings.Split(sign(trusted, "cust-002"), ".")
	flipped := []byte(parts[2])
	// Another base64url letter at the same place: the signature's bits change.
	flipped[10] = map[bool]byte{true: 'B', false: 'A'}[flipped[10] == 'A']
	keys := map[string]*rsa.PublicKey{"k1": &trusted.PublicKey}
	for _, tc := range []struct {
		name, token, reason string
	}{
		{"valid", valid, ""},
		{"signature bit flipped", parts[0] + "." + parts[1] + "." + string(flipped), "invalid_signature"},
		{"payload replaced after signing", parts[0] + "." + otherParts[1] + "." + parts[2], "invalid_signature"},
		{"another key under the trusted kid", sign(other, "cust-001"), "invalid_signature"},
		{"signature cut short", parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-8], "invalid_signature"},
		{"signature not base64url", parts[0] + "." + parts[1] + ".!!", "malformed_credential"},
	} {
		got, reason := verify(keys, tc.token, now)
		if reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.reason)
		}
		if tc.reason == "" && got.subject != "cust-001" {
			t.Errorf("%s: subject %q, want cust-001", tc.name, got.subject)
		}
	}
}

// Token times get the gateway's default 60 s leeway for clock difference,
// so setups B and C accept the same tokens: expired 30 s ago passes, 90 s
// ago does not; not valid until 30 s from now passes, 90 s does not.
func TestClaimsLeeway(t *testing.T) {
	now := time.Now()
	claims := func(exp, nbf time.Time) []byte {
		payload, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": "cust-001", "exp": exp.Unix(), "nbf": nbf.Unix()})
		return payload
	}
	for _, tc := range []struct {
		name     string
		exp, nbf time.Time
		reason   string
	}{
		{"expired 30 s ago", now.Add(-30 * time.Second), now.Add(-time.Hour), ""},
		{"expired 90 s ago", now.Add(-90 * time.Second), now.Add(-time.Hour), "expired"},
		{"valid in 30 s", now.Add(time.Hour), now.Add(30 * time.Second), ""},
		{"valid in 90 s", now.Add(time.Hour), now.Add(90 * time.Second), "not_yet_valid"},
	} {
		if _, reason := checkClaims(claims(tc.exp, tc.nbf), now); reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.reason)
		}
	}
}
