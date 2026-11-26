// Built-in protection's token check: only a token the configured key signed,
// unchanged, is accepted; each forged or altered form is refused with its
// reason.

package guard

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestTokenHeaderAndClaimRefusals(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	kid64 := strings.Repeat("k", 64)
	keys := map[string]*rsa.PublicKey{"k1": &key.PublicKey, kid64: &key.PublicKey}
	now := time.Now()

	// Segment counts in verify (missing second dot and extra fourth segment).
	validHdr := b64(`{"alg":"RS256","kid":"k1","typ":"JWT"}`)
	validPay := b64(`{"iss":"fetch-accounts","aud":"fetch-gateway","sub":"cust-001","exp":9999999999}`)
	for _, tc := range []struct {
		name, token string
	}{
		{"two segments", validHdr + "." + validPay},
		{"four segments", validHdr + "." + validPay + ".AAAA.BBBB"},
	} {
		if _, reason := verify(keys, tc.token, now); reason != "malformed_credential" {
			t.Errorf("%s: reason=%q, want malformed_credential", tc.name, reason)
		}
	}

	// Header structure and member refusals.
	for _, tc := range []struct {
		name, hdr, want string
	}{
		{"null header", "null", "malformed_credential"},
		{"duplicate header member", `{"alg":"RS256","alg":"RS256","kid":"k1"}`, "malformed_credential"},
		{"wrong alg", `{"alg":"ES256","kid":"k1"}`, "unsupported_header"},
		{"empty kid", `{"alg":"RS256","kid":""}`, "unsupported_header"},
		{"64-byte kid accepted", fmt.Sprintf(`{"alg":"RS256","kid":%q}`, kid64), ""},
		{"65-byte kid refused", fmt.Sprintf(`{"alg":"RS256","kid":%q}`, kid64+"x"), "unsupported_header"},
	} {
		gotKid, reason := checkHeader(b64(tc.hdr))
		if reason != tc.want {
			t.Errorf("header %s: reason=%q, want %q", tc.name, reason, tc.want)
		}
		if tc.want == "" && gotKid != kid64 {
			t.Errorf("header %s: kid=%q, want %q", tc.name, gotKid, kid64)
		}
	}

	// Claim payload structure, numericDate bounds/fractions, and subject bounds.
	expFuture := now.Add(time.Hour).Unix()
	claim := func(sub string, exp any) []byte {
		data, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": sub, "exp": exp})
		return data
	}
	for _, tc := range []struct {
		name    string
		payload []byte
		at      time.Time
		want    string
	}{
		{"null claims", []byte("null"), now, "invalid_claims"},
		{"duplicate claim member", []byte(fmt.Sprintf(`{"iss":"%s","aud":"%s","sub":"a","sub":"b","exp":%d}`, issuer, audience, expFuture)), now, "invalid_claims"},
		{"non-numeric exp", claim("cust-001", "soon"), now, "invalid_claims"},
		{"negative exp", claim("cust-001", -1), now, "invalid_claims"},
		{"zero exp within leeway", claim("cust-001", 0), time.Unix(0, 0), ""},
		{"max numericDate exp", claim("cust-001", maxNumericDate), now, ""},
		{"above max numericDate exp", claim("cust-001", float64(maxNumericDate)+1), now, "invalid_claims"},
		{"fractional exp preserved", []byte(fmt.Sprintf(`{"iss":"%s","aud":"%s","sub":"cust-001","exp":1000.9}`, issuer, audience)), time.Unix(1060, 500_000_000), ""},
		{"empty subject", claim("", expFuture), now, "invalid_claims"},
		{"subject at max length", claim(strings.Repeat("a", maxSubject), expFuture), now, ""},
		{"subject over max length", claim(strings.Repeat("a", maxSubject+1), expFuture), now, "invalid_claims"},
		{"subject with space", claim("a b", expFuture), now, "invalid_claims"},
		{"subject with DEL", claim("a\x7fb", expFuture), now, "invalid_claims"},
		{"subject boundary bang 0x21", claim("!", expFuture), now, ""},
		{"subject boundary tilde 0x7e", claim("~", expFuture), now, ""},
	} {
		if _, reason := checkClaims(tc.payload, tc.at); reason != tc.want {
			t.Errorf("claims %s: reason=%q, want %q", tc.name, reason, tc.want)
		}
	}
}
