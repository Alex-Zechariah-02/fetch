// Verification of the gateway's signed identity assertion. A service given
// the gateway's public keys answers an API request only when it carries an
// assertion those keys verify, made for this service and still fresh, and
// takes the account and roles from it instead of the plain identity headers.

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	assertionHeader = "X-Gateway-Assertion"
	// maxAssertion bounds the header before any parsing.
	maxAssertion = 4096
	// assertionLeeway is the clock difference tolerated between the gateway
	// and this service, on both "iat" and "exp".
	assertionLeeway = 5 * time.Second
)

// assertions verifies the gateway's assertions for one service.
type assertions struct {
	keys     map[string]*ecdsa.PublicKey // by key ID
	audience string                      // this service's API ID
}

// loadAssertions reads the gateway's public keys from a JSON Web Key Set
// file, as the gateway's jwks command prints it. Every key must be a named
// public ECDSA P-256 key; several are accepted so a key can be replaced
// without a gap.
func loadAssertions(path, audience string) (*assertions, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) == 0 {
		return nil, errors.New("the file is not a JSON Web Key Set with at least one key")
	}
	a := &assertions{keys: map[string]*ecdsa.PublicKey{}, audience: audience}
	for _, entry := range set.Keys {
		key, ok := entry.Key.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || entry.KeyID == "" || a.keys[entry.KeyID] != nil {
			return nil, fmt.Errorf("key %q: every key must be a distinct, named public ECDSA P-256 key", entry.KeyID)
		}
		a.keys[entry.KeyID] = key
	}
	return a, nil
}

// admit reports whether r carries exactly one valid assertion for this
// service at now. It then replaces the plain identity headers with the
// assertion's account and roles, so the handlers read only verified values.
func (a *assertions) admit(r *http.Request, now time.Time) bool {
	values := r.Header.Values(assertionHeader)
	if len(values) != 1 || len(values[0]) > maxAssertion {
		return false
	}
	// Only ES256 is parsed, so an unsigned or differently signed token
	// never reaches verification.
	signed, err := jose.ParseSignedCompact(values[0], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return false
	}
	key := a.keys[signed.Signatures[0].Header.KeyID]
	if key == nil {
		return false
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return false
	}
	var claims struct {
		Audience string   `json:"aud"`
		Subject  string   `json:"sub"`
		Roles    []string `json:"roles"`
		IssuedAt int64    `json:"iat"`
		Expires  int64    `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Audience != a.audience {
		return false
	}
	issued, expires := time.Unix(claims.IssuedAt, 0), time.Unix(claims.Expires, 0)
	if claims.IssuedAt == 0 || issued.After(now.Add(assertionLeeway)) || !now.Before(expires.Add(assertionLeeway)) {
		return false
	}
	r.Header.Del("X-Gateway-Subject")
	r.Header.Del("X-Gateway-Roles")
	if claims.Subject != "" {
		r.Header.Set("X-Gateway-Subject", claims.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(claims.Roles, ","))
	}
	return true
}
