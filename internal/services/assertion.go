// Verification of the gateway's signed identity assertion. A service given
// the gateway's public keys answers an API request only when it carries an
// assertion those keys verify, made for this service, for the request's own
// method and path, and still fresh, and takes the account and roles from it
// instead of the plain identity headers. Refusals are recorded in the
// service's log, at most one line a second with the count since the last.

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
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
	// assertionIssuer is the gateway's fixed "iss" of every assertion.
	assertionIssuer = "apiward"
	// refusalGap bounds the refusal log under a flood of unasserted
	// requests: one line a second carries the count.
	refusalGap = time.Second
)

// assertions verifies the gateway's assertions for one service.
type assertions struct {
	keys     map[string]*ecdsa.PublicKey // by key ID
	audience string                      // this service's API ID
	log      *slog.Logger

	mu      sync.Mutex // guards the refusal record below
	refused int        // refusals since the last line
	logged  time.Time  // when the last line was written
}

// loadAssertions reads the gateway's public keys from a JSON Web Key Set
// file, as the gateway's jwks command prints it. Every key must be a named
// public ECDSA P-256 key; several are accepted so a key can be replaced
// without a gap.
func loadAssertions(path, audience string, log *slog.Logger) (*assertions, error) {
	data, err := readBoundedFile(path, trusted)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) == 0 {
		return nil, errors.New("the file is not a JSON Web Key Set with at least one key")
	}
	a := &assertions{keys: map[string]*ecdsa.PublicKey{}, audience: audience, log: log}
	for _, entry := range set.Keys {
		key, ok := entry.Key.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || entry.KeyID == "" || a.keys[entry.KeyID] != nil {
			return nil, fmt.Errorf("key %q: every key must be a distinct, named public ECDSA P-256 key", entry.KeyID)
		}
		a.keys[entry.KeyID] = key
	}
	return a, nil
}

// keyIDs lists the accepted key IDs, sorted, for the start line.
func (a *assertions) keyIDs() []string { return slices.Sorted(maps.Keys(a.keys)) }

// check is admit with the refusal recorded: true admits r.
func (a *assertions) check(r *http.Request, now time.Time) bool {
	err := a.admit(r, now)
	if err == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refused++
	if now.Sub(a.logged) < refusalGap {
		return false
	}
	a.log.Warn("gateway assertion refused", "reason", err.Error(), "method", bounded(r.Method, 32), "path", bounded(r.URL.EscapedPath(), 512), "refused", a.refused)
	a.refused, a.logged = 0, now
	return false
}

// admit returns nil when r carries exactly one valid assertion for this
// service and for r's method and path at now, and why not otherwise. It then
// replaces the plain identity headers with the assertion's account and
// roles, so the handlers read only verified values.
func (a *assertions) admit(r *http.Request, now time.Time) error {
	values := r.Header.Values(assertionHeader)
	if len(values) != 1 || len(values[0]) > maxAssertion {
		return errors.New("no single assertion of at most 4096 bytes")
	}
	// Only ES256 is parsed, so an unsigned or differently signed token
	// never reaches verification.
	signed, err := jose.ParseSignedCompact(values[0], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return errors.New("not an ES256 compact assertion")
	}
	key := a.keys[signed.Signatures[0].Header.KeyID]
	if key == nil {
		return errors.New("unknown key ID")
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return errors.New("signature not verified")
	}
	var claims struct {
		Issuer   string   `json:"iss"`
		Audience string   `json:"aud"`
		Subject  string   `json:"sub"`
		Roles    []string `json:"roles"`
		Method   string   `json:"method"`
		Path     string   `json:"path"`
		IssuedAt int64    `json:"iat"`
		Expires  int64    `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer != assertionIssuer || claims.Audience != a.audience {
		return errors.New("another issuer or audience")
	}
	// The gateway signed this one request: on any other method or path the
	// assertion is a copy taken from it.
	if claims.Method != r.Method || claims.Path != r.URL.Path {
		return errors.New("made for another method or path")
	}
	issued, expires := time.Unix(claims.IssuedAt, 0), time.Unix(claims.Expires, 0)
	if claims.IssuedAt == 0 || issued.After(now.Add(assertionLeeway)) || !now.Before(expires.Add(assertionLeeway)) {
		return errors.New("expired or not yet valid")
	}
	r.Header.Del("X-Gateway-Subject")
	r.Header.Del("X-Gateway-Roles")
	if claims.Subject != "" {
		r.Header.Set("X-Gateway-Subject", claims.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(claims.Roles, ","))
	}
	return nil
}
