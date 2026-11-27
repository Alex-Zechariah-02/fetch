// Verification of the gateway's signed identity assertion. A service given
// the gateway's public keys answers an API request only when it carries an
// assertion those keys verify, made for this service, for the request's own
// method and path, and still fresh, and takes the account and roles from it
// instead of the plain identity headers. Refusals are recorded in the
// service's log, at most one line a second with the count since the last.

package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/trusted"
	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

const (
	assertionHeader = "X-Gateway-Assertion"
	// maxAssertion bounds the header before any parsing.
	maxAssertion = 4096
	// assertionLeeway is the clock difference tolerated between the gateway
	// and this service, on both "iat" and "exp".
	assertionLeeway = 5 * time.Second
	// maxAssertionLife bounds exp - iat: the gateway signs 30 s.
	maxAssertionLife = 60 * time.Second
	// assertionIssuer is the gateway's fixed "iss" of every assertion.
	assertionIssuer = "apiward"
	// refusalGap bounds the refusal log under a flood of unasserted
	// requests: one line a second carries the count.
	refusalGap = time.Second
)

type assertionSet struct {
	keys  map[string]crypto.PublicKey // by key ID: ed25519.PublicKey or *ecdsa.PublicKey (P-256)
	stamp stamp
}

// assertions verifies the gateway's assertions for one service.
type assertions struct {
	path     string
	audience string // this service's API ID
	log      *slog.Logger

	held     atomic.Pointer[assertionSet]
	checked  atomic.Int64 // Unix ns of the last stat check
	reloadMu sync.Mutex

	mu      sync.Mutex // guards the refusal record below
	refused int        // refusals since the last line
	logged  time.Time  // when the last line was written
}

// loadAssertions reads the gateway's public keys from a JSON Web Key Set
// file, as the gateway's jwks command prints it. Every key must be a named
// public Ed25519 or ECDSA P-256 key; several are accepted so a key can be
// replaced, also by one of the other type, without a gap.
func loadAssertions(path, audience string, log *slog.Logger) (*assertions, error) {
	st, err := stampOf(path)
	if err != nil {
		return nil, err
	}
	keys, err := loadAssertionKeys(path)
	if err != nil {
		return nil, err
	}
	a := &assertions{path: path, audience: audience, log: log}
	a.held.Store(&assertionSet{keys: keys, stamp: st})
	a.checked.Store(time.Now().UnixNano())
	return a, nil
}

func loadAssertionKeys(path string) (map[string]crypto.PublicKey, error) {
	data, err := readBoundedFile(path, trusted.Trusted)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) == 0 {
		return nil, errors.New("the file is not a JSON Web Key Set with at least one key")
	}
	keys := map[string]crypto.PublicKey{}
	for _, entry := range set.Keys {
		if algorithmOf(entry.Key) == "" || entry.KeyID == "" || keys[entry.KeyID] != nil {
			return nil, fmt.Errorf("key %q: every key must be a distinct, named public Ed25519 or ECDSA P-256 key", entry.KeyID)
		}
		keys[entry.KeyID] = entry.Key
	}
	return keys, nil
}

// currentKeys returns the active gateway public keys, reloading the file when
// its size or modification time changed (checked at most once a second). A
// failed reload keeps the previous keys and logs the error.
func (a *assertions) currentKeys() map[string]crypto.PublicKey {
	held := a.held.Load()
	ns := time.Now().UnixNano()
	if ns-a.checked.Load() < int64(time.Second) {
		return held.keys
	}
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	held = a.held.Load()
	if ns-a.checked.Load() < int64(time.Second) {
		return held.keys
	}
	a.checked.Store(ns)
	st, err := stampOf(a.path)
	if err != nil {
		a.log.Error("reloading gateway assertion keys", "path", a.path, "error", err)
		return held.keys
	}
	if st == held.stamp {
		return held.keys
	}
	keys, err := loadAssertionKeys(a.path)
	if err != nil {
		a.log.Error("reloading gateway assertion keys", "path", a.path, "error", err)
		return held.keys
	}
	a.held.Store(&assertionSet{keys: keys, stamp: st})
	return keys
}

// algorithmOf is the one JWS algorithm a key verifies: EdDSA for Ed25519,
// ES256 for P-256, "" for any other key. The key fixes the algorithm, never
// the token (RFC 8725 section 3.1).
func algorithmOf(key crypto.PublicKey) string {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return "EdDSA"
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return "ES256"
		}
	}
	return ""
}

// verify checks a compact EdDSA or ES256 assertion (RFC 7515 section 7.1)
// and returns its payload. Its header must name a known "kid", the
// algorithm that key fixes, and no "crit" extension (RFC 7515 section
// 4.1.11), so an unsigned or differently signed token never reaches
// verification. The 64-byte signature covers the encoded header, a dot and
// the encoded payload: Ed25519 signs them itself (RFC 8037 section 3.1);
// ES256 signs their SHA-256, as two P-256 integers at fixed width (RFC 7518
// section 3.4).
func (a *assertions) verify(token string) ([]byte, error) {
	header, rest, found := strings.Cut(token, ".")
	body, seal, sealed := strings.Cut(rest, ".")
	if !found || !sealed || strings.Contains(seal, ".") {
		return nil, errors.New("not a compact assertion")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, errors.New("not a compact assertion")
	}
	var fields map[string]any
	if josejson.Unmarshal(decoded, &fields) != nil || fields == nil {
		return nil, errors.New("not a compact assertion")
	}
	if _, hasCrit := fields["crit"]; hasCrit {
		return nil, errors.New("not a compact assertion")
	}
	kid, _ := fields["kid"].(string)
	key := a.currentKeys()[kid]
	if key == nil {
		return nil, errors.New("unknown key ID")
	}
	if fields["alg"] != algorithmOf(key) {
		return nil, errors.New("the algorithm is not the one the key fixes")
	}
	signature, err := base64.RawURLEncoding.DecodeString(seal)
	if err != nil || len(signature) != 64 || !verified(key, []byte(token[:len(header)+1+len(body)]), signature) {
		return nil, errors.New("signature not verified")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("not a compact assertion")
	}
	return payload, nil
}

// verified checks a 64-byte signature of input with key.
func verified(key crypto.PublicKey, input, signature []byte) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, input, signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(input)
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(k, digest[:], r, s)
	default:
		return false
	}
}

// keyIDs lists the accepted key IDs, sorted, for the start line.
func (a *assertions) keyIDs() []string { return slices.Sorted(maps.Keys(a.held.Load().keys)) }

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
	const (
		maxLoggedMethod = 32
		maxLoggedPath   = 512
	)
	a.log.Warn("gateway assertion refused", "reason", err.Error(), "method", bounded(r.Method, maxLoggedMethod), "path", bounded(r.URL.EscapedPath(), maxLoggedPath), "refused", a.refused)
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
	payload, err := a.verify(values[0])
	if err != nil {
		return err
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
	if josejson.Unmarshal(payload, &claims) != nil || claims.Issuer != assertionIssuer || claims.Audience != a.audience {
		return errors.New("another issuer or audience")
	}
	// The gateway signed this one request: on any other method or path the
	// assertion is a copy taken from it.
	if claims.Method != r.Method || claims.Path != r.URL.Path {
		return errors.New("made for another method or path")
	}
	issued, expires := time.Unix(claims.IssuedAt, 0), time.Unix(claims.Expires, 0)
	// The gateway's assertions live 30 s; a longer one is refused, so a key
	// misused to sign long-lived assertions gains no replay window.
	if claims.IssuedAt == 0 || issued.After(now.Add(assertionLeeway)) || !now.Before(expires.Add(assertionLeeway)) || expires.Sub(issued) > maxAssertionLife {
		return errors.New("expired, not yet valid or living too long")
	}
	r.Header.Del("X-Gateway-Subject")
	r.Header.Del("X-Gateway-Roles")
	if claims.Subject != "" {
		r.Header.Set("X-Gateway-Subject", claims.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(claims.Roles, ","))
	}
	return nil
}
