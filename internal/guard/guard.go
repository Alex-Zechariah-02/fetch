// The guard of one API process: its settings folder (trusted keys, blocked
// accounts, security log), and the handler that runs every check in the
// gateway's order before the API's own handler is reached.

package guard

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Files of the settings folder every API of a run shares: the trusted keys
// and the blocked accounts are read; each API appends to its own log.
const (
	KeysFile    = "keys.json"
	BlockedFile = "blocked.json"
	maxFile     = 64 << 10
	maxBlocked  = 10000
)

// LogFile is the security log of api in the settings folder.
func LogFile(api string) string { return api + "-security.log" }

// Config is what one API's guard enforces: its own operation table and the
// roles that exist (others in a token are ignored and recorded).
type Config struct {
	Dir, API   string
	Operations []Operation
	Roles      []string
}

// Guard holds one API's keys, table, counters, blocked list and log.
type Guard struct {
	api     string
	keys    map[string]*rsa.PublicKey
	table   *table
	roles   []string
	limiter *limiter
	blocked atomic.Pointer[map[string]bool]
	log     *securityLog
}

// New reads the settings folder and opens the API's security log. Every
// file must be valid: a guard never starts with fewer controls.
func New(cfg Config) (*Guard, error) {
	t, err := newTable(cfg.Operations)
	if err != nil {
		return nil, err
	}
	g := &Guard{api: cfg.API, table: t, roles: slices.Clone(cfg.Roles), limiter: newLimiter(), keys: map[string]*rsa.PublicKey{}}
	var keys []Key
	if err := readJSON(filepath.Join(cfg.Dir, KeysFile), &keys); err != nil || len(keys) == 0 || len(keys) > 64 {
		return nil, fmt.Errorf("%s: one to 64 trusted keys are required (%v)", KeysFile, err)
	}
	for _, key := range keys {
		data, err := readFile(key.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		if g.keys[key.Kid], err = parseKey(data); err != nil {
			return nil, fmt.Errorf("key %s: %w", key.Kid, err)
		}
	}
	var blocked []string
	if err := readJSON(filepath.Join(cfg.Dir, BlockedFile), &blocked); err != nil {
		return nil, fmt.Errorf("%s: %w", BlockedFile, err)
	}
	if err := g.setBlocked(blocked); err != nil {
		return nil, err
	}
	if g.log, err = openLog(filepath.Join(cfg.Dir, LogFile(cfg.API))); err != nil {
		return nil, err
	}
	return g, nil
}

// Close writes every queued record and closes the log.
func (g *Guard) Close() { g.log.close() }

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFile+1))
	if err == nil && len(data) > maxFile {
		err = errors.New(path + " is too large")
	}
	return data, err
}

// readJSON decodes one strict JSON value: no unknown or repeated members.
func readJSON(path string, value any) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	if _, reason := decodeJSON(data); reason != "" {
		return errors.New(reason)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// Wrap returns next behind every check. /internal/ calls between services
// pass straight through: the service key is their control, as in every mode.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			next.ServeHTTP(w, r)
			return
		}
		g.serve(w, r, next)
	})
}

// check is one request on its way through the stages.
type check struct {
	w       http.ResponseWriter
	log     *securityLog
	started time.Time
	record  record
}

// refuse records the refusal at stage and answers it.
func (c *check) refuse(stage string, status int, code, reason string) {
	c.record.Kind, c.record.Stage, c.record.Decision = "request.rejected", stage, "reject"
	c.record.Status, c.record.Error, c.record.Reason = status, code, reason
	c.record.DurationMS = float64(time.Since(c.started)) / float64(time.Millisecond)
	c.log.note(c.record)
	answer(c.w, status, code)
}

func (g *Guard) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	c := &check{w: w, log: g.log, started: time.Now(), record: record{RequestID: requestID(), API: g.api, Method: r.Method, Path: r.URL.Path}}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		c.record.Client = clientOf(peer.Addr().Unmap(), r.Header).String()
	}
	w.Header().Set("X-Request-Id", c.record.RequestID)
	// Identity comes only from the verified token: client copies of the
	// headers the handler reads it from are discarded before anything else.
	credentials := r.Header.Values("Authorization")
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Gateway-") || name == "X-Request-Id" {
			r.Header.Del(name)
		}
	}
	if !strings.HasPrefix(r.RequestURI, "/") || r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		c.refuse("ingress", http.StatusBadRequest, "bad_request", "ingress")
		return
	}
	if !canonical(r) {
		c.refuse("canonical", http.StatusBadRequest, "bad_request", "path_not_canonical")
		return
	}
	rule, allow, status := g.table.match(r.URL.Path, r.Method)
	if rule == nil {
		code := "not_found"
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", allow)
			code = "method_not_allowed"
		}
		c.refuse("route", status, code, code)
		return
	}
	c.record.Operation = rule.ID
	if !rule.Public() && !g.authorise(c, credentials, rule) {
		return
	}
	if !g.limit(c, rule) {
		return
	}
	if refused := readBody(r, rule); refused != nil {
		stage := "body"
		if refused.reason == "schema_mismatch" {
			stage = "validation"
		}
		c.refuse(stage, refused.status, refused.code, refused.reason)
		return
	}
	c.record.Kind, c.record.Stage, c.record.Decision = "request.admitted", "log", "admit"
	if c.log.commit(r.Context(), c.record) != nil {
		c.refuse("log", http.StatusServiceUnavailable, "gateway_unavailable", "log_unavailable")
		return
	}
	r.Header.Set("X-Request-Id", c.record.RequestID)
	if !rule.Public() {
		r.Header.Set("X-Gateway-Subject", c.record.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(c.record.Roles, ","))
	}
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(recorder, r)
	c.record.Kind, c.record.Stage, c.record.Decision, c.record.Status = "request.handled", "handler", "handled", recorder.status
	c.record.DurationMS = float64(time.Since(c.started)) / float64(time.Millisecond)
	c.log.note(c.record)
}

// authorise verifies the token, then refuses a blocked account, then keeps
// only defined roles and refuses when none is permitted on the operation.
func (g *Guard) authorise(c *check, credentials []string, rule *rule) bool {
	token, reason := bearer(credentials)
	var verified identity
	if reason == "" {
		verified, reason = verify(g.keys, token, time.Now())
	}
	if reason != "" {
		c.w.Header().Set("WWW-Authenticate", "Bearer")
		c.refuse("jwt", http.StatusUnauthorized, "unauthenticated", reason)
		return false
	}
	c.record.Subject = verified.subject
	permitted := false
	for _, role := range verified.roles {
		if !slices.Contains(g.roles, role) {
			c.record.IgnoredRoles = append(c.record.IgnoredRoles, role)
			continue
		}
		c.record.Roles = append(c.record.Roles, role)
		permitted = permitted || slices.Contains(rule.Roles, role)
	}
	switch {
	case (*g.blocked.Load())[verified.subject]:
		c.refuse("rbac", http.StatusForbidden, "account_blocked", "account_blocked")
	case !permitted:
		c.refuse("rbac", http.StatusForbidden, "forbidden", "no_permit")
	default:
		return true
	}
	return false
}

// limit counts the request on the operation's counter for the account, or
// for the direct peer address on a public operation.
func (g *Guard) limit(c *check, rule *rule) bool {
	key := c.record.Subject
	if rule.Public() {
		key = c.record.Client
	}
	if key == "" {
		c.refuse("rate", http.StatusBadRequest, "bad_request", "invalid_peer_address")
		return false
	}
	switch g.limiter.admit(counterKey{rule.ID, key}, rule.Count, rule.Window) {
	case exceeded:
		c.refuse("rate", http.StatusTooManyRequests, "rate_limited", "quota_exceeded")
		return false
	case full:
		c.refuse("rate", http.StatusServiceUnavailable, "gateway_unavailable", "rate_capacity")
		return false
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func requestID() string {
	var value [12]byte
	rand.Read(value[:])
	return hex.EncodeToString(value[:])
}
