// The guard of one API process: its settings folder (trusted keys, blocked
// accounts, security log), and the handler that runs every check in the
// gateway's order before the API's own handler is reached.

package guard

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/trusted"
)

// Files of the settings folder every API of a run shares: the trusted keys
// and the blocked accounts are read; each API appends to its own log.
const (
	KeysFile    = "keys.json"
	BlockedFile = "blocked.json"
	// maxFile bounds each key file read: a key set of a few keys fits with
	// room to spare.
	maxFile = 64 << 10
	// maxBlocked is far above the demo's accounts and bounds the set every
	// request is checked against.
	maxBlocked = 10000
	// maxBlockedBytes fits maxBlocked IDs of maxSubject bytes, each quoted
	// and followed by a comma, inside the brackets.
	maxBlockedBytes = maxBlocked*(maxSubject+3) + 2
	// maxInFlight is the gateway's default data.max_in_flight: past it a
	// request is refused 503 before its token is checked, so excess load
	// costs as little as possible.
	maxInFlight = 1024
)

// LogFile is the security log of api in the settings folder.
// One file per API keeps records apart; the log rotates at maxLogBytes.
func LogFile(api string) string { return api + "-security.log" }

// Config is what one API's guard enforces: its own operation table and the
// roles that exist (others in a token are ignored and recorded).
type Config struct {
	Dir, API   string
	Operations []Operation
	Roles      []string
	// Storage is the security log's archive; zero values take the
	// defaults (withDefaults).
	Storage Storage
	// TrustedProxy is the literal IP address of the proxy whose
	// X-Forwarded-For header is trusted; empty trusts no peer.
	TrustedProxy string
}

// Guard holds one API's keys, table, counters, blocked list and log.
type Guard struct {
	api          string
	trustedProxy netip.Addr
	keys         map[string]*rsa.PublicKey
	table        *table
	roles        []string
	limiter      *limiter
	blocked      atomic.Pointer[map[string]bool]
	// blockedPath is the settings folder's list, rewritten by each
	// replacement under replacing.
	blockedPath string
	replacing   sync.Mutex
	log         *securityLog
	ids         identifiers
	// refusals counts the refusals no control decides; summarising writes
	// them once a minute until stop closes.
	refusals summary
	stop     chan struct{}
	stopped  chan struct{}
	inFlight atomic.Int64
	// overloads and capacity count refusals past maxInFlight and past a
	// full rate table, for the control listener.
	overloads, capacity atomic.Uint64
}

// New reads the settings folder and opens the API's security log. Every
// file must be valid: a guard never starts with fewer controls.
func New(cfg Config) (*Guard, error) {
	t, err := newTable(cfg.Operations)
	if err != nil {
		return nil, err
	}
	var trustedProxy netip.Addr
	if cfg.TrustedProxy != "" {
		addr, err := netip.ParseAddr(cfg.TrustedProxy)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("trusted proxy %q: literal IP address required", cfg.TrustedProxy)
		}
		trustedProxy = addr.Unmap()
	}
	g := &Guard{api: cfg.API, trustedProxy: trustedProxy, table: t, roles: slices.Clone(cfg.Roles), limiter: newLimiter(), keys: map[string]*rsa.PublicKey{}, blockedPath: filepath.Join(cfg.Dir, BlockedFile)}
	g.ids.prefix = newIdentifiers().prefix
	var keys []Key
	// One key at least, so tokens can verify; 64 bounds the key files read at startup.
	if err := readJSON(filepath.Join(cfg.Dir, KeysFile), &keys); err != nil || len(keys) == 0 || len(keys) > 64 {
		return nil, fmt.Errorf("%s: one to 64 trusted keys are required (%v)", KeysFile, err)
	}
	for _, key := range keys {
		data, err := readFile(key.PublicKeyFile, maxFile)
		if err != nil {
			return nil, err
		}
		if g.keys[key.Kid], err = parseKey(data); err != nil {
			return nil, fmt.Errorf("key %s: %w", key.Kid, err)
		}
	}
	if err := g.loadBlocked(g.blockedPath); err != nil {
		return nil, fmt.Errorf("%s: %w", BlockedFile, err)
	}
	if g.log, err = openLog(filepath.Join(cfg.Dir, LogFile(cfg.API)), cfg.Storage.withDefaults(cfg.Dir)); err != nil {
		return nil, err
	}
	g.stop, g.stopped = make(chan struct{}), make(chan struct{})
	go g.summarise(g.stop, g.stopped)
	return g, nil
}

// Close writes the last refusal summary and every queued record, then
// closes the log.
func (g *Guard) Close() {
	close(g.stop)
	<-g.stopped
	g.log.close()
}

func readFile(path string, limit int64) ([]byte, error) {
	return trusted.ReadBounded(path, limit, trusted.Trusted)
}

// readJSON decodes one strict JSON value: no unknown or repeated members.
func readJSON(path string, value any) error {
	data, err := readFile(path, maxFile)
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
// pass straight through: the caller's key is their control, as in every mode.
// Identity headers are discarded on every path first: only the guard sets
// them, and an internal call carries none.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			if strings.HasPrefix(name, "X-Gateway-") {
				r.Header.Del(name)
			}
		}
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
	client  netip.Addr // invalid when the peer address did not parse
	record  record
}

// refuse records the refusal at stage and answers it.
func (c *check) refuse(stage string, status int, code, reason string) {
	c.record.Kind, c.record.Stage, c.record.Decision = "request.rejected", stage, "reject"
	c.record.Status, c.record.Error, c.record.Reason = status, code, reason
	c.record.DurationMS = float64(time.Since(c.started)) / float64(time.Millisecond)
	c.log.note(&c.record)
	answer(c.w, status, code)
}

// summarised answers a refusal no control decides and counts it in the
// minute's summary instead of a record of its own.
func (g *Guard) summarised(c *check, status int, code, reason string) {
	g.refusals.count(reason, c.record.Client)
	answer(c.w, status, code)
}

func (g *Guard) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	c := &check{w: w, log: g.log, started: time.Now(), record: record{RequestID: g.ids.issue(), API: g.api, Method: r.Method, Path: r.URL.Path}}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		c.client = clientOf(peer.Addr().Unmap(), r.Header, g.trustedProxy)
		c.record.Client = c.client.String()
	}
	w.Header().Set("X-Request-Id", c.record.RequestID)
	// The request ID is the guard's: a client's copy is discarded (Wrap
	// already discarded the identity headers).
	r.Header.Del("X-Request-Id")
	credentials := r.Header.Values("Authorization")
	// A proxy and the API must read the same target: origin- or absolute-form, no CONNECT or Upgrade.
	if (!strings.HasPrefix(r.RequestURI, "/") && !absoluteForm(r)) || r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		g.summarised(c, http.StatusBadRequest, "bad_request", "ingress")
		return
	}
	// Read any body within the global ceiling before taking an in-flight
	// slot, so a slow upload holds only its own connection.
	body, refused := bufferBody(r)
	if refused != nil {
		g.summarised(c, refused.status, refused.code, refused.reason)
		return
	}
	if g.inFlight.Add(1) > maxInFlight {
		g.inFlight.Add(-1)
		g.overloads.Add(1)
		w.Header().Set("Retry-After", "1")
		g.summarised(c, http.StatusServiceUnavailable, "overloaded", "overloaded")
		return
	}
	defer g.inFlight.Add(-1)
	if !canonical(r) {
		g.summarised(c, http.StatusBadRequest, "bad_request", "path_not_canonical")
		return
	}
	rule, allow, status := g.table.match(r.URL.Path, r.Method)
	if rule == nil {
		code := "not_found"
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", allow)
			code = "method_not_allowed"
		}
		g.summarised(c, status, code, code)
		return
	}
	c.record.Operation = rule.ID
	if !rule.Public() && !g.authorise(c, credentials, rule) {
		return
	}
	if !g.limit(c, rule) {
		return
	}
	if refused := readBody(r, body, rule); refused != nil {
		stage := "body"
		if refused.reason == "schema_mismatch" {
			stage = "validation"
		}
		c.refuse(stage, refused.status, refused.code, refused.reason)
		return
	}
	c.record.Kind, c.record.Stage, c.record.Decision = "request.admitted", "log", "admit"
	// The request waits for its record to be synced, so it never runs
	// unlogged. A timed-out admission was withdrawn, or is written and
	// superseded by this refusal of the same request.
	if err := c.log.commit(r.Context(), &c.record); err != nil {
		reason := "log_unavailable"
		if errors.Is(err, errLogTimedOut) {
			reason = "log_timeout"
		}
		c.refuse("log", http.StatusServiceUnavailable, "gateway_unavailable", reason)
		return
	}
	r.Header.Set("X-Request-Id", c.record.RequestID)
	if !rule.Public() {
		r.Header.Set("X-Gateway-Subject", c.record.Subject)
		r.Header.Set("X-Gateway-Roles", strings.Join(c.record.Roles, ","))
	}
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	// A handler that panics still gets its outcome: decision failed, 500
	// unless a status was already sent. The panic goes on to net/http.
	handled := false
	defer func() {
		if !handled {
			status := http.StatusInternalServerError
			if recorder.wrote {
				status = recorder.status
			}
			c.outcome("failed", status)
		}
	}()
	next.ServeHTTP(recorder, r)
	handled = true
	c.outcome("handled", recorder.status)
}
