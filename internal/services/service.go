// A Fetch service: its configuration, HTTP handler and protected control
// listener, with built-in protection in front when configured.

package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
)

type Config struct {
	Name string
	// Keys are the internal call keys by service name: this service's own
	// when it calls another, and each caller's it accepts (see needs).
	Keys                map[string][]byte
	InventoryURL        string
	OrdersURL           string
	SigningSettingsFile string
	// Protection is the settings folder of built-in protection; empty runs
	// the service behind a gateway, trusting its identity headers.
	Protection string
	// GatewayKey is the file of the gateway's public keys; set, every API
	// request must carry the gateway's signed identity assertion.
	GatewayKey string
	// Measure keeps receipts as counts with no cap and seeds the load
	// accounts, so a long load run measures the gateway, not this record.
	Measure bool
	// Log records refused assertions, resets and Accounts' signing failures;
	// nil writes them to standard error.
	Log *slog.Logger
}

type result struct {
	status int
	body   any
	// encoded, when set, is the answer already encoded (a stored checkout
	// answer), written as it is.
	encoded []byte
	effect  string
	// retryAfter, when above zero, is the seconds a 503 asks the client to wait.
	retryAfter int
}
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func failure(status int, code, message, field string) result {
	return result{status: status, body: apiError{code, message, field}}
}
func notFound() result { return failure(404, "not_found", "That resource was not found.", "") }

// encode returns the answer as JSON.
func (res result) encode() ([]byte, error) {
	if res.encoded != nil {
		return res.encoded, nil
	}
	return json.Marshal(res.body)
}

type resource interface {
	handle(*http.Request, []byte) result
	reset()
	snapshot() any
}

// counts replace the receipt list in measurement mode: answers per status.
type counts struct {
	Mode     string      `json:"mode"`
	Total    int         `json:"total"`
	ByStatus map[int]int `json:"by_status"`
}

func newCounts() *counts { return &counts{Mode: "count", ByStatus: map[int]int{}} }

type Service struct {
	// mu guards data, which lives in memory only: GET and HEAD read it under
	// the read lock, together; every other request changes it alone.
	mu             sync.RWMutex
	name, instance string
	callers        map[string][]byte // keys of the services that may call this one, by name
	data           resource
	// records guards the receipts and counts, which every request writes.
	records sync.Mutex
	recent  ring         // receipts of API requests
	calls   ring         // receipts of internal calls, kept apart so a report's page reads never push out API receipts
	seq     int          // receipts numbered since the last reset
	counts  *counts      // nil outside measurement mode
	guard   *guard.Guard // nil without built-in protection
	gateway *assertions  // nil when the gateway's assertion is not required
	log     *slog.Logger
	// bodyCap is the largest request body any of this service's operations
	// takes; a read never goes past it.
	bodyCap int64
}

func New(cfg Config) (*Service, error) {
	if err := checkKeys(cfg.Name, cfg.Keys); err != nil {
		return nil, err
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Service{name: cfg.Name, callers: map[string][]byte{}, instance: randomID(), log: log.With("service", cfg.Name), bodyCap: bodyLimit(cfg.Name)}
	for caller, key := range cfg.Keys {
		if caller != cfg.Name {
			s.callers[caller] = slices.Clone(key)
		}
	}
	switch cfg.Name {
	case "inventory":
		s.data = &inventory{measure: cfg.Measure}
	case "orders":
		client, err := newServiceClient(cfg.InventoryURL, cfg.Keys[cfg.Name])
		if err != nil {
			return nil, err
		}
		s.data = &orders{inventory: client, measure: cfg.Measure, outside: s.outside, locked: s.locked, stop: make(chan struct{})}
	case "support":
		client, err := newServiceClient(cfg.OrdersURL, cfg.Keys[cfg.Name])
		if err != nil {
			return nil, err
		}
		s.data = &support{orders: client, outside: s.outside}
	case "reports":
		client, err := newServiceClient(cfg.OrdersURL, cfg.Keys[cfg.Name])
		if err != nil {
			return nil, err
		}
		s.data = &reports{orders: client, outside: s.outside, log: s.log}
	case "accounts":
		accounts, err := newAccounts(cfg.SigningSettingsFile, cfg.Measure, s.log, s.outside)
		if err != nil {
			return nil, err
		}
		s.data = accounts
	default:
		return nil, fmt.Errorf("unknown service %q", cfg.Name)
	}
	s.data.reset()
	if cfg.Measure {
		s.counts = newCounts()
	}
	if cfg.GatewayKey != "" {
		if cfg.Protection != "" {
			return nil, errors.New("built-in protection runs without a gateway: do not give a gateway key with it")
		}
		gateway, err := loadAssertions(cfg.GatewayKey, cfg.Name, s.log)
		if err != nil {
			return nil, fmt.Errorf("the gateway key: %w", err)
		}
		s.gateway = gateway
	}
	if cfg.Protection != "" {
		g, err := guard.New(guard.Config{Dir: cfg.Protection, API: cfg.Name, Operations: operationsOf(cfg.Name), Roles: Roles})
		if err != nil {
			return nil, fmt.Errorf("built-in protection: %w", err)
		}
		s.guard = g
	}
	return s, nil
}

// api is the handler of the API listener: the service, behind its guard when
// built-in protection is on. The guard's checks run before ServeHTTP takes
// the service lock, so verification and log syncs are never serialised.
func (s *Service) api() http.Handler {
	if s.guard == nil {
		return s
	}
	return s.guard.Wrap(s)
}

// sharedLock marks a request context whose handler holds the read lock.
type sharedLock struct{}

// outside runs call without the service lock, which the caller holds (read
// or write, as ctx says) before and after. A call to another service waits on
// the network, and a password hash on the CPU; under the lock that wait would
// hold up every other request to this service. What the caller read before
// may have changed when outside returns: it checks again.
func (s *Service) outside(ctx context.Context, call func()) {
	if shared, _ := ctx.Value(sharedLock{}).(bool); shared {
		s.mu.RUnlock()
		defer s.mu.RLock()
	} else {
		s.mu.Unlock()
		defer s.mu.Lock()
	}
	call()
}

// locked runs call holding the write lock, for work that is no request's.
func (s *Service) locked(call func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call()
}

func randomID() string {
	var value [16]byte
	rand.Read(value[:])
	return hex.EncodeToString(value[:])
}
