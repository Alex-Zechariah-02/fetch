// The control listener of a service: its receipts, its state with a digest,
// and a reset to the seed, each recorded in the service's log; with
// built-in protection also the blocked list.

package services

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
)

type State struct {
	Service  string          `json:"service"`
	Version  string          `json:"version"`
	Instance string          `json:"instance"`
	SHA256   string          `json:"sha256"`
	Data     json.RawMessage `json:"data"`
}

func (s *Service) state() State {
	data, _ := json.Marshal(s.data.snapshot())
	sum := sha256.Sum256(data)
	return State{s.name, "fetch-1", s.instance, hex.EncodeToString(sum[:]), data}
}

func (s *Service) Control(secret []byte) http.Handler {
	secret = slices.Clone(secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Service", s.name)
		values := r.Header.Values("Authorization")
		if len(secret) < 32 || len(secret) > 4096 || len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), append([]byte("Bearer "), secret...)) != 1 {
			writeJSON(w, failure(401, "unauthenticated", "Control authentication is required.", ""))
			return
		}
		if r.Method == "PUT" && r.URL.Path == "/blocked" && s.guard != nil {
			s.guard.Blocked(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/receipts":
			if s.counts != nil {
				writeJSON(w, result{status: 200, body: s.counts})
				return
			}
			writeJSON(w, result{status: 200, body: map[string]any{"service": s.name, "instance": s.instance, "receipts": s.kept(), "dropped": s.dropped}})
		case r.Method == "GET" && r.URL.Path == "/state":
			writeJSON(w, result{status: 200, body: s.state()})
		case r.Method == "POST" && r.URL.Path == "/reset":
			// The receipts go with the data, so the service's log keeps the
			// record of the reset.
			answers := len(s.receipts) + s.dropped
			if s.counts != nil {
				answers = s.counts.Total
			}
			s.log.Warn("reset to the seed; data and receipts cleared", "answers", answers, "from", r.RemoteAddr)
			s.data.reset()
			s.receipts, s.dropped = nil, 0
			if s.counts != nil {
				s.counts = newCounts()
			}
			writeJSON(w, result{status: 200, body: s.state()})
		default:
			writeJSON(w, notFound())
		}
	})
}
