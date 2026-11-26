// The control listener of a service: its receipts, its state with a digest,
// and a reset to the seed, each recorded in the service's log; with
// built-in protection also the blocked list and the guard's counters.

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

// state encodes the data under the read lock (the snapshot is the live data,
// which only a writer changes) and hashes it after.
func (s *Service) state() (State, error) {
	s.mu.RLock()
	data, err := json.Marshal(s.data.snapshot())
	s.mu.RUnlock()
	if err != nil {
		return State{}, err
	}
	sum := sha256.Sum256(data)
	return State{s.name, "fetch-1", s.instance, hex.EncodeToString(sum[:]), data}, nil
}

// answerState writes the state, or 500 and a log line when it cannot be encoded.
func (s *Service) answerState(w http.ResponseWriter) {
	state, err := s.state()
	if err != nil {
		s.log.Error("state not encoded", "error", err)
		writeJSON(w, failure(500, "internal_error", "The state could not be encoded.", ""))
		return
	}
	writeJSON(w, result{status: 200, body: state})
}

// answerReceipts writes the receipts, or the counts in measurement mode,
// encoded after the records lock is released.
func (s *Service) answerReceipts(w http.ResponseWriter) {
	s.records.Lock()
	if s.counts != nil {
		encoded, err := json.Marshal(s.counts)
		s.records.Unlock()
		if err != nil {
			writeJSON(w, failure(500, "internal_error", "The counts could not be encoded.", ""))
			return
		}
		writeJSON(w, result{status: 200, encoded: encoded})
		return
	}
	s.records.Unlock()
	receipts, dropped := s.kept()
	writeJSON(w, result{status: 200, body: map[string]any{"service": s.name, "instance": s.instance, "receipts": receipts, "dropped": dropped}})
}

func (s *Service) Control(secret []byte) http.Handler {
	secret = slices.Clone(secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Service", s.name)
		values := r.Header.Values("Authorization")
		if len(secret) < minSecret || len(secret) > maxSecret || len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), append([]byte("Bearer "), secret...)) != 1 {
			writeJSON(w, failure(401, "unauthenticated", "Control authentication is required.", ""))
			return
		}
		switch {
		case r.Method == "PUT" && r.URL.Path == "/blocked" && s.guard != nil:
			s.guard.Blocked(w, r)
		case r.Method == "GET" && r.URL.Path == "/guard" && s.guard != nil:
			s.guard.Status(w, r)
		case r.Method == "GET" && r.URL.Path == "/receipts":
			s.answerReceipts(w)
		case r.Method == "GET" && r.URL.Path == "/state":
			s.answerState(w)
		case r.Method == "POST" && r.URL.Path == "/reset":
			// The receipts go with the data, so the service's log keeps the
			// record of the reset.
			s.mu.Lock()
			s.data.reset()
			s.mu.Unlock()
			answers := s.clear()
			s.log.Warn("reset to the seed; data and receipts cleared", "answers", answers, "from", r.RemoteAddr)
			s.answerState(w)
		default:
			writeJSON(w, notFound())
		}
	})
}
