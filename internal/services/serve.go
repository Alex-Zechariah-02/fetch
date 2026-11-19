// One request to a service: the caller's key or gateway assertion, the body
// read only for a method that takes one, the operation table, the handler
// under the service lock, the answer encoded after it, the receipt, and the
// write.

package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Service", s.name)
	internal := strings.HasPrefix(r.URL.Path, "/internal/")
	caller, known := s.caller(r)
	keyRequired := internal && !known
	// A known caller still reaches only the internal endpoints it uses.
	refused := internal && known && !permitted(caller, r.Method, r.URL.Path)
	// Calls between services carry the caller's key, not an assertion. The
	// signature is checked before the service lock is taken.
	// Signing in needs no assertion: the demo commands sign in at Accounts
	// directly, and the account comes from the password, not the gateway.
	login := s.name == "accounts" && r.URL.Path == "/accounts/login"
	unasserted := s.gateway != nil && !internal && !login && !s.gateway.check(r, time.Now())
	// Only a method that takes a body has it read; any other is refused on
	// its declared body without reading it.
	takesBody := r.Method == "POST" || r.Method == "PATCH" || r.Method == "PUT"
	declared := r.ContentLength != 0 || len(r.TransferEncoding) > 0
	var body []byte
	var err error
	if keyRequired || refused || unasserted || !takesBody {
		if declared {
			w.Header().Set("Connection", "close")
		}
	} else {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, s.bodyCap))
	}
	var tooLarge *http.MaxBytesError
	var res result
	switch {
	case keyRequired:
		res = failure(401, "service_key_required", "A service key is required.", "")
	case refused:
		res = failure(403, "service_not_permitted", "This service may not make that call.", "")
	case unasserted:
		res = failure(401, "gateway_assertion_required", "A valid gateway assertion is required.", "")
	case errors.As(err, &tooLarge):
		res = failure(413, "payload_too_large", "The request body is too large.", "")
	case err != nil:
		res = failure(400, "invalid_request", "The request body could not be read.", "")
	case !takesBody && declared:
		res = failure(400, "invalid_request", "This operation accepts no request body.", "")
	case r.Method != "GET" && r.Method != "HEAD" && r.URL.RawQuery != "":
		res = invalidQuery()
	case !internal && !routed(s.name, r.Method, r.URL.Path):
		res = notFound()
	default:
		res = s.handle(r, body)
	}
	// Encoded after the lock is released: every answer body holds copies of
	// the service's values (structs, and slices no later change writes
	// within their length), never the live maps or lists themselves.
	encoded, err := res.encode()
	if err != nil {
		s.log.Error("answer not encoded", "path", r.URL.Path, "error", err)
		res = failure(500, "internal_error", "The service could not form its answer.", "")
		encoded, _ = res.encode()
	}
	s.note(r, res, len(body), internal)
	write(w, res, encoded)
}

// handle runs the resource's handler under the service lock: shared for a
// read, exclusive for a change.
func (s *Service) handle(r *http.Request, body []byte) result {
	shared := r.Method == "GET" || r.Method == "HEAD"
	if shared {
		s.mu.RLock()
		defer s.mu.RUnlock()
	} else {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	return s.data.handle(r.WithContext(context.WithValue(r.Context(), sharedLock{}, shared)), body)
}

// note keeps the request's receipt, or its count in measurement mode.
func (s *Service) note(r *http.Request, res result, bodyBytes int, internal bool) {
	s.records.Lock()
	defer s.records.Unlock()
	if s.counts != nil {
		s.counts.Total++
		s.counts.ByStatus[res.status]++
		return
	}
	// Each value is cut to these lengths, so no request can grow one receipt:
	// the gateway sends at most the five roles (42 bytes) and a generation ID
	// that names its overrides.
	s.keep(Receipt{Time: time.Now().UTC(), RequestID: bounded(r.Header.Get("X-Request-Id"), 128), Generation: bounded(r.Header.Get("X-Gateway-Generation"), 256), Method: r.Method, Target: bounded(r.URL.EscapedPath(), 512), Status: res.status, Effect: res.effect, Authorization: r.Header.Get("Authorization") != "", Subject: bounded(r.Header.Get("X-Gateway-Subject"), 128), Roles: bounded(r.Header.Get("X-Gateway-Roles"), 64), BodyBytes: bodyBytes, Internal: internal})
}

// bounded cuts a header copied into a receipt, so no caller grows the receipts.
func bounded(value string, n int) string {
	if len(value) > n {
		return value[:n]
	}
	return value
}

// writeJSON sends res, answering 500 when it cannot be encoded.
func writeJSON(w http.ResponseWriter, res result) {
	encoded, err := res.encode()
	if err != nil {
		res = failure(500, "internal_error", "The service could not form its answer.", "")
		encoded, _ = res.encode()
	}
	write(w, res, encoded)
}

// write sends an answer that is already encoded as JSON, then a newline as
// a second write, so a large answer is never copied to append it.
func write(w http.ResponseWriter, res result, encoded []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if res.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(res.retryAfter))
	}
	w.WriteHeader(res.status)
	w.Write(encoded)
	w.Write(newline)
}

var newline = []byte{'\n'}
