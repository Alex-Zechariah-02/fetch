// The outcome of an admitted request: the status its handler sent, the
// record of how it ended, and request identifiers.

package guard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// outcome records how the handler ended an admitted request.
func (c *check) outcome(decision string, status int) {
	c.record.Kind, c.record.Stage, c.record.Decision, c.record.Status = "request.handled", "handler", decision, status
	c.record.DurationMS = float64(time.Since(c.started)) / float64(time.Millisecond)
	c.log.note(&c.record)
}

// statusRecorder notes the status the handler sent and whether it sent one.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(status int) {
	// Informational (1xx) responses precede the final status.
	if !s.wrote && status >= http.StatusOK {
		s.status, s.wrote = status, true
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(data []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(data)
}

// Unwrap lets http.NewResponseController reach the server's writer, so a
// handler behind the guard can still flush, set deadlines or hijack.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// identifiers issues request IDs: a random prefix per process, so two runs
// never share one, and a counter, so issuing one costs no random read.
type identifiers struct {
	prefix string
	next   atomic.Uint64
}

func newIdentifiers() *identifiers {
	// 8 random bytes keep processes apart in the security log.
	var value [8]byte
	rand.Read(value[:])
	return &identifiers{prefix: hex.EncodeToString(value[:])}
}

// issue returns the next request ID: the prefix and a 16-digit counter.
func (i *identifiers) issue() string {
	return fmt.Sprintf("%s%016x", i.prefix, i.next.Add(1))
}
