// Request bodies are buffered before an in-flight slot is taken, so a slow
// upload holds only its own connection and never consumes a slot other clients
// need.

package guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type slowReader struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
	data    string
	offset  int
}

func (s *slowReader) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.started) })
	<-s.release
	if s.offset >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.offset:])
	s.offset += n
	return n, nil
}

func TestSlowBodyDoesNotHoldInFlightSlot(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	table, err := newTable([]Operation{
		{ID: "note", API: "orders", Method: http.MethodPost, Target: "/orders/note", Count: 60, Window: time.Minute, MaxBytes: 1024, Schema: map[string]any{"type": "object"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{api: "orders", log: log, table: table, limiter: newLimiter(), blockedPath: filepath.Join(dir, BlockedFile)}
	empty := map[string]bool{}
	g.blocked.Store(&empty)

	handler := g.Wrap(http.HandlerFunc(ok))
	body := &slowReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
		data:    `{"x":"ok"}`,
	}
	req := httptest.NewRequest(http.MethodPost, "/orders/note", body)
	req.ContentLength = int64(len(body.data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(rec, req)
	}()

	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		close(body.release)
		t.Fatal("guard did not start reading the body")
	}
	if got := g.inFlight.Load(); got != 0 {
		close(body.release)
		<-done
		t.Fatalf("slow body upload held %d in-flight slot(s) while reading, want 0", got)
	}
	close(body.release)
	<-done
	if rec.Code != http.StatusOK {
		t.Fatalf("completed request answered %d: %s", rec.Code, rec.Body.String())
	}
	if got := g.inFlight.Load(); got != 0 {
		t.Fatalf("in-flight count after completion = %d, want 0", got)
	}

	// A body above the global ceiling is refused 413 before taking a slot.
	g.inFlight.Store(maxInFlight)
	big := httptest.NewRequest(http.MethodPost, "/orders/note", strings.NewReader(strings.Repeat("a", maxBody+1)))
	big.Header.Set("Content-Type", "application/json")
	bigRec := httptest.NewRecorder()
	handler.ServeHTTP(bigRec, big)
	if bigRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body above global ceiling under full slots answered %d, want 413", bigRec.Code)
	}
	if got := g.inFlight.Load(); got != maxInFlight {
		t.Fatalf("in-flight count after oversized body = %d, want %d", got, maxInFlight)
	}
}
