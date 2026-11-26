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
	"sync/atomic"
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

func TestInFlightCapAtLimitAndRelease(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	table, err := newTable([]Operation{
		{ID: "ping", API: "orders", Method: http.MethodGet, Target: "/ping", Count: maxInFlight + 16, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{api: "orders", log: log, table: table, limiter: newLimiter(), blockedPath: filepath.Join(dir, BlockedFile)}
	empty := map[string]bool{}
	g.blocked.Store(&empty)

	entered := make(chan struct{}, maxInFlight)
	early := make(chan int, maxInFlight)
	release := make(chan struct{})
	var codes [maxInFlight]atomic.Int64
	handler := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	for i := range maxInFlight {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
			codes[idx].Store(int64(rec.Code))
			select {
			case <-release:
			default:
				early <- rec.Code
			}
		}(i)
	}

	deadline := time.After(5 * time.Second)
	for count := 0; count < maxInFlight; count++ {
		select {
		case <-entered:
		case code := <-early:
			close(release)
			wg.Wait()
			t.Fatalf("request %d/%d refused early with status %d, want %d concurrent admitted", count+1, maxInFlight, code, maxInFlight)
		case <-deadline:
			close(release)
			wg.Wait()
			t.Fatalf("only %d/%d concurrent requests entered handler", count, maxInFlight)
		}
	}

	// One past the cap must be refused 503 overloaded without leaking a slot.
	over := httptest.NewRecorder()
	handler.ServeHTTP(over, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if over.Code != http.StatusServiceUnavailable || over.Header().Get("Retry-After") != "1" {
		close(release)
		wg.Wait()
		t.Fatalf("request past cap: status=%d Retry-After=%q, want 503/1", over.Code, over.Header().Get("Retry-After"))
	}
	if got := g.inFlight.Load(); got != maxInFlight {
		close(release)
		wg.Wait()
		t.Fatalf("in-flight at cap = %d, want %d", got, maxInFlight)
	}

	close(release)
	wg.Wait()
	for i := range maxInFlight {
		if c := codes[i].Load(); c != http.StatusOK {
			t.Fatalf("concurrent request %d status = %d, want 200", i, c)
		}
	}
	if got := g.inFlight.Load(); got != 0 {
		t.Fatalf("in-flight after all requests completed = %d, want 0", got)
	}
	after := httptest.NewRecorder()
	handler.ServeHTTP(after, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if after.Code != http.StatusOK || g.inFlight.Load() != 0 {
		t.Fatalf("follow-up request: status=%d inFlight=%d, want 200/0", after.Code, g.inFlight.Load())
	}
}
