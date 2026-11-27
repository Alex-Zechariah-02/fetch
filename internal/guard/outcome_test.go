// An admitted request always gets one truthful outcome: a panicking handler
// is recorded as failed, and a timed-out admission is withdrawn.

package guard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A handler that panics leaves an outcome record (decision failed, 500)
// instead of an admission without one.
func TestPanicRecordsOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orders-security.log")
	log, err := openLog(path, Storage{})
	if err != nil {
		t.Fatal(err)
	}
	table, err := newTable([]Operation{{ID: "ping", API: "orders", Method: http.MethodGet, Target: "/ping", Count: 100, Window: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{api: "orders", log: log, table: table, limiter: newLimiter()}
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("handler failure") })
	func() {
		defer func() { _ = recover() }()
		g.Wrap(panicking).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", nil))
	}()
	log.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"kind":"request.handled"`) || !strings.Contains(string(data), `"decision":"failed","status":500`) {
		t.Fatalf("no failed outcome recorded:\n%s", data)
	}
}

// An admission whose wait ended before the writer took it is withdrawn and
// never written.
func TestCommitWithdrawsOnTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orders-security.log")
	l := &securityLog{path: path, limit: maxLogBytes, queue: make(chan entry, queueSize), done: make(chan struct{})}
	if err := l.open(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.commit(ctx, &record{Kind: "request.admitted", RequestID: "late"}); !errors.Is(err, errLogTimedOut) {
		t.Fatalf("commit: %v", err)
	}
	go l.run()
	l.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "late") {
		t.Fatalf("withdrawn admission written:\n%s", data)
	}
}

// Informational 1xx headers do not overwrite the final HTTP status recorded.
func TestStatusRecorderIgnoresInformationalStatus(t *testing.T) {
	t.Parallel()
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	rec.WriteHeader(http.StatusEarlyHints)
	rec.WriteHeader(http.StatusCreated)
	if rec.status != http.StatusCreated {
		t.Fatalf("recorded status %d, want %d", rec.status, http.StatusCreated)
	}
}
