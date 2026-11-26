// The security log under pressure: the queue's last quarter kept for
// admissions, losses reported at close, rotation at exactly the size bound,
// and request records timed in milliseconds.

package guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Refusals fill at most three quarters of the queue; admissions may use the
// rest, and past a full queue nothing is queued.
func TestLogKeepsQuarterForAdmissions(t *testing.T) {
	t.Parallel()
	l := &securityLog{queue: make(chan entry, queueSize)}
	for range queueSize - queueSize/4 {
		l.note(&record{Kind: "request.rejected"})
	}
	if lost := l.lost.Load(); lost != 0 {
		t.Fatalf("%d refusals lost below three quarters of the queue", lost)
	}
	l.note(&record{Kind: "request.rejected"})
	if lost := l.lost.Load(); lost != 1 {
		t.Fatalf("a refusal past three quarters of the queue: lost %d, want 1", lost)
	}
	for i := range queueSize / 4 {
		if !l.enqueue(&record{Kind: "request.admitted"}, make(chan error, 1), new(atomic.Int32)) {
			t.Fatalf("admission %d refused within the admissions' quarter", i)
		}
	}
	if l.enqueue(&record{Kind: "request.admitted"}, make(chan error, 1), new(atomic.Int32)) {
		t.Fatal("an admission queued past a full queue")
	}
}

// Records lost since the last batch are written in a loss record at close,
// and a closed log refuses every commit.
func TestLogReportsLossAtClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(l, "GET"); err != nil {
		t.Fatal(err)
	}
	// Two refusals the queue could not take, as note counts them.
	l.lost.Add(2)
	l.close()
	if err := admit(l, "GET"); !errors.Is(err, errLogFailed) {
		t.Fatalf("a commit after close: %v, want %v", err, errLogFailed)
	}
	all := records(t, dir)
	if len(all) == 0 {
		t.Fatal("no records")
	}
	if last := all[len(all)-1]; last.Kind != "log.loss" || last.Lost != 2 {
		t.Fatalf("last record %s with lost %d, want log.loss with lost 2", last.Kind, last.Lost)
	}
}

// A batch that brings the active file to exactly its size bound rotates it;
// one that stays below does not. Record lengths vary with their time, so
// each write aims at the bound with the last record's length.
func TestLogRotatesAtItsBound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	if err := admit(l, "GET"); err != nil {
		t.Fatal(err)
	}
	line := l.written.Load()
	for range 20 {
		start := l.written.Load()
		bound := start + line
		l.limit = bound // the writer is idle between batches
		if err := admit(l, "GET"); err != nil {
			t.Fatal(err)
		}
		rotated, err := listRotated(dir, "orders-security.log")
		if err != nil {
			t.Fatal(err)
		}
		if len(rotated) == 0 {
			if l.written.Load() >= bound {
				t.Fatalf("the active file reached its bound of %d bytes without rotating", bound)
			}
			line = l.written.Load() - start
			continue
		}
		info, err := os.Stat(rotated[0].path())
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == bound {
			return
		}
		if err := os.Remove(rotated[0].path()); err != nil {
			t.Fatal(err)
		}
		line = info.Size() - start
	}
	t.Fatal("no batch ended exactly at the bound in 20 tries")
}

// A refusal's and an outcome's duration_ms are milliseconds since the
// request arrived.
func TestRecordDurationsInMilliseconds(t *testing.T) {
	t.Parallel()
	g, path := testGuard(t)
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	handler := g.Wrap(slow)
	start := time.Now()
	for range 3 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", nil))
	}
	elapsed := float64(time.Since(start)) / float64(time.Millisecond)
	g.log.close()
	handled, rejected := 0, 0
	for _, r := range records(t, filepath.Dir(path)) {
		switch r.Kind {
		case "request.handled":
			handled++
			if r.DurationMS < 20 || r.DurationMS > elapsed {
				t.Fatalf("outcome duration %.3f ms, want 20 to %.3f", r.DurationMS, elapsed)
			}
		case "request.rejected":
			rejected++
			if r.DurationMS > elapsed {
				t.Fatalf("refusal duration %.3f ms, want at most %.3f", r.DurationMS, elapsed)
			}
		}
	}
	if handled != 2 || rejected != 1 {
		t.Fatalf("%d outcomes and %d refusals, want 2 and 1", handled, rejected)
	}
}
