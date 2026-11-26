// Security log health state: recovery stays unavailable on failed writes,
// legal and illegal state transitions, and concurrent lock-free reads.

package guard

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A failed log.recovered write never lets a concurrent reader observe the log
// as available between clearing the old failure flag and setting the next one.
func TestLogHealthStaysUnavailableDuringFailedRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "orders-security.log")
	l := &securityLog{path: path, limit: maxLogBytes, queue: make(chan entry, 1), evictCh: make(chan entry, 1), done: make(chan struct{})}
	if err := l.open(); err != nil {
		t.Fatal(err)
	}
	l.file.Close()
	l.noSpace.Store(true)
	l.reason, l.since = "storage_space", time.Now()

	var stop atomic.Bool
	var sawHealthy atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			if !l.unavailable() {
				sawHealthy.Add(1)
			}
		}
	}()

	for range 5000 {
		l.noSpace.Store(true)
		l.down.Store(false)
		l.tried = time.Time{}
		if l.ready() {
			stop.Store(true)
			<-done
			t.Fatal("ready succeeded on a closed log file")
		}
	}
	stop.Store(true)
	<-done
	if n := sawHealthy.Load(); n != 0 {
		t.Fatalf("unavailable() read false %d times during failed recovery writes", n)
	}
}

func BenchmarkLogHealth(b *testing.B) {
	dir := b.TempDir()
	l, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		b.Fatal(err)
	}
	defer l.close()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if l.unavailable() {
			b.Fatal("healthy log read unavailable")
		}
	}
}
