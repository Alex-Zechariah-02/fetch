// Security log health state: recovery stays unavailable on failed writes,
// legal and illegal state transitions, and concurrent lock-free reads.

package guard

import (
	"path/filepath"
	"sync"
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
	if !l.moveHealth(healthWriting, healthNoSpace) {
		t.Fatal("failed to enter healthNoSpace")
	}
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
		if l.currentHealth() == healthDown && !l.moveHealth(healthDown, healthNoSpace) {
			stop.Store(true)
			<-done
			t.Fatal("failed to move healthDown -> healthNoSpace")
		}
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

// Every state move in the health table is accepted and updates healthState,
// every disallowed move and stale expected state is refused, and concurrent
// readers observe only valid health states.
func TestLogHealthTransitions(t *testing.T) {
	t.Parallel()
	allStates := []logHealth{healthWriting, healthRotating, healthFull, healthDown, healthNoSpace}
	allowed := map[[2]logHealth]bool{
		{healthWriting, healthRotating}: true,
		{healthWriting, healthFull}:     true,
		{healthWriting, healthDown}:     true,
		{healthWriting, healthNoSpace}:  true,
		{healthRotating, healthWriting}: true,
		{healthRotating, healthFull}:    true,
		{healthRotating, healthDown}:    true,
		{healthRotating, healthNoSpace}: true,
		{healthFull, healthWriting}:     true,
		{healthDown, healthWriting}:     true,
		{healthDown, healthDown}:        true,
		{healthDown, healthNoSpace}:     true,
		{healthNoSpace, healthWriting}:  true,
		{healthNoSpace, healthNoSpace}:  true,
		{healthNoSpace, healthDown}:     true,
	}

	for _, from := range allStates {
		for _, to := range allStates {
			l := &securityLog{}
			l.health.Store(int32(from))
			want := allowed[[2]logHealth{from, to}]
			got := l.moveHealth(from, to)
			if got != want {
				t.Errorf("moveHealth(%d, %d) = %v, want %v", from, to, got, want)
			}
			wantAfter := from
			if want {
				wantAfter = to
			}
			if after := l.currentHealth(); after != wantAfter {
				t.Errorf("after moveHealth(%d, %d): state %d, want %d", from, to, after, wantAfter)
			}
		}
	}

	// Wrong expected state is refused even for a legal edge.
	l := &securityLog{}
	if l.moveHealth(healthDown, healthWriting) || l.currentHealth() != healthWriting {
		t.Fatalf("wrong expected state succeeded: health=%d", l.currentHealth())
	}
	// Unknown state refuses every transition.
	l.health.Store(99)
	if l.moveHealth(logHealth(99), healthWriting) {
		t.Fatal("unknown state transitioned to healthWriting")
	}

	// unavailable() holds for healthFull, healthDown and healthNoSpace only.
	wantUnavailable := map[logHealth]bool{
		healthWriting:  false,
		healthRotating: false,
		healthFull:     true,
		healthDown:     true,
		healthNoSpace:  true,
	}
	for s, want := range wantUnavailable {
		l.health.Store(int32(s))
		if got := l.unavailable(); got != want {
			t.Errorf("state %d: unavailable() = %v, want %v", s, got, want)
		}
	}

	// Concurrent transitions and reads stay race-free and valid.
	l = &securityLog{}
	var wg sync.WaitGroup
	var stop atomic.Bool
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				s := l.currentHealth()
				_ = l.unavailable()
				if s < healthWriting || s > healthNoSpace {
					t.Errorf("invalid health state %d", s)
					return
				}
			}
		})
	}
	for range 2000 {
		l.moveHealth(healthWriting, healthRotating)
		l.moveHealth(healthRotating, healthFull)
		l.moveHealth(healthFull, healthWriting)
		l.moveHealth(healthWriting, healthDown)
		l.moveHealth(healthDown, healthNoSpace)
		l.moveHealth(healthNoSpace, healthDown)
		l.moveHealth(healthDown, healthWriting)
	}
	stop.Store(true)
	wg.Wait()
}

// Recovering from a failed file counts a recovery; recovering from no space
// does not, and a succeeding rotation clears a prior rotation failure.
func TestLogHealthRecoveryAndRotation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := &securityLog{path: filepath.Join(dir, "orders-security.log"), limit: 1, queue: make(chan entry, 1), evictCh: make(chan entry, 1), done: make(chan struct{})}
	if err := l.open(); err != nil {
		t.Fatal(err)
	}
	defer l.file.Close()

	// healthRotating clears back to healthWriting on a succeeding rotation.
	if !l.moveHealth(healthWriting, healthRotating) {
		t.Fatal("failed to enter healthRotating")
	}
	if err := l.write([]entry{{line: []byte(`{"kind":"ok"}` + "\n")}}); err != nil {
		t.Fatalf("write with rotation: %v", err)
	}
	if got := l.currentHealth(); got != healthWriting {
		t.Fatalf("after succeeding rotation: health = %d, want healthWriting", got)
	}

	// healthNoSpace recovery resumes writing without incrementing recoveries.
	if !l.moveHealth(healthWriting, healthNoSpace) {
		t.Fatal("failed to enter healthNoSpace")
	}
	l.reason, l.since, l.tried = "storage_space", time.Now(), time.Time{}
	if !l.ready() || l.currentHealth() != healthWriting || l.recoveries.Load() != 0 {
		t.Fatalf("after no-space recovery: health=%d recoveries=%d", l.currentHealth(), l.recoveries.Load())
	}

	// healthDown recovery replaces the file and increments recoveries.
	if !l.moveHealth(healthWriting, healthDown) {
		t.Fatal("failed to enter healthDown")
	}
	l.reason, l.since, l.tried = "sync_failed", time.Now(), time.Time{}
	if !l.ready() || l.currentHealth() != healthWriting || l.recoveries.Load() != 1 {
		t.Fatalf("after down recovery: health=%d recoveries=%d", l.currentHealth(), l.recoveries.Load())
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
