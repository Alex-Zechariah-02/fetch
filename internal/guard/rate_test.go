// The weighted sliding-window limiter, held to the gateway's arithmetic: a
// previous bucket's weight fades across the current one, buckets roll, a
// sweep is bounded, the wait a refusal names is exact, and a random sequence
// gets the decisions a limiter rebuilt from admitted times gives.

package guard

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const testWindow = int64(60000)

// The previous bucket's requests weigh fully at its end and fade linearly to
// nothing across the current bucket.
func TestRateWeightFades(t *testing.T) {
	l := newLimiter()
	key := counterKey{"op", "acct"}
	start := 10 * testWindow
	for range 10 {
		if v, _ := l.admit(key, 10, time.Minute, start); v != admitted {
			t.Fatal("a request under the limit was refused")
		}
	}
	if v, _ := l.admit(key, 10, time.Minute, start+testWindow); v != exceeded {
		t.Fatal("ten requests of the previous bucket did not weigh fully at its end")
	}
	// Half way through, the ten weigh five: five more fit, the sixth does not.
	for i := range 5 {
		if v, _ := l.admit(key, 10, time.Minute, start+testWindow+testWindow/2); v != admitted {
			t.Fatalf("request %d at half weight refused", i+1)
		}
	}
	if v, _ := l.admit(key, 10, time.Minute, start+testWindow+testWindow/2); v != exceeded {
		t.Fatal("a request past the weighted limit was admitted")
	}
}

// A counter rolls one bucket by shifting, more than one by clearing, and an
// earlier time leaves it as it is.
func TestRateRoll(t *testing.T) {
	c := &counter{window: testWindow, bucket: 5, current: 7, previous: 3}
	c.roll(4 * testWindow)
	if c.bucket != 5 || c.current != 7 || c.previous != 3 {
		t.Fatalf("an earlier time moved the counter: %+v", c)
	}
	c.roll(6 * testWindow)
	if c.bucket != 6 || c.current != 0 || c.previous != 7 {
		t.Fatalf("one bucket on: %+v", c)
	}
	c.current = 4
	c.roll(8 * testWindow)
	if c.bucket != 8 || c.current != 0 || c.previous != 0 {
		t.Fatalf("two buckets on: %+v", c)
	}
}

// One sweep removes at most its budget of expired counters, earliest first,
// so a burst of keys that expired together never stalls one request.
func TestRateSweepBounded(t *testing.T) {
	l := newLimiter()
	for i := range 3 * sweepEvery {
		l.admit(counterKey{"op", string(rune('a'+i%26)) + string(rune(i))}, 5, time.Minute, 0)
	}
	held := l.size()
	l.sweep(2*testWindow, sweepEvery)
	if removed := held - l.size(); removed != sweepEvery {
		t.Fatalf("one sweep removed %d counters, want %d", removed, sweepEvery)
	}
	l.sweep(testWindow, sweepEvery)
	if removed := held - l.size(); removed != sweepEvery {
		t.Fatal("a sweep removed counters whose estimate is not zero")
	}
}

// A refusal names the whole seconds until the key admits again, and at that
// time it does.
func TestRateRetryAfter(t *testing.T) {
	l := newLimiter()
	key := counterKey{"op", "acct"}
	now := 3*testWindow + 20000
	for range 2 {
		l.admit(key, 2, time.Minute, now)
	}
	v, wait := l.admit(key, 2, time.Minute, now)
	if v != exceeded || wait < 1 {
		t.Fatalf("verdict %v, wait %d", v, wait)
	}
	if v, _ := l.admit(key, 2, time.Minute, now+wait*1000-1000); v != exceeded {
		t.Fatal("admitted a second before the named wait ended")
	}
	if v, _ := l.admit(key, 2, time.Minute, now+wait*1000); v != admitted {
		t.Fatal("still refused when the named wait ended")
	}
}

// reference decides from the admitted times alone, without rolling counters.
type reference struct{ admitted []int64 }

func (r *reference) admit(now, count int64) bool {
	bucket := now / testWindow
	var current, previous int64
	for _, at := range r.admitted {
		switch at / testWindow {
		case bucket:
			current++
		case bucket - 1:
			previous++
		}
	}
	elapsed := now - bucket*testWindow
	if current*testWindow+previous*(testWindow-elapsed)+testWindow > count*testWindow {
		return false
	}
	r.admitted = append(r.admitted, now)
	return true
}

// A random sequence of requests at increasing times gets the same decision
// from the limiter as from the reference.
func TestRateMatchesReference(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for run := range 20 {
		l, ref := newLimiter(), &reference{}
		count := int64(1 + random.IntN(12))
		now := int64(random.IntN(int(testWindow)))
		for step := range 400 {
			now += int64(random.IntN(int(testWindow / 8)))
			v, _ := l.admit(counterKey{"op", "acct"}, int(count), time.Minute, now)
			if want := ref.admit(now, count); (v == admitted) != want {
				t.Fatalf("run %d step %d at %d: limiter %v, reference %v", run, step, now, v, want)
			}
		}
	}
}

func TestRateClockTableHeapAndRetryAfter(t *testing.T) {
	t.Run("503 alone gets Retry-After 1", func(t *testing.T) {
		refused := httptest.NewRecorder()
		answer(refused, http.StatusBadRequest, "bad_request")
		if got := refused.Header().Get("Retry-After"); got != "" {
			t.Fatalf("400 set Retry-After=%q, want empty", got)
		}
		busy := httptest.NewRecorder()
		answer(busy, http.StatusServiceUnavailable, "overloaded")
		if got := busy.Header().Get("Retry-After"); got != "1" {
			t.Fatalf("503 set Retry-After=%q, want 1", got)
		}
		preset := httptest.NewRecorder()
		preset.Header().Set("Retry-After", "30")
		answer(preset, http.StatusServiceUnavailable, "overloaded")
		if got := preset.Header().Get("Retry-After"); got != "30" {
			t.Fatalf("503 replaced Retry-After 30 with %q", got)
		}
	})

	t.Run("exact Retry-After across two buckets", func(t *testing.T) {
		// 4 admitted in bucket 9 and 1 at +15 s into bucket 10 under 4 per
		// minute: the previous bucket's weight allows the next one at +30 s.
		l := newLimiter()
		key := counterKey{"op", "exact"}
		for range 4 {
			if v, _ := l.admit(key, 4, time.Minute, 9*testWindow); v != admitted {
				t.Fatal("bucket 9 admission refused")
			}
		}
		if v, _ := l.admit(key, 4, time.Minute, 10*testWindow+15000); v != admitted {
			t.Fatal("bucket 10 first admission refused")
		}
		if v, wait := l.admit(key, 4, time.Minute, 10*testWindow+15000); v != exceeded || wait != 15 {
			t.Fatalf("verdict=%v wait=%d, want exceeded and 15", v, wait)
		}
	})

	t.Run("clock moves forward", func(t *testing.T) {
		l := newLimiter()
		before := l.now()
		time.Sleep(15 * time.Millisecond)
		if after := l.now(); after <= before {
			t.Fatalf("limiter clock did not advance: %d -> %d", before, after)
		}
	})

	t.Run("sweep removes the earliest expiry first", func(t *testing.T) {
		l := newLimiter()
		l.admit(counterKey{"op", "early"}, 5, time.Second, 0)
		l.admit(counterKey{"op", "late"}, 5, time.Second, 10000)
		l.sweep(5000, 10)
		if l.size() != 1 {
			t.Fatalf("sweep left %d counters, want 1", l.size())
		}
	})

	t.Run("a rolled counter moves back in expiry order", func(t *testing.T) {
		l := newLimiter()
		l.admit(counterKey{"op", "early"}, 5, time.Second, 0)
		l.admit(counterKey{"op", "mid"}, 5, time.Second, 1000)
		l.admit(counterKey{"op", "early"}, 5, time.Second, 2000)
		l.sweep(3000, 10)
		if l.size() != 1 {
			t.Fatalf("sweep left %d counters, want 1", l.size())
		}
	})

	t.Run("periodic sweep runs on every sweepEvery-th admission only", func(t *testing.T) {
		l := newLimiter()
		l.admit(counterKey{"op", "expired"}, 5, 10*time.Millisecond, 0)
		for i := range sweepEvery - 2 {
			l.admit(counterKey{"op", "live-" + strconv.Itoa(i)}, 5, time.Minute, 100)
		}
		if l.size() != sweepEvery-1 {
			t.Fatalf("before admission %d: %d counters, want %d", sweepEvery, l.size(), sweepEvery-1)
		}
		l.admit(counterKey{"op", "last"}, 5, time.Minute, 100)
		if l.size() != sweepEvery-1 {
			t.Fatalf("after admission %d: %d counters, want %d", sweepEvery, l.size(), sweepEvery-1)
		}
	})

	t.Run("full table refuses live keys and sweeps expired ones", func(t *testing.T) {
		l := newLimiter()
		for i := range maxCounters {
			if v, _ := l.admit(counterKey{"op", "k" + strconv.Itoa(i)}, 5, time.Minute, 0); v != admitted {
				t.Fatalf("counter %d refused below maxCounters", i)
			}
		}
		if v, _ := l.admit(counterKey{"op", "overflow"}, 5, time.Minute, 0); v != full {
			t.Fatalf("live table at maxCounters: verdict=%v, want full", v)
		}
		if v, _ := l.admit(counterKey{"op", "after-expiry"}, 5, time.Minute, 2*testWindow); v != admitted {
			t.Fatalf("expired table at maxCounters: verdict=%v, want admitted after a sweep", v)
		}
	})
}
