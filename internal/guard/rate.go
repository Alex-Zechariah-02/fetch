// The weighted sliding-window rate limit of one API process: counters per
// operation and key (account or client address), the gateway's admission
// rule and table bound, and a clock that wall-clock steps do not move.

package guard

import (
	"container/heap"
	"sync"
	"time"
)

const (
	// maxCounters bounds the table; a full table of live counters refuses
	// new keys instead of forgetting admitted requests.
	maxCounters = 262144
	// sweepEvery admissions, counters whose estimate is zero are removed.
	sweepEvery = 1024
)

// counterKey is one quota: an operation and the account or address counted.
type counterKey struct{ operation, key string }

// counter holds the requests admitted in the current bucket and the one
// before it; buckets are window milliseconds long, anchored at the epoch.
type counter struct {
	window, bucket, current, previous int64
	key                               counterKey
	index                             int // position in the expiry heap
}

// removable is when both buckets have ended, so the estimate is zero.
func (c *counter) removable() int64 { return (c.bucket + 2) * c.window }

// roll moves the counter to the bucket containing now.
func (c *counter) roll(now int64) {
	bucket := now / c.window
	switch {
	case bucket == c.bucket+1:
		c.previous, c.current = c.current, 0
	case bucket > c.bucket+1:
		c.previous, c.current = 0, 0
	}
	c.bucket = max(c.bucket, bucket)
}

// usage is the weighted count times the window, so admission is exact
// integer arithmetic.
func (c *counter) usage(now int64) int64 {
	elapsed := max(now-c.bucket*c.window, 0)
	return c.current*c.window + c.previous*(c.window-elapsed)
}

// expiry orders counters by removable time; it implements heap.Interface.
type expiry []*counter

func (q expiry) Len() int           { return len(q) }
func (q expiry) Less(i, j int) bool { return q[i].removable() < q[j].removable() }
func (q expiry) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}
func (q *expiry) Push(x any) {
	c := x.(*counter)
	c.index = len(*q)
	*q = append(*q, c)
}
func (q *expiry) Pop() any {
	old := *q
	c := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	return c
}

// verdict is a rate decision.
type verdict int

const (
	admitted verdict = iota
	exceeded
	full
)

// limiter makes each check and increment one atomic decision.
type limiter struct {
	mu         sync.Mutex
	counters   map[counterKey]*counter
	queue      expiry
	admissions int
	anchor     time.Time
}

func newLimiter() *limiter {
	return &limiter{counters: map[counterKey]*counter{}, anchor: time.Now()}
}

// now is Unix milliseconds: the wall clock at start plus monotonic time since.
func (l *limiter) now() int64 {
	return l.anchor.UnixMilli() + time.Since(l.anchor).Milliseconds()
}

// admit applies the rule: with C admitted in the current bucket, P in the
// previous one and offset d into the current bucket, a request is admitted
// when C + P*(W-d)/W + 1 <= N; only an admitted request is counted.
func (l *limiter) admit(key counterKey, count int, window time.Duration) verdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, w := l.now(), window.Milliseconds()
	c := l.counters[key]
	if c == nil {
		if len(l.counters) >= maxCounters {
			l.sweep(now)
		}
		if len(l.counters) >= maxCounters {
			return full
		}
		c = &counter{window: w, bucket: now / w, key: key}
		l.counters[key] = c
		heap.Push(&l.queue, c)
	}
	removable := c.removable()
	c.roll(now)
	if c.removable() != removable {
		heap.Fix(&l.queue, c.index)
	}
	if c.usage(now)+w > int64(count)*w {
		return exceeded
	}
	c.current++
	l.admissions++
	if l.admissions%sweepEvery == 0 {
		l.sweep(now)
	}
	return admitted
}

// sweep removes the counters whose estimate is zero, visiting only those.
func (l *limiter) sweep(now int64) {
	for len(l.queue) > 0 && l.queue[0].removable() <= now {
		c := heap.Pop(&l.queue).(*counter)
		delete(l.counters, c.key)
	}
}
