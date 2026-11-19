// Bounded service data: Orders keeps the seed orders and the newest placed
// ones, and Orders and Inventory forget their oldest checkout and
// reservation identities; outside measurement mode a checkout identity only
// after a day. Measurement mode keeps little and forgets by count alone, so
// the work a request costs is the same at the end of a long run as at its
// start; other modes keep more, below the 20,000 orders a report reads. A
// forgotten identity can be used again, which a load generator that makes a
// new one per request never does.

package services

import (
	"slices"
	"time"
)

const (
	// measureOrders is how many placed orders, beyond the seed, a
	// measurement run keeps at least.
	measureOrders = 1000
	// measureKeys is how many checkout or reservation identities a
	// measurement run keeps at least, while their answers fit keptBytes.
	measureKeys = 10000
	// keptOrders and keptKeys are the same bounds outside measurement mode:
	// at most twice keptOrders placed orders stay below the reports' bound.
	keptOrders = 5000
	keptKeys   = 50000
	// keptBytes bounds the answers one service's key memory holds: an Orders
	// answer is about 700 bytes, so a measurement run keeps tens of
	// thousands, and the memory stays far below the gateway's own.
	keptBytes = 32 << 20
)

// keyLife is how long a checkout identity is kept at least, so a client's
// retry of one checkout replays its answer and never places a second order;
// a day, as payment APIs keep idempotency keys. The memory is the process's:
// a restart or a reset forgets every key.
const keyLife = 24 * time.Hour

// arrivals remembers keys in the order they came, so that the oldest can be
// forgotten once older than life. A limit of zero remembers nothing. The
// oldest held key is keys[head]; the slice is compacted once half of it is
// forgotten, so forgetting costs no shift and the memory shrinks with it.
type arrivals struct {
	keys     []arrival
	head     int
	limit    int
	life     time.Duration
	bytes    int // the sizes of the held keys' answers
	maxBytes int // zero sets no bound on bytes
}

type arrival struct {
	key  string
	at   time.Time
	size int
}

// measured is the key memory of a service, bounded for its mode. Outside
// measurement mode it keeps each key at least life; in measurement mode it
// keeps the newest measureKeys at least and forgets older ones at any age,
// so a long run is never refused for holding too many.
func measured(measure bool, life time.Duration) arrivals {
	if measure {
		return arrivals{limit: measureKeys, maxBytes: keptBytes}
	}
	return arrivals{limit: keptKeys, life: life, maxBytes: keptBytes}
}

// held is the number of keys remembered.
func (w *arrivals) held() int { return len(w.keys) - w.head }

// add notes key, whose answer takes size bytes, arrived at now, and returns
// the keys now to be forgotten.
func (w *arrivals) add(key string, size int, now time.Time) []string {
	if w.limit == 0 {
		return nil
	}
	w.keys = append(w.keys, arrival{key, now, size})
	w.bytes += size
	return w.expire(now)
}

// expire returns the keys now to be forgotten: the oldest limit once twice
// the limit are held, and then the oldest while the answers exceed maxBytes,
// each only when older than life.
func (w *arrivals) expire(now time.Time) []string {
	if w.limit == 0 {
		return nil
	}
	var oldest []string
	if w.held() >= 2*w.limit && now.Sub(w.keys[w.head+w.limit-1].at) >= w.life {
		for range w.limit {
			oldest = append(oldest, w.forget())
		}
	}
	for w.maxBytes > 0 && w.held() > 0 && w.bytes > w.maxBytes && now.Sub(w.keys[w.head].at) >= w.life {
		oldest = append(oldest, w.forget())
	}
	if w.head > 0 && w.head >= len(w.keys)/2 {
		w.keys, w.head = slices.Clone(w.keys[w.head:]), 0
	}
	return oldest
}

// forget drops the oldest key and returns it.
func (w *arrivals) forget() string {
	entry := w.keys[w.head]
	w.keys[w.head] = arrival{}
	w.head++
	w.bytes -= entry.size
	return entry.key
}

// full reports that four times the limit are held, or answers of maxBytes,
// none old enough to forget: a new key is refused rather than an unexpired
// one forgotten.
func (w *arrivals) full() bool {
	return w.limit > 0 && (w.held() >= 4*w.limit || w.maxBytes > 0 && w.bytes >= w.maxBytes)
}

// trim drops the oldest kept placed orders, with the reservations they
// name, once twice that many have been placed.
func (d *orders) trim() {
	kept := keptOrders
	if d.measure {
		kept = measureOrders
	}
	if len(d.list) < d.seeded+2*kept {
		return
	}
	for _, order := range d.list[d.seeded : d.seeded+kept] {
		delete(d.reservations, order.ID)
	}
	d.list = slices.Delete(d.list, d.seeded, d.seeded+kept)
	d.reindex()
}
