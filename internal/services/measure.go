// Bounded service data: Orders keeps the seed orders and the newest placed
// ones, and Orders and Inventory forget their oldest checkout and
// reservation identities, a checkout identity only after a day. Measurement
// mode keeps little, so the work a request costs is the same at the end of a
// long run as at its start; other modes keep more, below the 20,000 orders a
// report reads. A forgotten identity can be used again, which a load
// generator that makes a new one per request never does.

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
	// measurement run keeps at least.
	measureKeys = 10000
	// keptOrders and keptKeys are the same bounds outside measurement mode:
	// at most twice keptOrders placed orders stay below the reports' bound.
	keptOrders = 5000
	keptKeys   = 50000
)

// keyLife is how long a checkout identity is kept at least, so a client's
// retry of one checkout replays its answer and never places a second order;
// a day, as payment APIs keep idempotency keys.
const keyLife = 24 * time.Hour

// arrivals remembers keys in the order they came, so that the oldest can be
// forgotten once older than life. A limit of zero remembers nothing.
type arrivals struct {
	keys  []arrival
	limit int
	life  time.Duration
}

type arrival struct {
	key string
	at  time.Time
}

// measured is the key memory of a service, bounded for its mode, keeping
// each key at least life.
func measured(measure bool, life time.Duration) arrivals {
	if measure {
		return arrivals{limit: measureKeys, life: life}
	}
	return arrivals{limit: keptKeys, life: life}
}

// add notes key, arrived at now, and returns the keys now to be forgotten.
func (w *arrivals) add(key string, now time.Time) []string {
	if w.limit == 0 {
		return nil
	}
	w.keys = append(w.keys, arrival{key, now})
	return w.expire(now)
}

// expire returns the oldest limit keys, now to be forgotten, once twice the
// limit are held and all of them are older than life.
func (w *arrivals) expire(now time.Time) []string {
	if w.limit == 0 || len(w.keys) < 2*w.limit || now.Sub(w.keys[w.limit-1].at) < w.life {
		return nil
	}
	oldest := make([]string, w.limit)
	for i, entry := range w.keys[:w.limit] {
		oldest[i] = entry.key
	}
	w.keys = slices.Delete(w.keys, 0, w.limit)
	return oldest
}

// full reports that four times the limit are held, none old enough to
// forget: a new key is refused rather than an unexpired one forgotten.
func (w *arrivals) full() bool {
	return w.limit > 0 && len(w.keys) >= 4*w.limit
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
}
