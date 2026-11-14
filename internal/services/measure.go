// Bounded service data: Orders keeps the seed orders and the newest placed
// ones, and Orders and Inventory forget their oldest checkout and
// reservation identities. Measurement mode keeps little, so the work a
// request costs is the same at the end of a long run as at its start; other
// modes keep more, below the 20,000 orders a report reads. A forgotten
// identity can be used again, which a load generator that makes a new one
// per request never does.

package services

import "slices"

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

// arrivals remembers keys in the order they came, so that the oldest can be
// forgotten. A limit of zero remembers nothing.
type arrivals struct {
	keys  []string
	limit int
}

// measured is the key memory of a service, bounded for its mode.
func measured(measure bool) arrivals {
	if measure {
		return arrivals{limit: measureKeys}
	}
	return arrivals{limit: keptKeys}
}

// add notes key and returns the oldest limit keys, now to be forgotten, once
// twice the limit are held.
func (w *arrivals) add(key string) []string {
	if w.limit == 0 {
		return nil
	}
	w.keys = append(w.keys, key)
	if len(w.keys) < 2*w.limit {
		return nil
	}
	oldest := slices.Clone(w.keys[:w.limit])
	w.keys = slices.Delete(w.keys, 0, w.limit)
	return oldest
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
