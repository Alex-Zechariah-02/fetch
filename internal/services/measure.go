// Measurement mode keeps a service's data from growing with the run, so the
// work a request costs is the same at the end of a long run as at its start:
// Orders keeps the seed orders and the newest placed ones, and Orders and
// Inventory forget their oldest checkout and reservation identities. A
// forgotten identity can be used again, which a load generator that makes a
// new one per request never does. Outside measurement mode nothing is
// forgotten.

package services

import "slices"

const (
	// measureOrders is how many placed orders, beyond the seed, a
	// measurement run keeps at least.
	measureOrders = 1000
	// measureKeys is how many checkout or reservation identities a
	// measurement run keeps at least.
	measureKeys = 10000
)

// arrivals remembers keys in the order they came, so that the oldest can be
// forgotten. A limit of zero remembers nothing.
type arrivals struct {
	keys  []string
	limit int
}

// measured is the key memory of a service in measurement mode.
func measured(measure bool) arrivals {
	if measure {
		return arrivals{limit: measureKeys}
	}
	return arrivals{}
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

// trim drops the oldest placed orders of a measurement run, with the
// reservations they name, once twice measureOrders have been placed.
func (d *orders) trim() {
	if !d.measure || len(d.list) < d.seeded+2*measureOrders {
		return
	}
	for _, order := range d.list[d.seeded : d.seeded+measureOrders] {
		delete(d.reservations, order.ID)
	}
	d.list = slices.Delete(d.list, d.seeded, d.seeded+measureOrders)
}
