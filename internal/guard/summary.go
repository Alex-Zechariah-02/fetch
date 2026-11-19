// Refusals no control decides (ingress, canonical path, route, overload)
// counted per minute instead of recorded one by one, as the gateway's
// audit.ingress_summary does: a flood of them costs a counter, not a durable
// record each. Control refusals (token, roles, rate, body) keep one record.

package guard

import (
	"cmp"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	// summaryInterval keeps a flood to one record a minute while still
	// placing it in time to the minute.
	summaryInterval = time.Minute
	// summaryTop is how many of the busiest addresses one summary names.
	summaryTop = 16
	// summaryAddresses bounds the addresses counted per interval; refusals
	// from further addresses still count in their reason.
	summaryAddresses = 4096
)

// addressCount is how many refusals one client address had.
type addressCount struct {
	Address string `json:"address"`
	Count   uint64 `json:"count"`
}

// summary counts one interval's refusals by reason and client address.
type summary struct {
	mu        sync.Mutex
	since     time.Time
	reasons   map[string]uint64
	addresses map[string]uint64
}

// count adds one refusal of reason from address.
func (s *summary) count(reason, address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reasons == nil {
		s.since = time.Now().UTC()
		s.reasons, s.addresses = map[string]uint64{}, map[string]uint64{}
	}
	s.reasons[reason]++
	if _, known := s.addresses[address]; known || len(s.addresses) < summaryAddresses {
		s.addresses[address]++
	}
}

// take returns the counted refusals as one record and starts a new
// interval, or false when none were counted.
func (s *summary) take(api string) (record, bool) {
	s.mu.Lock()
	reasons, addresses, since := s.reasons, s.addresses, s.since
	s.reasons, s.addresses = nil, nil
	s.mu.Unlock()
	if reasons == nil {
		return record{}, false
	}
	top := make([]addressCount, 0, len(addresses))
	for address, n := range addresses {
		top = append(top, addressCount{address, n})
	}
	slices.SortFunc(top, func(x, y addressCount) int {
		return cmp.Or(cmp.Compare(y.Count, x.Count), cmp.Compare(x.Address, y.Address))
	})
	return record{Kind: "audit.ingress_summary", API: api, First: since, Counts: maps.Clone(reasons), Addresses: top[:min(len(top), summaryTop)]}, true
}

// summarise writes a summary record every interval until stop closes, then
// writes the last one; done closes when it has.
func (g *Guard) summarise(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(summaryInterval)
	defer ticker.Stop()
	flush := func() {
		if r, found := g.refusals.take(g.api); found {
			g.log.note(&r)
		}
	}
	for {
		select {
		case <-ticker.C:
			flush()
		case <-stop:
			flush()
			return
		}
	}
}
