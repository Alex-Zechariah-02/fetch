// Receipts: what each service remembers of the requests it answered, as
// evidence independent of the gateway. Outside measurement mode a service
// keeps the newest maxReceipts API receipts and, apart, the newest
// maxReceipts internal-call receipts, and counts the older ones it let go, so
// a long run never fills it and a report's page reads never push out the API
// receipts.

package services

import "time"

type Receipt struct {
	Seq           int       `json:"seq"`
	Time          time.Time `json:"time"`
	RequestID     string    `json:"request_id"`
	Generation    string    `json:"generation"`
	Method        string    `json:"method"`
	Target        string    `json:"target"`
	Status        int       `json:"status"`
	Effect        string    `json:"effect,omitempty"`
	Authorization bool      `json:"authorization"`
	Subject       string    `json:"subject,omitempty"`
	Roles         string    `json:"roles,omitempty"`
	BodyBytes     int       `json:"body_bytes"`
	// Internal marks a call from another service under /internal/.
	Internal bool `json:"internal,omitempty"`
}

// maxReceipts is how many receipts of each kind a service holds outside
// measurement mode.
const maxReceipts = 10000

// ring holds the newest maxReceipts receipts and counts the ones it let go.
type ring struct {
	receipts []Receipt
	dropped  int
}

func (g *ring) add(receipt Receipt) {
	if len(g.receipts) < maxReceipts {
		g.receipts = append(g.receipts, receipt)
		return
	}
	g.receipts[g.dropped%maxReceipts] = receipt
	g.dropped++
}

// list is the receipts held, oldest first.
func (g *ring) list() []Receipt {
	oldest := g.dropped % maxReceipts // 0 until the ring is full
	return append(append([]Receipt{}, g.receipts[oldest:]...), g.receipts[:oldest]...)
}

// keep records a receipt, numbered from the last reset; s.records is held.
func (s *Service) keep(receipt Receipt) {
	s.seq++
	receipt.Seq = s.seq
	if receipt.Internal {
		s.calls.add(receipt)
		return
	}
	s.recent.add(receipt)
}

// kept lists every receipt held, oldest first, and how many were let go.
func (s *Service) kept() ([]Receipt, int) {
	s.records.Lock()
	defer s.records.Unlock()
	api, calls := s.recent.list(), s.calls.list()
	merged := make([]Receipt, 0, len(api)+len(calls))
	for len(api) > 0 || len(calls) > 0 {
		if len(calls) == 0 || len(api) > 0 && api[0].Seq < calls[0].Seq {
			merged, api = append(merged, api[0]), api[1:]
			continue
		}
		merged, calls = append(merged, calls[0]), calls[1:]
	}
	return merged, s.recent.dropped + s.calls.dropped
}

// clear forgets every receipt and count, as a reset does.
func (s *Service) clear() int {
	s.records.Lock()
	defer s.records.Unlock()
	answers := s.seq
	if s.counts != nil {
		answers = s.counts.Total
		s.counts = newCounts()
	}
	s.recent, s.calls, s.seq = ring{}, ring{}, 0
	return answers
}
