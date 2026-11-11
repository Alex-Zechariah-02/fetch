// Receipts: what each service remembers of the requests it answered, as
// evidence independent of the gateway. Outside measurement mode a service
// keeps the newest maxReceipts and counts the older ones it let go, so a long
// run never fills it.

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
}

// maxReceipts is how many receipts a service holds outside measurement mode.
const maxReceipts = 10000

// keep records a receipt, numbered from the last reset, in place of the
// oldest one once maxReceipts are held.
func (s *Service) keep(receipt Receipt) {
	receipt.Seq = len(s.receipts) + s.dropped + 1
	if len(s.receipts) < maxReceipts {
		s.receipts = append(s.receipts, receipt)
		return
	}
	s.receipts[s.dropped%maxReceipts] = receipt
	s.dropped++
}

// kept lists the receipts held, oldest first.
func (s *Service) kept() []Receipt {
	oldest := s.dropped % maxReceipts // 0 until the ring is full
	return append(append([]Receipt{}, s.receipts[oldest:]...), s.receipts[:oldest]...)
}
