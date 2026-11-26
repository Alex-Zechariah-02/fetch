// Stock reservations for checkout: reserve, release and commit.

package services

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"
)

type Line struct {
	Item     string `json:"item"`
	Quantity int    `json:"quantity"`
}
type PricedLine struct {
	Item      string `json:"item"`
	Name      string `json:"name"`
	Quantity  int    `json:"quantity"`
	UnitPrice int64  `json:"unit_price_sen"`
}
type purchase struct {
	Merchant string `json:"merchant"`
	Items    []Line `json:"items"`
}
type reservationResult struct {
	Merchant Merchant     `json:"merchant"`
	Items    []PricedLine `json:"items"`
	Subtotal int64        `json:"subtotal_sen"`
}
type reservationState uint8

const (
	reservationHeld reservationState = iota
	reservationCommitted
	reservationReleased
)

type reservation struct {
	digest   [32]byte
	counts   map[string]int
	response reservationResult
	state    reservationState
}

func (d *inventory) reserve(r *http.Request, body []byte) result {
	key := r.Header.Get("Idempotency-Key")
	if !idempotencyKey(key) {
		return failure(400, "invalid_request", "A valid idempotency key is required.", "Idempotency-Key")
	}
	digest := sha256.Sum256(body)
	if previous, found := d.reservations[key]; found {
		if previous.digest != digest || previous.state == reservationReleased {
			return failure(409, "idempotency_conflict", "That reservation identity is already used.", "")
		}
		return result{status: 200, body: previous.response}
	}
	var request purchase
	if rejected := decodeBody(r, body, orderBody, &request); rejected != nil {
		return *rejected
	}
	merchant, found := d.merchant(request.Merchant)
	if !found {
		return notFound()
	}
	if !merchant.Open {
		return failure(422, "merchant_closed", "This merchant is closed.", "merchant")
	}
	// One to twenty lines, the same bound the policy's checkout schema sets.
	if len(request.Items) < 1 || len(request.Items) > 20 {
		return failure(422, "invalid_change", "Choose from one to twenty items.", "items")
	}
	response := reservationResult{Merchant: merchant, Items: []PricedLine{}}
	counts := map[string]int{}
	for i, line := range request.Items {
		field := fmt.Sprintf("items[%d].item", i)
		stock := d.item(line.Item)
		if stock == nil || !stock.Item.Available {
			return failure(422, "item_unavailable", "This item is unavailable.", field)
		}
		if stock.Item.Merchant != request.Merchant {
			return failure(422, "mixed_merchants", "Choose items from one merchant.", field)
		}
		// A line holds one to fifty, as the policy's line schema allows.
		if line.Quantity < 1 || line.Quantity > 50 {
			return failure(422, "invalid_change", "Choose a quantity from one to fifty.", fmt.Sprintf("items[%d].quantity", i))
		}
		counts[line.Item] += line.Quantity
		if stock.Stock != nil && counts[line.Item] > *stock.Stock-stock.Reserved {
			return failure(409, "out_of_stock", stock.Item.Name+" is out of stock.", field)
		}
		response.Items = append(response.Items, PricedLine{line.Item, stock.Item.Name, line.Quantity, stock.Item.Price})
		response.Subtotal += int64(line.Quantity) * stock.Item.Price
	}
	for id, quantity := range counts {
		if stock := d.item(id); stock.Stock != nil {
			stock.Reserved += quantity
		}
	}
	d.reservations[key] = reservation{digest: digest, counts: counts, response: response}
	for _, old := range d.recent.add(key, reservationSize(len(request.Items)), time.Now()) {
		d.forget(old)
	}
	return result{status: 200, body: response, effect: "reserved stock"}
}

// forget drops a reservation the key memory no longer holds, returning the
// stock it still reserves: one neither released nor committed would
// otherwise keep that stock reserved for good.
func (d *inventory) forget(key string) {
	entry := d.reservations[key]
	if entry.state == reservationHeld {
		for id, quantity := range entry.counts {
			if stock := d.item(id); stock != nil && stock.Stock != nil {
				stock.Reserved -= quantity
			}
		}
	}
	delete(d.reservations, key)
}

func (d *inventory) release(key string) result {
	if !idempotencyKey(key) {
		return failure(400, "invalid_request", "A valid reservation identity is required.", "")
	}
	entry, found := d.reservations[key]
	if found && entry.state == reservationCommitted {
		return failure(409, "invalid_transition", "This reservation was already consumed.", "")
	}
	if found && entry.state == reservationHeld {
		for id, quantity := range entry.counts {
			if stock := d.item(id); stock.Stock != nil {
				stock.Reserved -= quantity
			}
		}
	}
	// A release may arrive before a timed-out prepare. Keep a tombstone so
	// that delayed request cannot reserve orphaned stock afterwards.
	entry.state = reservationReleased
	d.reservations[key] = entry
	// A tombstone for a reservation never made joins the same bounded memory
	// as a reservation, so it is forgotten in turn and Inventory stays bounded.
	if !found {
		for _, old := range d.recent.add(key, reservationSize(0), time.Now()) {
			d.forget(old)
		}
	}
	return result{status: 200, body: map[string]any{"released": true}}
}

func (d *inventory) commit(key string) result {
	entry, found := d.reservations[key]
	if !found || entry.state == reservationReleased {
		return notFound()
	}
	if entry.state == reservationHeld {
		for id, quantity := range entry.counts {
			if stock := d.item(id); stock.Stock != nil {
				*stock.Stock -= quantity
				stock.Reserved -= quantity
			}
		}
		entry.state = reservationCommitted
		d.reservations[key] = entry
	}
	return result{status: 200, body: map[string]any{"committed": true}}
}

// reservationSize estimates the memory of a reservation of lines: its key,
// digest, merchant and flags, and per line a priced line and a count.
func reservationSize(lines int) int { return 512 + 160*lines }
