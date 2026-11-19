// Checkout for the Orders API: request checks, stock reservation through
// Inventory and the idempotent placing of an order.

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"
)

func inventoryUnavailable() result {
	return failure(503, "inventory_unavailable", "Inventory could not confirm this request. Check the order before trying again.", "")
}

func (d *orders) create(r *http.Request, body []byte) result {
	subject := r.Header.Get("X-Gateway-Subject")
	if _, found := d.wallets[subject]; !found || !hasRole(r, "CUSTOMER") {
		return notFound()
	}
	values := r.Header.Values("Idempotency-Key")
	// One key names one checkout: with two, which one counts would be a guess.
	if len(values) > 1 || len(values) == 1 && !idempotencyKey(values[0]) {
		return failure(400, "invalid_request", "Use an idempotency key of 16 to 64 letters, digits, underscores or hyphens.", "Idempotency-Key")
	}
	key := r.Header.Get("Idempotency-Key")
	scope := subject + ":" + key
	digest := sha256.Sum256(body)
	// A key is placed once: a request that arrives while its key is being
	// placed waits for that placement and then replays its answer.
	for key != "" {
		if previous, found := d.idempotency[scope]; found {
			if previous.digest != digest {
				return failure(409, "idempotency_conflict", "This checkout key was used for a different order.", "")
			}
			return result{status: previous.status, encoded: previous.body}
		}
		placed, busy := d.placing[scope]
		if !busy {
			break
		}
		d.outside(r.Context(), func() {
			select {
			case <-placed:
			case <-r.Context().Done():
			}
		})
		if r.Context().Err() != nil {
			return failure(499, "request_cancelled", "The caller cancelled the request before the order was placed.", "")
		}
	}
	if key != "" {
		for _, old := range d.recent.expire(time.Now()) {
			delete(d.idempotency, old)
		}
		if d.recent.full() {
			return failure(503, "checkout_busy", "Too many recent checkouts are held. Try again later.", "")
		}
	}
	epoch, placed := d.epoch, make(chan struct{})
	if key != "" {
		d.placing[scope] = placed
	}
	res := d.place(r, body, key)
	close(placed)
	if d.epoch != epoch {
		return res
	}
	delete(d.placing, scope)
	// A server failure is not kept, so a retry with the key tries again
	// under a new reservation; the failed attempt's own is released.
	if key != "" && res.status < 500 {
		// Encoded once: the stored bytes are also this answer's.
		encoded, err := res.encode()
		if err != nil {
			return failure(500, "internal_error", "The service could not form its answer.", "")
		}
		// Answers are kept at least keyLife (recent) while this process
		// runs, so a retry within it never places a second order; a restart
		// or a reset forgets them.
		d.idempotency[scope] = savedOrderResult{digest, res.status, encoded}
		for _, old := range d.recent.add(scope, len(encoded)+len(scope), time.Now()) {
			delete(d.idempotency, old)
		}
		res.encoded = encoded
	}
	return res
}
func (d *orders) release(ctx context.Context, key string) bool {
	// Compensation survives caller cancellation and uses one stable identity.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if d.releasing[key] {
		return false
	}
	d.releasing[key] = true
	epoch, released := d.epoch, false
	d.outside(ctx, func() {
		// Two attempts bound the Inventory calls one failed checkout makes.
		for range 2 {
			status, _, err := d.inventory.call(cleanup, "DELETE", "/internal/reservations/"+key, nil, key)
			if err == nil && status == 200 {
				released = true
				return
			}
			if cleanup.Err() != nil {
				return
			}
		}
	})
	if d.epoch != epoch {
		return released
	}
	delete(d.releasing, key)
	if released {
		delete(d.pendingRelease, key)
		return true
	}
	// No maximum: each entry is one reservation Inventory still holds,
	// and dropping one would leave its stock reserved for good.
	d.pendingRelease[key] = true
	if !d.retrying {
		d.retrying = true
		go d.retry()
	}
	return false
}

// retry is the compensation worker: it retries the releases Inventory has
// not confirmed, at most retryBatch per turn under the service lock, waiting
// one second after a turn that settled everything it tried and twice as long
// (up to half a minute) after one that did not. It ends when nothing is
// pending or the service closes, so no request ever waits on another's
// compensation.
func (d *orders) retry() {
	delay := time.Second
	for {
		select {
		case <-d.stop:
			return
		case <-time.After(delay):
		}
		settled, pending := true, false
		d.locked(func() {
			keys := slices.Sorted(maps.Keys(d.pendingRelease))
			for _, key := range keys[:min(len(keys), retryBatch)] {
				if !d.releasing[key] && !d.release(context.Background(), key) {
					settled = false
				}
			}
			pending = len(d.pendingRelease) > 0
			d.retrying = pending
		})
		if !pending {
			return
		}
		if settled {
			delay = time.Second
		} else {
			delay = min(2*delay, 30*time.Second)
		}
	}
}

// retryBatch bounds one turn of the compensation worker; each release makes
// at most two Inventory calls of three seconds.
const retryBatch = 32

func (d *orders) place(r *http.Request, body []byte, key string) result {
	var request orderRequest
	if rejected := decodeBody(r, body, orderBody, &request); rejected != nil {
		return *rejected
	}
	if !validOrderRequest(request) {
		return failure(400, "invalid_request", "Check the items, delivery address and payment choice.", "")
	}
	subject := r.Header.Get("X-Gateway-Subject")
	// Each attempt reserves under its own identity: a failed attempt's
	// reservation is released and its identity stays refused in Inventory
	// (so a delayed request cannot reserve again), and a retry with the same
	// checkout key must still be able to reserve.
	hash := sha256.Sum256([]byte(subject + ":" + key + ":" + randomID()))
	reservationKey := hex.EncodeToString(hash[:])
	data, err := json.Marshal(purchase{request.Merchant, request.Items})
	if err != nil {
		return failure(500, "internal_error", "The service could not form its request.", "")
	}
	var status int
	var reply []byte
	epoch := d.epoch
	d.outside(r.Context(), func() {
		status, reply, err = d.inventory.call(r.Context(), "POST", "/internal/reservations", data, reservationKey)
	})
	// Everything below reads the wallet, the orders and the next order
	// number as they are now. After a reset the order is not placed.
	if err != nil || status >= 500 || status == 401 || d.epoch != epoch {
		d.release(r.Context(), reservationKey)
		return inventoryUnavailable()
	}
	if status != 200 {
		var problem apiError
		if json.Unmarshal(reply, &problem) != nil || problem.Error == "" {
			return inventoryUnavailable()
		}
		return result{status: status, body: problem}
	}
	var reserved reservationResult
	if json.Unmarshal(reply, &reserved) != nil || reserved.Merchant.ID != request.Merchant || len(reserved.Items) != len(request.Items) {
		d.release(r.Context(), reservationKey)
		return inventoryUnavailable()
	}
	fee, _ := d.fee(subject, reserved.Merchant)
	total := reserved.Subtotal + fee
	if request.Payment == "wallet" && d.wallets[subject] < total {
		d.release(r.Context(), reservationKey)
		return failure(409, "insufficient_wallet", "Your Fetch wallet balance is too low for this order.", "payment")
	}
	now := time.Now().UTC()
	created := Order{ID: fmt.Sprintf("ORD-%04d", d.next), Customer: subject, Merchant: request.Merchant, MerchantName: reserved.Merchant.Name, Items: reserved.Items, Subtotal: reserved.Subtotal, DeliveryFee: fee, Total: total, Payment: request.Payment, Address: request.Address, Note: request.Note, Status: "placed", Timeline: []TimelineEntry{{"placed", now}}, CreatedAt: now}
	if request.Payment == "wallet" {
		d.wallets[subject] -= total
	}
	d.list = append(d.list, created)
	d.index[created.ID] = len(d.list) - 1
	if martOrder(created) {
		d.martOrders[subject]++
	}
	d.next++
	d.reservations[created.ID] = reservationKey
	d.trim()
	return result{status: 201, body: map[string]any{"order": created}, effect: "created " + created.ID}
}

// validOrderRequest bounds every field, so a stored order and its receipt
// stay small: IDs have 7 characters (MER-001), a postcode 5; at most 20
// lines of at most 50 units keep the subtotal far inside an int64.
func validOrderRequest(request orderRequest) bool {
	if !length(request.Merchant, 7, 7) ||
		len(request.Items) < 1 || len(request.Items) > 20 ||
		!length(request.Note, 0, 200) ||
		!length(request.Address.Line1, 1, 100) ||
		!length(request.Address.Line2, 0, 100) ||
		!length(request.Address.Postcode, 5, 5) ||
		!length(request.Address.City, 1, 40) ||
		!slices.Contains(states, request.Address.State) ||
		(request.Payment != "cash" && request.Payment != "wallet") {
		return false
	}
	for _, line := range request.Items {
		if !length(line.Item, 7, 7) || line.Quantity < 1 || line.Quantity > 50 {
			return false
		}
	}
	return true
}
