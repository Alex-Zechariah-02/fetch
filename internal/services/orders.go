// The Orders API: its records, its data and the routing of its requests.
// Orders are held in placement order with an index by ID, so a read finds an
// order, a page or a customer's mart history without scanning the list.

package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

type Address struct {
	Line1    string `json:"line1"`
	Line2    string `json:"line2"`
	Postcode string `json:"postcode"`
	City     string `json:"city"`
	State    string `json:"state"`
}
type TimelineEntry struct {
	Status string    `json:"status"`
	At     time.Time `json:"at"`
}
type Order struct {
	ID           string          `json:"id"`
	Customer     string          `json:"customer"`
	Merchant     string          `json:"merchant"`
	MerchantName string          `json:"merchant_name"`
	Items        []PricedLine    `json:"items"`
	Subtotal     int64           `json:"subtotal_sen"`
	DeliveryFee  int64           `json:"delivery_fee_sen"`
	Total        int64           `json:"total_sen"`
	Payment      string          `json:"payment"`
	Address      Address         `json:"address"`
	Note         string          `json:"note"`
	Status       string          `json:"status"`
	Rider        *string         `json:"rider"`
	Timeline     []TimelineEntry `json:"timeline"`
	CreatedAt    time.Time       `json:"created_at"`
}
type orderRequest struct {
	Merchant string  `json:"merchant"`
	Items    []Line  `json:"items"`
	Address  Address `json:"address"`
	Payment  string  `json:"payment"`
	Note     string  `json:"note"`
}
type savedOrderResult struct {
	digest [32]byte
	status int
	body   json.RawMessage
}
type orders struct {
	inventory *serviceClient
	list      []Order        // in placement order, oldest first
	index     map[string]int // position in list by order ID
	// martOrders counts each customer's orders at mart merchants that are not
	// cancelled: the first one has free delivery.
	martOrders     map[string]int
	seeded         int // orders in the seed, which a measurement run keeps
	wallets        map[string]int64
	next           int
	idempotency    map[string]savedOrderResult
	reservations   map[string]string
	pendingRelease map[string]bool
	// outside runs a call to Inventory without the service lock; locked runs
	// the compensation worker's turns under it.
	outside func(context.Context, func())
	locked  func(func())
	// retrying is set while the compensation worker runs; stop ends it.
	retrying bool
	stop     chan struct{}
	// epoch counts resets: a request that waited outside the lock while the
	// data was replaced must not write its result into the new data.
	epoch int
	// releasing and placing hold the reservation keys and checkout scopes
	// with a call to Inventory under way, so no second request repeats it.
	releasing map[string]bool
	placing   map[string]chan struct{}
	measure   bool     // also the load accounts' wallets
	recent    arrivals // checkout identities, oldest first
}

var orderStatuses = []string{"placed", "accepted", "ready", "picked_up", "delivered", "cancelled"}
var states = []string{"Johor", "Kedah", "Kelantan", "Melaka", "Negeri Sembilan", "Pahang", "Perak", "Perlis", "Pulau Pinang", "Sabah", "Sarawak", "Selangor", "Terengganu", "Wilayah Persekutuan Kuala Lumpur", "Wilayah Persekutuan Labuan", "Wilayah Persekutuan Putrajaya"}

func (d *orders) reset() {
	d.list = seedOrders()
	d.seeded = len(d.list)
	d.reindex()
	d.recent = measured(d.measure, keyLife)
	d.wallets = map[string]int64{"cust-001": walletSeed, "cust-002": walletSeed, "cust-003": walletSeed}
	if d.measure {
		for _, user := range loadUsers() {
			d.wallets[user.ID] = walletSeed
		}
	}
	d.next = nextNumber(d.list)
	d.idempotency = map[string]savedOrderResult{}
	d.reservations = map[string]string{}
	d.pendingRelease = map[string]bool{}
	d.releasing = map[string]bool{}
	d.placing = map[string]chan struct{}{}
	d.epoch++
}

// reindex rebuilds the index and the mart counts from the list.
func (d *orders) reindex() {
	d.index = make(map[string]int, len(d.list))
	d.martOrders = map[string]int{}
	for i, order := range d.list {
		d.index[order.ID] = i
		if martOrder(order) {
			d.martOrders[order.Customer]++
		}
	}
}

// martOrder reports an order at a mart merchant that is not cancelled.
func martOrder(order Order) bool {
	return order.Status != "cancelled" && (order.Merchant == "MER-005" || order.Merchant == "MER-006")
}

func (d *orders) close() {
	close(d.stop)
	d.inventory.close()
}
func (d *orders) snapshot() any {
	return struct {
		Orders  []Order          `json:"orders"`
		Wallets map[string]int64 `json:"wallets"`
		Next    int              `json:"next"`
		Pending int              `json:"pending_releases"`
	}{d.list, d.wallets, d.next, len(d.pendingRelease)}
}
func (d *orders) find(id string) *Order {
	i, found := d.index[id]
	if !found {
		return nil
	}
	return &d.list[i]
}
func (d *orders) fee(subject string, merchant Merchant) (int64, *string) {
	if merchant.Section == "mart" && d.martOrders[subject] == 0 {
		reason := "first_mart_order"
		return 0, &reason
	}
	return merchant.DeliveryFee, nil
}
func (d *orders) handle(r *http.Request, body []byte) result {
	if r.Method == "POST" && r.URL.Path == "/orders" {
		return d.create(r, body)
	}
	if r.Method == "POST" {
		if len(body) != 0 {
			return failure(400, "invalid_request", "This operation accepts no request body.", "")
		}
		for _, action := range []string{"cancel", "accept", "ready", "pickup", "deliver"} {
			if id, ok := oneID(r.URL.Path, "/orders/"+action+"/"); ok {
				return d.transition(r, id, action)
			}
		}
	}
	if r.Method != "GET" {
		return notFound()
	}
	path := r.URL.Path
	subject := r.Header.Get("X-Gateway-Subject")
	if path == "/orders/wallet" {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		balance, found := d.wallets[subject]
		if !found || !hasRole(r, "CUSTOMER") {
			return notFound()
		}
		return result{status: 200, body: map[string]any{"balance_sen": balance}}
	}
	if path == "/orders/quote" {
		return d.quote(r, subject)
	}
	if id, ok := oneID(path, "/orders/detail/"); ok {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		order := d.find(id)
		if order == nil || !seesOrder(r, *order) {
			return notFound()
		}
		return result{status: 200, body: map[string]any{"order": *order}}
	}
	if id, ok := oneID(path, "/internal/orders/"); ok {
		// Support checks a ticket's order reference: the order and its customer only.
		order := d.find(id)
		if order == nil {
			return notFound()
		}
		return result{status: 200, body: map[string]any{"order": map[string]string{"id": order.ID, "customer": order.Customer}}}
	}
	if path == "/orders/jobs" {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		if !hasRole(r, "RIDER") {
			return notFound()
		}
		available, mine := []Order{}, []Order{}
		for _, order := range d.list {
			if order.Status == "ready" && order.Rider == nil {
				available = append(available, order)
			}
			if order.Rider != nil && *order.Rider == subject && order.Status == "picked_up" {
				mine = append(mine, order)
			}
		}
		return result{status: 200, body: map[string]any{"available": available, "mine": mine}}
	}
	if path == "/orders" || path == "/orders/mine" || path == "/orders/merchant" || path == "/internal/orders" {
		return d.page(r, path, subject)
	}
	return notFound()
}

// quote is a customer's delivery fee at a merchant, read from Inventory.
func (d *orders) quote(r *http.Request, subject string) result {
	q, ok := query(r, "merchant")
	if !ok || q.Get("merchant") == "" {
		return invalidQuery()
	}
	if _, found := d.wallets[subject]; !found || !hasRole(r, "CUSTOMER") {
		return notFound()
	}
	var status int
	var body []byte
	var err error
	epoch := d.epoch
	d.outside(r.Context(), func() {
		status, body, err = d.inventory.call(r.Context(), "GET", "/internal/merchants/"+url.PathEscape(q.Get("merchant")), nil, "")
	})
	// The fee below is read from the orders as they are now.
	if err != nil || status >= http.StatusInternalServerError || d.epoch != epoch {
		return inventoryUnavailable()
	}
	if status != http.StatusOK {
		return notFound()
	}
	var response struct {
		Merchant Merchant `json:"merchant"`
	}
	if json.Unmarshal(body, &response) != nil || response.Merchant.ID == "" {
		return inventoryUnavailable()
	}
	fee, reason := d.fee(subject, response.Merchant)
	return result{status: 200, body: map[string]any{"merchant": response.Merchant.ID, "delivery_fee_sen": fee, "free_delivery": reason != nil, "reason": reason}}
}
