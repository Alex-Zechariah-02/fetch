// The Orders API: its records, its data and the routing of its requests.

package services

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
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
	inventory      *serviceClient
	list           []Order
	seeded         int // orders in the seed, which a measurement run keeps
	wallets        map[string]int64
	next           int
	idempotency    map[string]savedOrderResult
	reservations   map[string]string
	pendingRelease map[string]bool
	// outside runs a call to Inventory without the service lock.
	outside func(func())
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
	d.recent = measured(d.measure, keyLife)
	d.wallets = map[string]int64{"cust-001": walletSeed, "cust-002": walletSeed, "cust-003": walletSeed}
	if d.measure {
		for _, user := range loadUsers() {
			d.wallets[user.ID] = walletSeed
		}
	}
	d.next = 1005
	d.idempotency = map[string]savedOrderResult{}
	d.reservations = map[string]string{}
	d.pendingRelease = map[string]bool{}
	d.releasing = map[string]bool{}
	d.placing = map[string]chan struct{}{}
	d.epoch++
}
func (d *orders) close() { d.inventory.close() }
func (d *orders) snapshot() any {
	return struct {
		Orders  []Order          `json:"orders"`
		Wallets map[string]int64 `json:"wallets"`
		Next    int              `json:"next"`
		Pending int              `json:"pending_releases"`
	}{d.list, d.wallets, d.next, len(d.pendingRelease)}
}
func (d *orders) find(id string) *Order {
	for i := range d.list {
		if d.list[i].ID == id {
			return &d.list[i]
		}
	}
	return nil
}
func (d *orders) fee(subject string, merchant Merchant) (int64, *string) {
	if merchant.Section == "mart" {
		for _, order := range d.list {
			if order.Customer == subject && order.Status != "cancelled" && (order.Merchant == "MER-005" || order.Merchant == "MER-006") {
				return merchant.DeliveryFee, nil
			}
		}
		reason := "first_mart_order"
		return 0, &reason
	}
	return merchant.DeliveryFee, nil
}
func (d *orders) handle(r *http.Request, body []byte) result {
	// Retry one outstanding compensation per arrival, never the checkout.
	// Every attempt has its own bound and reuses the reservation identity.
	for _, key := range slices.Sorted(maps.Keys(d.pendingRelease)) {
		if !d.releasing[key] {
			d.release(r.Context(), key)
			break
		}
	}
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
		d.outside(func() {
			status, body, err = d.inventory.call(r.Context(), "GET", "/internal/merchants/"+url.PathEscape(q.Get("merchant")), nil, "")
		})
		// The fee below is read from the orders as they are now.
		if err != nil || status >= 500 || d.epoch != epoch {
			return inventoryUnavailable()
		}
		if status != 200 {
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
		q, ok := query(r, "status", "limit", "after")
		if !ok {
			return invalidQuery()
		}
		if q.Get("status") != "" && !slices.Contains(orderStatuses, q.Get("status")) {
			return invalidQuery()
		}
		n, after, ok := pagination(q)
		if !ok {
			return invalidQuery()
		}
		if path == "/orders/mine" && !hasRole(r, "CUSTOMER") {
			return notFound()
		}
		if path == "/orders" && !hasRole(r, "SUPPORT") && !hasRole(r, "OPERATIONS") {
			return notFound()
		}
		var ownMerchant string
		if path == "/orders/merchant" {
			user, found := userByID(subject)
			if !found || !hasRole(r, "MERCHANT") || user.Merchant == nil {
				return notFound()
			}
			ownMerchant = *user.Merchant
			if q.Has("limit") || q.Has("after") {
				return invalidQuery()
			}
			// A merchant's screen shows its orders at once; trim bounds the list.
			n = len(d.list)
		}
		if path == "/orders/mine" && q.Has("status") {
			return invalidQuery()
		}
		status := q.Get("status")
		listed := func(order Order) bool {
			return (path != "/orders/mine" || order.Customer == subject) && (ownMerchant == "" || order.Merchant == ownMerchant) && (status == "" || order.Status == status)
		}
		// Only the caller's orders and the cursor's are sorted (sorting the
		// whole list on every read was most of Orders' work); a sorted subset
		// keeps its relative order, so pages and the cursor check are unchanged.
		var ordered []Order
		for _, order := range d.list {
			if order.ID == after || listed(order) {
				ordered = append(ordered, order)
			}
		}
		slices.SortFunc(ordered, func(a, b Order) int {
			if compared := b.CreatedAt.Compare(a.CreatedAt); compared != 0 {
				return compared
			}
			return strings.Compare(b.ID, a.ID)
		})
		items := []Order{}
		seen := after == ""
		for _, order := range ordered {
			if !seen {
				if order.ID == after {
					seen = true
				}
				continue
			}
			if !listed(order) {
				continue
			}
			items = append(items, order)
		}
		if !seen {
			return invalidQuery()
		}
		response := map[string]any{"items": items[:min(n, len(items))]}
		if len(items) > n {
			response["next"] = items[n-1].ID
		}
		return result{status: 200, body: response}
	}
	return notFound()
}
