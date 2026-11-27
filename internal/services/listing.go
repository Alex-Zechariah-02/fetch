// Pages of orders, newest placed first: the list is walked backwards from
// the cursor, so a page costs the orders it passes, with no copy or sort of
// the whole list.

package services

import (
	"net/http"
	"slices"
)

// Page sizes: most lists default to 20; a merchant's board and the support
// lists, which a screen shows whole, to 50. No page is larger than 100.
const (
	defaultPage = 20
	boardPage   = 50
	maxPage     = 100
)

// page answers the order lists: support and operations see every order, a
// customer their own, a merchant its shop's, and Reports reads every order
// with the data's epoch, so a report can refuse pages of two resets.
func (d *orders) page(r *http.Request, path, subject string) result {
	q, ok := query(r, "status", "limit", "after")
	if !ok {
		return invalidQuery()
	}
	if q.Get("status") != "" && !slices.Contains(orderStatuses, q.Get("status")) {
		return invalidQuery()
	}
	size := defaultPage
	if path == "/orders/merchant" {
		size = boardPage
	}
	n, after, ok := pagination(q, size)
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
	}
	if path == "/orders/mine" && q.Has("status") {
		return invalidQuery()
	}
	status := q.Get("status")
	listed := func(order Order) bool {
		return (path != "/orders/mine" || order.Customer == subject) && (ownMerchant == "" || order.Merchant == ownMerchant) && (status == "" || order.Status == status)
	}
	start := len(d.list) - 1
	if after != "" {
		position, found := d.index[after]
		if !found {
			return invalidQuery()
		}
		start = position - 1
	}
	// One order past the page shows whether another page follows.
	items := []Order{}
	for i := start; i >= 0 && len(items) <= n; i-- {
		if listed(d.list[i]) {
			items = append(items, d.list[i])
		}
	}
	response := map[string]any{"items": items[:min(n, len(items))]}
	if len(items) > n {
		response["next"] = items[n-1].ID
	}
	if path == "/internal/orders" {
		response["epoch"] = d.epoch
	}
	return result{status: 200, body: response}
}
