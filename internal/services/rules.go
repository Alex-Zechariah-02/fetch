// Every Fetch API operation with the roles that may call it, its rate and its
// request body rule: each API's own table for built-in protection, and the
// source of the demonstration's baseline gateway policy (contract sections 4
// and 6), so both modes start from the same rules.

package services

import (
	"slices"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
)

// Roles are the five roles Accounts issues; any other role in a token is
// ignored.
var Roles = []string{"CUSTOMER", "MERCHANT", "RIDER", "SUPPORT", "OPERATIONS"}

// window is every operation's rate window.
const window = 60 * time.Second

func stringSchema(minimum, maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
}
func integerSchema(minimum, maximum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": maximum}
}
func objectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

// Operations lists every API operation in the baseline policy's order.
func Operations() []guard.Operation {
	itemChange := objectSchema([]string{}, map[string]any{"price_sen": integerSchema(50, 100000), "available": map[string]any{"type": "boolean"}})
	stockChange := objectSchema([]string{"delta"}, map[string]any{"delta": integerSchema(-100, 100)})
	line := objectSchema([]string{"item", "quantity"}, map[string]any{"item": stringSchema(7, 7), "quantity": integerSchema(1, 50)})
	address := objectSchema([]string{"line1", "postcode", "city", "state"}, map[string]any{
		"line1": stringSchema(1, 100), "line2": stringSchema(0, 100), "postcode": stringSchema(5, 5), "city": stringSchema(1, 40),
		"state": map[string]any{"type": "string", "enum": []string{"Johor", "Kedah", "Kelantan", "Melaka", "Negeri Sembilan", "Pahang", "Perak", "Perlis", "Pulau Pinang", "Sabah", "Sarawak", "Selangor", "Terengganu", "Wilayah Persekutuan Kuala Lumpur", "Wilayah Persekutuan Labuan", "Wilayah Persekutuan Putrajaya"}},
	})
	checkout := objectSchema([]string{"merchant", "items", "address", "payment"}, map[string]any{
		"merchant": stringSchema(7, 7), "items": map[string]any{"type": "array", "items": line, "minItems": 1, "maxItems": 20},
		"address": address, "note": stringSchema(0, 200), "payment": map[string]any{"type": "string", "enum": []string{"cash", "wallet"}},
	})
	ticket := objectSchema([]string{"subject", "message"}, map[string]any{"subject": stringSchema(5, 120), "message": stringSchema(1, 2000), "order": stringSchema(8, 8), "request_ref": stringSchema(16, 64)})
	reply := objectSchema([]string{"message"}, map[string]any{"message": stringSchema(1, 2000)})
	login := objectSchema([]string{"email", "password"}, map[string]any{"email": stringSchema(3, 254), "password": stringSchema(1, 256)})
	public, all := []string(nil), Roles
	customer, merchant, rider := []string{"CUSTOMER"}, []string{"MERCHANT"}, []string{"RIDER"}
	support, operations := []string{"SUPPORT"}, []string{"OPERATIONS"}
	op := func(id, api, method, target string, roles []string, count, maxBytes int, schema map[string]any) guard.Operation {
		return guard.Operation{ID: id, API: api, Method: method, Target: target, Roles: slices.Clone(roles), Count: count, Window: window, MaxBytes: maxBytes, Schema: schema}
	}
	return []guard.Operation{
		op("inventory.categories", "inventory", "GET", "/inventory/categories", public, 120, 0, nil),
		op("inventory.merchants", "inventory", "GET", "/inventory/merchants", public, 120, 0, nil),
		op("inventory.merchant", "inventory", "GET", "/inventory/merchants/*", public, 120, 0, nil),
		op("inventory.search", "inventory", "GET", "/inventory/search", public, 60, 0, nil),
		op("inventory.item", "inventory", "GET", "/inventory/items/*", public, 120, 0, nil),
		op("inventory.item.update", "inventory", "PATCH", "/inventory/items/*", merchant, 30, 512, itemChange),
		op("inventory.stock.read", "inventory", "GET", "/inventory/stock/*", []string{"MERCHANT", "OPERATIONS"}, 100, 0, nil),
		op("inventory.stock.adjust", "inventory", "PATCH", "/inventory/stock/*", []string{"MERCHANT", "OPERATIONS"}, 30, 256, stockChange),
		op("orders.quote", "orders", "GET", "/orders/quote", customer, 60, 0, nil),
		op("orders.create", "orders", "POST", "/orders", customer, 10, 4096, checkout),
		op("orders.mine", "orders", "GET", "/orders/mine", customer, 60, 0, nil),
		op("orders.wallet", "orders", "GET", "/orders/wallet", customer, 60, 0, nil),
		op("orders.detail", "orders", "GET", "/orders/detail/*", all, 120, 0, nil),
		op("orders.cancel", "orders", "POST", "/orders/cancel/*", customer, 10, 0, nil),
		op("orders.merchant", "orders", "GET", "/orders/merchant", merchant, 120, 0, nil),
		op("orders.accept", "orders", "POST", "/orders/accept/*", merchant, 60, 0, nil),
		op("orders.ready", "orders", "POST", "/orders/ready/*", merchant, 60, 0, nil),
		op("orders.jobs", "orders", "GET", "/orders/jobs", rider, 120, 0, nil),
		op("orders.pickup", "orders", "POST", "/orders/pickup/*", rider, 60, 0, nil),
		op("orders.deliver", "orders", "POST", "/orders/deliver/*", rider, 60, 0, nil),
		op("orders.all", "orders", "GET", "/orders", []string{"SUPPORT", "OPERATIONS"}, 60, 0, nil),
		op("reports.merchant", "reports", "GET", "/reports/merchant", merchant, 30, 0, nil),
		op("reports.summary", "reports", "GET", "/reports/summary", operations, 30, 0, nil),
		op("reports.sales", "reports", "GET", "/reports/sales", operations, 30, 0, nil),
		op("reports.top-items", "reports", "GET", "/reports/top-items", operations, 30, 0, nil),
		op("support.create", "support", "POST", "/support/tickets", customer, 5, 4096, ticket),
		op("support.mine", "support", "GET", "/support/mine", customer, 60, 0, nil),
		op("support.queue", "support", "GET", "/support/queue", support, 60, 0, nil),
		op("support.ticket", "support", "GET", "/support/ticket/*", []string{"CUSTOMER", "SUPPORT"}, 60, 0, nil),
		op("support.reply", "support", "POST", "/support/reply/*", []string{"CUSTOMER", "SUPPORT"}, 20, 4096, reply),
		op("support.resolve", "support", "POST", "/support/resolve/*", support, 20, 0, nil),
		op("accounts.login", "accounts", "POST", "/accounts/login", public, 10, 512, login),
		op("accounts.refresh", "accounts", "POST", "/accounts/refresh", all, 30, 0, nil),
		op("accounts.me", "accounts", "GET", "/accounts/me", all, 60, 0, nil),
	}
}

// operationsOf is the table of one API.
func operationsOf(api string) []guard.Operation {
	var table []guard.Operation
	for _, op := range Operations() {
		if op.API == api {
			table = append(table, op)
		}
	}
	return table
}
