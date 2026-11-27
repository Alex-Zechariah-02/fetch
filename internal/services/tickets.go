// Ticket lists and order references of the Support API: the lists page,
// newest first, and give each ticket's summary (its last message cut to a
// preview); a ticket's messages come only from its own page.

package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"time"
	"unicode/utf8"
)

// previewRunes bounds a summary's preview of the last message.
const previewRunes = 120

// TicketSummary is a ticket in a list: no messages, their count and a
// preview of the last one.
type TicketSummary struct {
	ID           string    `json:"id"`
	Customer     string    `json:"customer"`
	CustomerName string    `json:"customer_name"`
	Order        *string   `json:"order"`
	RequestRef   *string   `json:"request_ref"`
	Subject      string    `json:"subject"`
	Status       string    `json:"status"`
	MessageCount int       `json:"message_count"`
	Preview      string    `json:"preview"`
	UpdatedAt    time.Time `json:"updated_at"`
	CreatedAt    time.Time `json:"created_at"`
}

func summarise(ticket Ticket) TicketSummary {
	summary := TicketSummary{ID: ticket.ID, Customer: ticket.Customer, CustomerName: ticket.CustomerName, Order: ticket.Order, RequestRef: ticket.RequestRef, Subject: ticket.Subject, Status: ticket.Status, MessageCount: len(ticket.Messages), UpdatedAt: ticket.CreatedAt, CreatedAt: ticket.CreatedAt}
	if n := len(ticket.Messages); n > 0 {
		last := ticket.Messages[n-1]
		summary.Preview, summary.UpdatedAt = preview(last.Body), last.At
	}
	return summary
}

// preview cuts body to previewRunes characters.
func preview(body string) string {
	if utf8.RuneCountInString(body) <= previewRunes {
		return body
	}
	return string([]rune(body)[:previewRunes]) + "…"
}

// list answers /support/mine (a customer's tickets) and /support/queue
// (every ticket, for support agents), a page at a time.
func (d *support) list(r *http.Request, subject string) result {
	q, ok := query(r, "status", "limit", "after")
	if !ok {
		return invalidQuery()
	}
	mine := r.URL.Path == "/support/mine"
	if mine {
		if q.Has("status") {
			return invalidQuery()
		}
		if !hasRole(r, "CUSTOMER") {
			return notFound()
		}
	} else if !hasRole(r, "SUPPORT") {
		return notFound()
	}
	status := q.Get("status")
	if status != "" && !slices.Contains([]string{"open", "answered", "resolved"}, status) {
		return invalidQuery()
	}
	n, after, ok := pagination(q, boardPage)
	if !ok {
		return invalidQuery()
	}
	start := len(d.tickets) - 1
	if after != "" {
		position := slices.IndexFunc(d.tickets, func(t Ticket) bool { return t.ID == after })
		if position < 0 {
			return invalidQuery()
		}
		start = position - 1
	}
	// One ticket past the page shows whether another page follows.
	items := []TicketSummary{}
	for i := start; i >= 0 && len(items) <= n; i-- {
		ticket := d.tickets[i]
		if mine && ticket.Customer != subject || status != "" && ticket.Status != status {
			continue
		}
		items = append(items, summarise(ticket))
	}
	response := map[string]any{"items": items[:min(n, len(items))]}
	if len(items) > n {
		response["next"] = items[n-1].ID
	}
	return result{status: 200, body: response}
}

// ownOrder checks with Orders that order is one of subject's, and returns
// the refusal when it is not or Orders cannot say.
func (d *support) ownOrder(ctx context.Context, subject, order string) *result {
	var status int
	var body []byte
	var err error
	d.outside(ctx, func() {
		status, body, err = d.orders.call(ctx, "GET", "/internal/orders/"+url.PathEscape(order), nil, "")
	})
	var answer struct {
		Order struct {
			Customer string `json:"customer"`
		} `json:"order"`
	}
	switch {
	case err != nil || status >= http.StatusInternalServerError:
		refused := failure(http.StatusServiceUnavailable, "orders_unavailable", "Orders could not confirm the order. Try again later.", "")
		return &refused
	case status == http.StatusOK && json.Unmarshal(body, &answer) == nil && answer.Order.Customer == subject:
		return nil
	case status == http.StatusOK || status == http.StatusNotFound:
		// Another customer's order is refused like one that does not exist.
		refused := failure(http.StatusUnprocessableEntity, "invalid_order", "Choose one of your own orders.", "order")
		return &refused
	default:
		refused := failure(http.StatusServiceUnavailable, "orders_unavailable", "Orders could not confirm the order. Try again later.", "")
		return &refused
	}
}
