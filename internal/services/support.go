// The Support API: customers open tickets and reply, support agents read
// the queue, answer and resolve. Tickets live in memory, the newest
// keptTickets of them, each with at most maxMessages messages. A ticket's
// order reference is checked with Orders once, at creation: it must be one
// of the customer's own orders.

package services

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"
)

type Message struct {
	From       string    `json:"from"`
	Author     string    `json:"author"`
	AuthorName string    `json:"author_name"`
	Body       string    `json:"body"`
	At         time.Time `json:"at"`
}
type Ticket struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	// CustomerName is the customer's display name, so staff need not read
	// account IDs.
	CustomerName string    `json:"customer_name"`
	Order        *string   `json:"order"`
	RequestRef   *string   `json:"request_ref"`
	Subject      string    `json:"subject"`
	Status       string    `json:"status"`
	Messages     []Message `json:"messages"`
	CreatedAt    time.Time `json:"created_at"`
}

// keptTickets bounds the tickets kept: the oldest go first, as Orders forgets
// its oldest placed orders. maxMessages ends a long conversation in a new
// ticket; together they hold the Support API under about 160 MiB at the
// largest messages.
const (
	keptTickets = 1000
	maxMessages = 20
	minSubject  = 5
	maxSubject  = 120
	maxMessage  = 2000
	orderLen    = 8
	minRef      = 16
	maxRef      = 64
)

type support struct {
	tickets []Ticket
	next    int
	orders  *serviceClient
	// outside runs the call to Orders without the service lock.
	outside func(context.Context, func())
}

func (d *support) close() { d.orders.close() }

func (d *support) reset() {
	// The day before the process started, after the seed's recent orders.
	at := seedDay.AddDate(0, 0, -1).Add(5 * time.Hour)
	order := "ORD-1002"
	d.tickets = []Ticket{{
		ID: "TKT-1001", Customer: "cust-002", CustomerName: displayName("cust-002"), Order: &order, Subject: "Missing item", Status: "open",
		Messages:  []Message{newMessage("customer", "cust-002", "One item was missing from my delivery.", at)},
		CreatedAt: at,
	}}
	d.next = 1002
}
func (d *support) snapshot() any {
	return struct {
		Tickets []Ticket `json:"tickets"`
		Next    int      `json:"next"`
	}{d.tickets, d.next}
}
func (d *support) find(id string) *Ticket {
	for i := range d.tickets {
		if d.tickets[i].ID == id {
			return &d.tickets[i]
		}
	}
	return nil
}
func seesTicket(r *http.Request, ticket Ticket) bool {
	return hasRole(r, "SUPPORT") || hasRole(r, "CUSTOMER") && ticket.Customer == r.Header.Get("X-Gateway-Subject")
}
func (d *support) handle(r *http.Request, body []byte) result {
	subject := r.Header.Get("X-Gateway-Subject")
	if subject == "" {
		return notFound()
	}
	if r.URL.Path == "/support/tickets" && r.Method == "POST" {
		if !hasRole(r, "CUSTOMER") {
			return notFound()
		}
		var request struct {
			Subject    string  `json:"subject"`
			Message    string  `json:"message"`
			Order      *string `json:"order"`
			RequestRef *string `json:"request_ref"`
		}
		if rejected := decodeBody(r, body, ticketBody, &request); rejected != nil {
			return *rejected
		}
		// The lengths bound one stored ticket; a value outside them is refused with 400.
		if !length(request.Subject, minSubject, maxSubject) || !length(request.Message, 1, maxMessage) || request.Order != nil && !length(*request.Order, orderLen, orderLen) || request.RequestRef != nil && !length(*request.RequestRef, minRef, maxRef) {
			return failure(400, "invalid_request", "Check the ticket subject, message and references.", "")
		}
		if request.Order != nil {
			if refused := d.ownOrder(r.Context(), subject, *request.Order); refused != nil {
				return *refused
			}
		}
		now := time.Now().UTC()
		ticket := Ticket{
			ID: fmt.Sprintf("TKT-%04d", d.next), Customer: subject, CustomerName: displayName(subject), Order: request.Order, RequestRef: request.RequestRef,
			Subject: request.Subject, Status: "open", Messages: []Message{newMessage("customer", subject, request.Message, now)}, CreatedAt: now,
		}
		d.next++
		if len(d.tickets) >= keptTickets {
			d.tickets = slices.Delete(d.tickets, 0, len(d.tickets)-keptTickets+1)
		}
		d.tickets = append(d.tickets, ticket)
		return result{status: 201, body: map[string]any{"ticket": ticket}, effect: "created " + ticket.ID}
	}
	if (r.URL.Path == "/support/mine" || r.URL.Path == "/support/queue") && r.Method == "GET" {
		return d.list(r, subject)
	}
	if id, ok := oneID(r.URL.Path, "/support/ticket/"); ok && r.Method == "GET" {
		if _, ok := query(r); !ok {
			return invalidQuery()
		}
		ticket := d.find(id)
		if ticket == nil || !seesTicket(r, *ticket) {
			return notFound()
		}
		return result{status: 200, body: map[string]any{"ticket": *ticket}}
	}
	if id, ok := oneID(r.URL.Path, "/support/reply/"); ok && r.Method == "POST" {
		ticket := d.find(id)
		if ticket == nil || !seesTicket(r, *ticket) {
			return notFound()
		}
		if ticket.Status == "resolved" {
			return failure(409, "invalid_transition", "This ticket is resolved. Start a new ticket for another question.", "")
		}
		if len(ticket.Messages) >= maxMessages {
			return failure(409, "ticket_full", "This ticket has reached its message limit. Start a new ticket to continue.", "")
		}
		var request struct {
			Message string `json:"message"`
		}
		if rejected := decodeBody(r, body, ticketBody, &request); rejected != nil {
			return *rejected
		}
		if !length(request.Message, 1, maxMessage) {
			return failure(400, "invalid_request", "Enter a message of one to two thousand characters.", "message")
		}
		from := "customer"
		ticket.Status = "open"
		if hasRole(r, "SUPPORT") {
			from = "agent"
			ticket.Status = "answered"
		}
		ticket.Messages = append(ticket.Messages, newMessage(from, subject, request.Message, time.Now().UTC()))
		return result{status: 200, body: map[string]any{"ticket": *ticket}, effect: "replied " + id}
	}
	if id, ok := oneID(r.URL.Path, "/support/resolve/"); ok && r.Method == "POST" {
		ticket := d.find(id)
		if ticket == nil || !hasRole(r, "SUPPORT") {
			return notFound()
		}
		if len(body) != 0 {
			return failure(400, "invalid_request", "This operation accepts no request body.", "")
		}
		ticket.Status = "resolved"
		return result{status: 200, body: map[string]any{"ticket": *ticket}, effect: "resolved " + id}
	}
	return notFound()
}

func newMessage(from, author, body string, at time.Time) Message {
	return Message{From: from, Author: author, AuthorName: displayName(author), Body: body, At: at}
}

// displayName is the seed user's name for an account ID. An unknown ID, which
// a verified token cannot normally carry, is shown as the ID itself.
func displayName(id string) string {
	if user, ok := userByID(id); ok {
		return user.Name
	}
	return id
}
