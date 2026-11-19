// The Support API: its contract answers, its ticket and message bounds and
// the query parameter its contract declares.

package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupportContract(t *testing.T) {
	_, orders := newCommerce(t)
	s := supportWith(t, orders)
	for _, tc := range []struct {
		method, path, body, subject, roles, contains string
		status                                       int
	}{
		{"GET", "/support/mine", "", "cust-002", "CUSTOMER", "TKT-1001", 200},
		{"GET", "/support/queue?status=open", "", "support-01", "SUPPORT", "TKT-1001", 200},
		{"GET", "/support/ticket/TKT-1001", "", "cust-001", "CUSTOMER", "not_found", 404},
		{"GET", "/support/ticket/TKT-1001", "", "cust-002", "CUSTOMER", "Missing item", 200},
		{"POST", "/support/reply/TKT-1001", `{"message":"We are checking this for you."}`, "support-01", "SUPPORT", `"status":"answered"`, 200},
		{"POST", "/support/reply/TKT-1001", `{"message":"Thank you for checking."}`, "cust-002", "CUSTOMER", `"status":"open"`, 200},
		{"POST", "/support/resolve/TKT-1001", "", "support-01", "SUPPORT", `"status":"resolved"`, 200},
		{"POST", "/support/reply/TKT-1001", `{"message":"Another question"}`, "cust-002", "CUSTOMER", "invalid_transition", 409},
		{"POST", "/support/tickets", `{"subject":"Delivery question","message":"Where is my delivery?","order":"ORD-1001","request_ref":"0123456789abcdef"}`, "cust-001", "CUSTOMER", "TKT-1002", 201},
		{"GET", "/support/queue?status=bad", "", "support-01", "SUPPORT", "invalid_query", 400},
		{"GET", "/support/mine?status=open", "", "cust-001", "CUSTOMER", "invalid_query", 400},
		// Another customer's order is refused like one that does not exist.
		{"POST", "/support/tickets", `{"subject":"Delivery question","message":"Where is it?","order":"ORD-1002"}`, "cust-001", "CUSTOMER", "invalid_order", 422},
		{"POST", "/support/tickets", `{"subject":"Delivery question","message":"Where is it?","order":"ORD-9999"}`, "cust-001", "CUSTOMER", "invalid_order", 422},
		{"POST", "/support/tickets", `{"subject":"tiny","message":"Hello"}`, "cust-001", "CUSTOMER", "invalid_request", 400},
		{"POST", "/support/reply/TKT-1002", `{"message":""}`, "cust-001", "CUSTOMER", "invalid_request", 400},
	} {
		w := serviceRequest(s, tc.method, tc.path, tc.body, tc.subject, tc.roles, "")
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) || w.Header().Get("X-Service") != "support" {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body)
		}
	}
	w := serviceRequest(s, "GET", "/support/ticket/TKT-1002", "", "cust-001", "CUSTOMER", "")
	var body map[string]map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body["ticket"]) != 9 {
		t.Fatalf("ticket fields: %s", w.Body)
	}
	// Staff read names, not account IDs: the ticket and each message carry
	// the seed user's display name.
	var named struct {
		Ticket struct {
			CustomerName string `json:"customer_name"`
			Messages     []struct {
				AuthorName string `json:"author_name"`
			} `json:"messages"`
		} `json:"ticket"`
	}
	if json.Unmarshal(w.Body.Bytes(), &named) != nil || named.Ticket.CustomerName != "Customer 1" || len(named.Ticket.Messages) == 0 || named.Ticket.Messages[0].AuthorName != "Customer 1" {
		t.Fatalf("ticket names: %s", w.Body)
	}
}

// The ticket lists page, newest first, and give summaries: a preview of the
// last message, never the messages themselves.
func TestSupportListsPage(t *testing.T) {
	s := newService(t, Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders})
	for i := range 3 {
		body := fmt.Sprintf(`{"subject":"Question %d","message":"%s"}`, i, strings.Repeat("m", 200))
		if w := serviceRequest(s, "POST", "/support/tickets", body, "cust-001", "CUSTOMER", ""); w.Code != 201 {
			t.Fatalf("ticket %d: %d %s", i, w.Code, w.Body)
		}
	}
	var page struct {
		Items []map[string]json.RawMessage `json:"items"`
		Next  string                       `json:"next"`
	}
	w := serviceRequest(s, "GET", "/support/queue?limit=2", "", "support-01", "SUPPORT", "")
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 2 || page.Next != "TKT-1003" || string(page.Items[0]["id"]) != `"TKT-1004"` {
		t.Fatalf("first page: %s", w.Body)
	}
	if _, found := page.Items[0]["messages"]; found || len(page.Items[0]["preview"]) > 130*3 || string(page.Items[0]["message_count"]) != "1" {
		t.Fatalf("a list item is not a summary: %s", w.Body)
	}
	w = serviceRequest(s, "GET", "/support/queue?limit=2&after="+page.Next, "", "support-01", "SUPPORT", "")
	page.Next = ""
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 2 || page.Next != "" || string(page.Items[1]["id"]) != `"TKT-1001"` {
		t.Fatalf("second page: %s", w.Body)
	}
}

// The Support API keeps the newest keptTickets tickets and at most
// maxMessages messages in one ticket.
func TestSupportBounds(t *testing.T) {
	t.Parallel()
	s, err := New(Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders})
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxMessages - 1 {
		if w := serviceRequest(s, "POST", "/support/reply/TKT-1001", `{"message":"More detail."}`, "cust-002", "CUSTOMER", ""); w.Code != 200 {
			t.Fatalf("reply %d: %d %s", i+2, w.Code, w.Body)
		}
	}
	if w := serviceRequest(s, "POST", "/support/reply/TKT-1001", `{"message":"One more."}`, "cust-002", "CUSTOMER", ""); w.Code != 409 || !strings.Contains(w.Body.String(), "ticket_full") {
		t.Fatalf("reply past the message limit: %d %s", w.Code, w.Body)
	}
	for i := range keptTickets {
		if w := serviceRequest(s, "POST", "/support/tickets", `{"subject":"Question","message":"Hello"}`, "cust-001", "CUSTOMER", ""); w.Code != 201 {
			t.Fatalf("ticket %d: %d %s", i, w.Code, w.Body)
		}
	}
	tickets := s.data.(*support).tickets
	if len(tickets) != keptTickets || tickets[0].ID != "TKT-1002" || tickets[len(tickets)-1].ID != "TKT-2001" {
		t.Fatalf("kept %d tickets, %s to %s", len(tickets), tickets[0].ID, tickets[len(tickets)-1].ID)
	}
}

// The queue's status filter is declared in the contract with the values the
// handler accepts.
func TestSupportContractDeclaresStatus(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "support.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, queue, found := strings.Cut(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n  /support/queue:\n")
	queue, _, _ = strings.Cut(queue, "\n  /")
	for _, want := range []string{" in: query\n          name: status\n", "- open\n", "- answered\n", "- resolved\n"} {
		if !found || !strings.Contains(queue, want) {
			t.Errorf("the /support/queue contract lacks %q", want)
		}
	}
}
