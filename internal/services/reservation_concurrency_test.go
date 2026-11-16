// Concurrent reservations and checkouts: one reservation of the last stock
// wins, a release returns it, and a replayed checkout places one order, one
// reservation and one debit, as the stock, orders and receipts show.

package services

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// receiptsOf counts s's receipts with target path, by status.
func receiptsOf(s *Service, path string) map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	by := map[int]int{}
	for _, receipt := range s.kept() {
		if receipt.Target == path {
			by[receipt.Status]++
		}
	}
	return by
}

func reserveRequest(s *Service, method, path, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Service-Key", string(testSecret))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestReservationConcurrencyAndLatePrepare(t *testing.T) {
	s := newService(t, Config{Name: "inventory", Secret: testSecret})
	body := `{"merchant":"MER-005","items":[{"item":"ITM-502","quantity":4},{"item":"ITM-502","quantity":4}]}`
	statuses := make([]int, 2)
	reserve := func(i int) func() {
		return func() {
			statuses[i] = reserveRequest(s, "POST", "/internal/reservations", body, fmt.Sprintf("reservation-race-%d", i)).Code
		}
	}
	together(reserve(0), reserve(1))
	if !(statuses[0] == 200 && statuses[1] == 409 || statuses[0] == 409 && statuses[1] == 200) {
		t.Fatalf("oversell or duplicate-line undercount: %v", statuses)
	}
	if s.data.(*inventory).item("ITM-502").Reserved != 8 {
		t.Fatal("duplicate lines did not reserve their total quantity")
	}
	if got := receiptsOf(s, "/internal/reservations"); got[200] != 1 || got[409] != 1 {
		t.Fatalf("reservation receipts %v, want one 200 and one 409", got)
	}
	winner := fmt.Sprintf("reservation-race-%d", map[bool]int{true: 0, false: 1}[statuses[0] == 200])
	if w := reserveRequest(s, "DELETE", "/internal/reservations/"+winner, "", winner); w.Code != 200 || s.data.(*inventory).item("ITM-502").Reserved != 0 {
		t.Fatalf("release of the winner: %d, %d still reserved", w.Code, s.data.(*inventory).item("ITM-502").Reserved)
	}
	key := "reservation-late-prepare"
	if w := reserveRequest(s, "DELETE", "/internal/reservations/"+key, "", key); w.Code != 200 {
		t.Fatalf("release before prepare: %d", w.Code)
	}
	if w := reserveRequest(s, "POST", "/internal/reservations", body, key); w.Code != 409 {
		t.Fatalf("late prepare survived the release tombstone: %d", w.Code)
	}
}

func TestConcurrentCheckoutReplayAndScope(t *testing.T) {
	stockService, orderService := newCommerce(t)
	responses := make([]*httptest.ResponseRecorder, 6)
	calls := make([]func(), len(responses))
	for i := range calls {
		calls[i] = func() {
			responses[i] = serviceRequest(orderService, "POST", "/orders", checkoutBody, "cust-003", "CUSTOMER", "concurrent-same-checkout")
		}
	}
	together(calls...)
	for _, response := range responses {
		if response.Code != 201 || response.Body.String() != responses[0].Body.String() {
			t.Fatal("concurrent checkout did not replay the frozen first result")
		}
	}
	if stockService.data.(*inventory).item("ITM-501").Reserved != 2 || orderService.data.(*orders).wallets["cust-003"] != 4620 {
		t.Fatal("replay duplicated stock or wallet effects")
	}
	seeded := len(seedOrders())
	if placed := len(orderService.data.(*orders).list) - seeded; placed != 1 {
		t.Fatalf("six replays placed %d orders", placed)
	}
	if got := receiptsOf(stockService, "/internal/reservations"); got[200] != 1 || len(got) != 1 {
		t.Fatalf("Inventory reservation receipts %v, want one 200", got)
	}
	if got := receiptsOf(orderService, "/orders"); got[201] != 6 || len(got) != 1 {
		t.Fatalf("checkout receipts %v, want six 201", got)
	}
	// Another account has an independent checkout identity even with the same key.
	body := strings.Replace(checkoutBody, `"wallet"`, `"cash"`, 1)
	if w := serviceRequest(orderService, "POST", "/orders", body, "cust-001", "CUSTOMER", "concurrent-same-checkout"); w.Code != 201 {
		t.Fatalf("checkout key was shared between accounts: %d", w.Code)
	}
	if placed := len(orderService.data.(*orders).list) - seeded; placed != 2 || stockService.data.(*inventory).item("ITM-501").Reserved != 4 {
		t.Fatalf("the other account's checkout placed %d orders in all, %d reserved", placed, stockService.data.(*inventory).item("ITM-501").Reserved)
	}
}
