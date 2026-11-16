// The service lock is not held while another service is called: one test
// keeps Inventory waiting and checks what Orders still does meanwhile.

package services

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A call to another service does not hold the service lock: while Inventory
// keeps a checkout and a quote waiting, Orders answers a read. A second
// request with the waiting checkout's key makes no second reservation; it
// waits and replays the first answer, and one order is placed.
func TestServiceCallsReleaseLock(t *testing.T) {
	inventory := newService(t, Config{Name: "inventory", Secret: testSecret})
	held := make(chan struct{})
	arrived := make(chan struct{}, 8)
	var reservations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/internal/reservations" {
			reservations.Add(1)
		}
		arrived <- struct{}{}
		<-held
		inventory.ServeHTTP(w, r)
	}))
	defer server.Close()
	orderService, err := New(Config{Name: "orders", Secret: testSecret, InventoryURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	reached := func(what string) {
		t.Helper()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s never reached Inventory", what)
		}
	}
	const key = "lock-released-checkout"
	checkout := func() *httptest.ResponseRecorder {
		return serviceRequest(orderService, "POST", "/orders", checkoutBody, "cust-003", "CUSTOMER", key)
	}

	var first, quote, second *httptest.ResponseRecorder
	var wg sync.WaitGroup
	wg.Go(func() { first = checkout() })
	reached("the checkout")
	wg.Go(func() {
		quote = serviceRequest(orderService, "GET", "/orders/quote?merchant=MER-001", "", "cust-003", "CUSTOMER", "")
	})
	reached("the quote")
	wg.Go(func() { second = checkout() })

	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- serviceRequest(orderService, "GET", "/orders/wallet", "", "cust-003", "CUSTOMER", "")
	}()
	select {
	case w := <-answered:
		if w.Code != 200 {
			t.Fatalf("wallet while Inventory waits: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Orders answered nothing while a call to Inventory waited")
	}

	close(held)
	wg.Wait()
	if first.Code != 201 || quote.Code != 200 {
		t.Fatalf("after Inventory answered: checkout %d %s, quote %d %s", first.Code, first.Body, quote.Code, quote.Body)
	}
	if second.Code != 201 || second.Body.String() != first.Body.String() {
		t.Fatalf("the same key while the first waited: %d %s", second.Code, second.Body)
	}
	if n := reservations.Load(); n != 1 {
		t.Fatalf("%d reservations for one checkout key", n)
	}
	if n := len(orderService.data.(*orders).list); n != len(seedOrders())+1 {
		t.Fatalf("%d orders, want one more than the seed", n)
	}
}
