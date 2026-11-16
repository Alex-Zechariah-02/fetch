// Concurrent changes: reservation compensation, two checkouts or rider
// claims at once, and a cancel racing an accept, each with its interleaving
// forced.

package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReservationTimeoutCompensation(t *testing.T) {
	inventory := newService(t, Config{Name: "inventory", Secret: testSecret})
	var refuseRelease atomic.Bool
	refuseRelease.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Key") != string(testSecret) || r.Header.Get("Authorization") != "" {
			t.Error("internal identity was not the service key")
		}
		if r.Method == "DELETE" && refuseRelease.Load() {
			w.WriteHeader(503)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/internal/reservations" {
			// Apply a real reservation, then withhold its HTTP acknowledgement.
			recorded := httptest.NewRecorder()
			inventory.ServeHTTP(recorded, r)
			time.Sleep(100 * time.Millisecond)
			for name, values := range recorded.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorded.Code)
			w.Write(recorded.Body.Bytes())
			return
		}
		inventory.ServeHTTP(w, r)
	}))
	defer server.Close()
	orderService, err := New(Config{Name: "orders", Secret: testSecret, InventoryURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	orderService.data.(*orders).inventory.http.Timeout = 25 * time.Millisecond
	w := serviceRequest(orderService, "POST", "/orders", checkoutBody, "cust-003", "CUSTOMER", "checkout-timeout-01")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "inventory_unavailable") {
		t.Fatalf("timeout: %d %s", w.Code, w.Body)
	}
	if len(orderService.data.(*orders).list) != len(seedOrders()) || orderService.data.(*orders).wallets["cust-003"] != 10000 {
		t.Fatal("uncertain reservation created or charged an order")
	}
	refuseRelease.Store(false)
	serviceRequest(orderService, "GET", "/orders/wallet", "", "cust-003", "CUSTOMER", "")
	w = serviceRequest(inventory, "GET", "/inventory/stock/ITM-501", "", "ops-01", "OPERATIONS", "")
	if !strings.Contains(w.Body.String(), `"reserved":0`) {
		t.Fatalf("orphan reservation survived recovery: %s", w.Body)
	}
	w = serviceRequest(orderService, "POST", "/orders", checkoutBody, "cust-003", "CUSTOMER", "checkout-timeout-01")
	if w.Code != 503 {
		t.Fatalf("failed checkout identity unexpectedly re-applied: %d %s", w.Code, w.Body)
	}
}

// together runs each call in its own goroutine, all released at once, and
// waits for them.
func together(calls ...func()) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, call := range calls {
		wg.Go(func() {
			<-start
			call()
		})
	}
	close(start)
	wg.Wait()
}

// overlapped is newCommerce whose Inventory holds each reservation until n
// have arrived, so n checkouts all reserve before any reads the wallet.
func overlapped(t *testing.T, n int) (*Service, *Service) {
	t.Helper()
	inventory := newService(t, Config{Name: "inventory", Secret: testSecret})
	var arrived atomic.Int32
	all := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/internal/reservations" {
			if arrived.Add(1) == int32(n) {
				close(all)
			}
			select {
			case <-all:
			case <-time.After(5 * time.Second):
				t.Error("the reservations did not overlap")
			}
		}
		inventory.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return inventory, newService(t, Config{Name: "orders", Secret: testSecret, InventoryURL: server.URL})
}

func TestConcurrentWalletAndRiderClaims(t *testing.T) {
	for _, wallet := range []bool{true, false} {
		t.Run(map[bool]string{true: "wallet", false: "rider"}[wallet], func(t *testing.T) {
			inventory, orders := overlapped(t, 2)
			statuses := make([]int, 2)
			claim := func(i int) func() {
				return func() {
					if wallet {
						statuses[i] = serviceRequest(orders, "POST", "/orders", checkoutBody, "cust-003", "CUSTOMER", []string{"parallel-wallet-first", "parallel-wallet-second"}[i]).Code
					} else {
						statuses[i] = serviceRequest(orders, "POST", "/orders/pickup/ORD-1004", "", []string{"rider-01", "rider-02"}[i], "RIDER", "").Code
					}
				}
			}
			together(claim(0), claim(1))
			wins, conflicts := 0, 0
			for _, code := range statuses {
				if code == 200 || code == 201 {
					wins++
				} else if code == 409 {
					conflicts++
				} else {
					t.Errorf("unexpected status %d", code)
				}
			}
			if wins != 1 || conflicts != 1 {
				t.Fatalf("non-atomic changes: %v", statuses)
			}
			if wallet {
				w := serviceRequest(inventory, "GET", "/inventory/stock/ITM-501", "", "ops-01", "OPERATIONS", "")
				if !strings.Contains(w.Body.String(), `"reserved":2`) {
					t.Fatalf("losing purchase retained stock: %s", w.Body)
				}
			}
		})
	}
}

func TestCancelAcceptRace(t *testing.T) {
	for range 15 {
		_, orders := newCommerce(t)
		statuses := make([]int, 2)
		together(func() {
			statuses[0] = serviceRequest(orders, "POST", "/orders/cancel/ORD-1001", "", "cust-001", "CUSTOMER", "").Code
		}, func() {
			statuses[1] = serviceRequest(orders, "POST", "/orders/accept/ORD-1001", "", "merchant-001", "MERCHANT", "").Code
		})
		if !(statuses[0] == 200 && statuses[1] == 409 || statuses[0] == 409 && statuses[1] == 200) {
			t.Fatalf("cancel/accept race: %v", statuses)
		}
	}
}
