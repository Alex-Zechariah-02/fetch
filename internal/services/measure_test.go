// Measurement mode: receipts become uncapped counts and the load accounts
// exist, while the default mode keeps its newest receipts and its seed.

package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeasureCountsReceiptsWithoutCap(t *testing.T) {
	orders, err := New(Config{Name: "orders", Secret: testSecret, InventoryURL: "http://127.0.0.1:9", Measure: true})
	if err != nil {
		t.Fatal(err)
	}
	for range maxReceipts + 1 {
		if w := serviceRequest(orders, "GET", "/orders/wallet", "", "load-1000", "CUSTOMER", ""); w.Code != 200 {
			t.Fatalf("wallet of a load account: status %d %s", w.Code, w.Body)
		}
	}
	serviceRequest(orders, "GET", "/nowhere", "", "", "", "")
	w := httptest.NewRecorder()
	orders.Control(testSecret).ServeHTTP(w, controlRequest("GET", "/receipts"))
	var got counts
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Mode != "count" || got.Total != maxReceipts+2 || got.ByStatus[200] != maxReceipts+1 || got.ByStatus[404] != 1 {
		t.Fatalf("receipt counts: %s", w.Body)
	}
	orders.Control(testSecret).ServeHTTP(httptest.NewRecorder(), controlRequest("POST", "/reset"))
	w = httptest.NewRecorder()
	orders.Control(testSecret).ServeHTTP(w, controlRequest("GET", "/receipts"))
	got = counts{}
	if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Total != 0 || len(got.ByStatus) != 0 {
		t.Fatalf("counts after reset: %s", w.Body)
	}
}

// A service that has answered more than maxReceipts requests still answers:
// it holds the newest ones in order, numbered from the reset, and reports how
// many older ones it let go.
func TestReceiptsKeepNewest(t *testing.T) {
	support, err := New(Config{Name: "support", Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	const extra = 3
	for range maxReceipts + extra {
		if w := serviceRequest(support, "GET", "/nowhere", "", "", "", ""); w.Code != 404 {
			t.Fatalf("a request past the receipt limit: status %d %s", w.Code, w.Body)
		}
	}
	var got struct {
		Receipts []Receipt `json:"receipts"`
		Dropped  int       `json:"dropped"`
	}
	w := httptest.NewRecorder()
	support.Control(testSecret).ServeHTTP(w, controlRequest("GET", "/receipts"))
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Receipts) != maxReceipts || got.Dropped != extra {
		t.Fatalf("receipts held %d, dropped %d (%v)", len(got.Receipts), got.Dropped, err)
	}
	for i, receipt := range got.Receipts {
		if receipt.Seq != extra+1+i {
			t.Fatalf("receipt %d has seq %d, want %d", i, receipt.Seq, extra+1+i)
		}
	}
	support.Control(testSecret).ServeHTTP(httptest.NewRecorder(), controlRequest("POST", "/reset"))
	serviceRequest(support, "GET", "/nowhere", "", "", "", "")
	if len(support.receipts) != 1 || support.receipts[0].Seq != 1 || support.dropped != 0 {
		t.Fatalf("after reset: %d receipts, first seq %d, dropped %d", len(support.receipts), support.receipts[0].Seq, support.dropped)
	}
}

func TestLoadAccountsOnlyInMeasureMode(t *testing.T) {
	plain, _, settings := accountService(t)
	measured, err := New(Config{Name: "accounts", Secret: testSecret, SigningSettingsFile: settings, Measure: true})
	if err != nil {
		t.Fatal(err)
	}
	login := `{"email":"load0001@fetch.test","password":"` + demoPassword + `"}`
	if w := serviceRequest(measured, "POST", "/accounts/login", login, "", "", ""); w.Code != 200 {
		t.Fatalf("load account in measurement mode: status %d %s", w.Code, w.Body)
	}
	if w := serviceRequest(plain, "POST", "/accounts/login", login, "", "", ""); w.Code != 401 {
		t.Fatalf("load account outside measurement mode: status %d", w.Code)
	}
}

// controlRequest is an authenticated request to a service's control listener.
func controlRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+string(testSecret))
	return r
}

// A measurement run keeps the seed orders and the newest placed ones and
// forgets the oldest identities; outside measurement mode nothing is dropped.
func TestMeasureBoundsData(t *testing.T) {
	place := func(d *orders, n int) {
		for range n {
			id := fmt.Sprintf("ORD-%04d", d.next)
			d.list = append(d.list, Order{ID: id})
			d.reservations[id] = "key-" + id
			d.next++
			d.trim()
		}
	}
	run := &orders{measure: true}
	run.reset()
	seed := len(run.list)
	place(run, 2*measureOrders)
	first, last := run.list[seed].ID, run.list[len(run.list)-1].ID
	if len(run.list) != seed+measureOrders || len(run.reservations) != measureOrders ||
		first != fmt.Sprintf("ORD-%04d", 1005+measureOrders) || last != fmt.Sprintf("ORD-%04d", 1005+2*measureOrders-1) ||
		run.list[0].ID != seedOrders()[0].ID {
		t.Fatalf("measured run holds %d orders (%s to %s), %d reservations", len(run.list), first, last, len(run.reservations))
	}
	plain := &orders{}
	plain.reset()
	place(plain, 2*measureOrders)
	if len(plain.list) != seed+2*measureOrders {
		t.Fatalf("default mode dropped orders: %d", len(plain.list))
	}

	keys := arrivals{limit: 2}
	var forgotten []string
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		forgotten = append(forgotten, keys.add(key)...)
	}
	if strings.Join(forgotten, "") != "ab" || strings.Join(keys.keys, "") != "cde" {
		t.Fatalf("forgotten %v, kept %v", forgotten, keys.keys)
	}
	if none := measured(false); none.add("a") != nil || len(none.keys) != 0 {
		t.Fatal("a service outside measurement mode remembers keys")
	}
}
