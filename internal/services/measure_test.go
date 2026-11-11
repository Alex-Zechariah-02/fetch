// Measurement mode: receipts become uncapped counts and the load accounts
// exist, while the default mode keeps its newest receipts and its seed.

package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
