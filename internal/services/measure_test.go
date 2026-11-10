// Measurement mode: receipts become uncapped counts and the load accounts
// exist, while the default mode keeps its capped list and its seed.

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
