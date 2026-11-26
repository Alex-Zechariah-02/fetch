// Route matching for wildcard targets: a prefix ending in "/*" covers only
// paths strictly longer than the prefix before "*".

package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWildcardPrefixAtExactLength(t *testing.T) {
	cases := []struct {
		api, method, prefix, child string
	}{
		{"inventory", "GET", "/inventory/items/", "/inventory/items/ITM-501"},
		{"inventory", "PATCH", "/inventory/items/", "/inventory/items/ITM-501"},
		{"inventory", "PATCH", "/inventory/stock/", "/inventory/stock/ITM-501"},
		{"inventory", "GET", "/inventory/merchants/", "/inventory/merchants/MER-001"},
		{"orders", "GET", "/orders/detail/", "/orders/detail/ORD-1001"},
		{"support", "GET", "/support/ticket/", "/support/ticket/TKT-1"},
	}
	for _, tc := range cases {
		if routed(tc.api, tc.method, tc.prefix) {
			t.Errorf("%s %s %s: exact wildcard prefix matched, want false", tc.api, tc.method, tc.prefix)
		}
		if !routed(tc.api, tc.method, tc.child) {
			t.Errorf("%s %s %s: path below wildcard prefix did not match, want true", tc.api, tc.method, tc.child)
		}
	}
}

func TestEachAPIBodyLimit(t *testing.T) {
	want := map[string]int64{
		"inventory": orderBody,
		"orders":    orderBody,
		"support":   ticketBody,
		"accounts":  loginBody,
		"reports":   0,
	}
	for api, limit := range want {
		if got := bodyLimit(api); got != limit {
			t.Errorf("bodyLimit(%q) = %d, want %d", api, got, limit)
		}
	}
	// Inventory accepts an internal reservation larger than its own public
	// itemBody (512) up to orderBody (4096) and refuses one byte past it.
	s := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
	call := func(body, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/internal/reservations", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Service-Key", string(testKeyset["orders"]))
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	base := `{"merchant":"MER-005","items":[{"item":"ITM-501","quantity":1}]}`
	within := strings.Repeat(" ", 1024-len(base)) + base
	if w := call(within, "body-limit-within-01"); w.Code != http.StatusOK {
		t.Fatalf("1024-byte internal reservation: status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	over := strings.Repeat(" ", orderBody+1-len(base)) + base
	if w := call(over, "body-limit-over-0001"); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d-byte internal reservation: status=%d, want 413", len(over), w.Code)
	}
}
