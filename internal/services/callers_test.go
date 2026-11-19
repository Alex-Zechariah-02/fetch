// Tests of the keys between services: each caller is named by its own key,
// reaches only the internal endpoints it uses, and a service starts only with
// exactly the keys it holds.

package services

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// internalCall is an internal request to s carrying key, or none when empty.
func internalCall(s *Service, method, path string, key []byte) int {
	r := httptest.NewRequest(method, path, nil)
	if key != nil {
		r.Header.Set("X-Service-Key", string(key))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Code
}

func TestInternalCallers(t *testing.T) {
	inventory := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
	orders := newService(t, Config{Name: "orders", Keys: testKeys("orders"), InventoryURL: unusedOrders})
	for _, tc := range []struct {
		name   string
		s      *Service
		method string
		path   string
		key    []byte
		status int
	}{
		{"reports reads the order list", orders, "GET", "/internal/orders", testKeyset["reports"], 200},
		{"support reads one order", orders, "GET", "/internal/orders/ORD-1001", testKeyset["support"], 200},
		{"support may not read the list", orders, "GET", "/internal/orders", testKeyset["support"], 403},
		{"reports may not read one order", orders, "GET", "/internal/orders/ORD-1001", testKeyset["reports"], 403},
		{"orders' own key is no caller of orders", orders, "GET", "/internal/orders", testKeyset["orders"], 401},
		{"the control secret is no service key", orders, "GET", "/internal/orders", testSecret, 401},
		{"no key", orders, "GET", "/internal/orders", nil, 401},
		{"orders reads a merchant", inventory, "GET", "/internal/merchants/MER-001", testKeyset["orders"], 200},
		{"reports may not call inventory", inventory, "GET", "/internal/merchants/MER-001", testKeyset["reports"], 401},
		{"support may not release a reservation", inventory, "DELETE", "/internal/reservations/reservation-none-01", testKeyset["support"], 401},
	} {
		if status := internalCall(tc.s, tc.method, tc.path, tc.key); status != tc.status {
			t.Errorf("%s: %d, want %d", tc.name, status, tc.status)
		}
	}
	// A service key opens no control listener.
	r := httptest.NewRequest("GET", "/state", nil)
	r.Header.Set("Authorization", "Bearer "+string(testKeyset["reports"]))
	w := httptest.NewRecorder()
	orders.Control(testSecret).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("a service key opened the control listener: %d", w.Code)
	}
}

func TestServiceKeysExact(t *testing.T) {
	shared := map[string][]byte{"orders": testKeyset["orders"], "reports": testKeyset["reports"], "support": testKeyset["reports"]}
	extra := testKeys("inventory")
	extra["reports"] = testKeyset["reports"]
	for name, cfg := range map[string]Config{
		"missing":     {Name: "inventory"},
		"extra":       {Name: "inventory", Keys: extra},
		"shared":      {Name: "orders", Keys: shared, InventoryURL: unusedOrders},
		"short":       {Name: "reports", Keys: map[string][]byte{"reports": []byte("short")}, OrdersURL: unusedOrders},
		"accounts":    {Name: "accounts", Keys: map[string][]byte{"orders": testKeyset["orders"]}},
		"wrong owner": {Name: "support", Keys: map[string][]byte{"reports": testKeyset["reports"]}, OrdersURL: unusedOrders},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s keys accepted", name)
		}
	}
}

func TestCommandKeys(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "control.secret")
	if err := os.WriteFile(secret, testSecret, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-service", "inventory", "-control-secret", secret},
		{"-service", "inventory", "-control-secret", secret, "-keys", dir},
	} {
		err := Command(context.Background(), "", args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "key") {
			t.Errorf("%v: %v", args, err)
		}
	}
	err := Command(context.Background(), "accounts", []string{"-control-secret", secret, "-keys", dir}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no internal calls") {
		t.Errorf("accounts with keys: %v", err)
	}
}
