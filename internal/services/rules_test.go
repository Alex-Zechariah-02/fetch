// Route matching for wildcard targets: a prefix ending in "/*" covers only
// paths strictly longer than the prefix before "*".

package services

import "testing"

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
