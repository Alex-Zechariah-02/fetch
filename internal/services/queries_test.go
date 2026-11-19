// The query parameters each OpenAPI contract declares are the ones its
// service accepts: the contract text is read per path and every declared
// parameter is sent to the real handler, which must answer it, refuse an
// undeclared one and refuse a request without a required one.

package services

import (
	"maps"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// queryCase is one contract path: the service that answers it, a caller it
// serves, and a valid value for each query parameter its handler reads.
type queryCase struct {
	service, path, subject, roles string
	params                        url.Values
	required                      []string
}

func TestContractsDeclareQueries(t *testing.T) {
	t.Parallel()
	inventory, orders := newCommerce(t)
	server := httptest.NewServer(orders)
	t.Cleanup(server.Close)
	reports, err := New(Config{Name: "reports", Keys: testKeys("reports"), OrdersURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	support, err := New(Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders})
	if err != nil {
		t.Fatal(err)
	}
	services := map[string]*Service{"inventory": inventory, "orders": orders, "reports": reports, "support": support}
	dates, _ := url.ParseQuery(seedWindow())
	for _, tc := range []queryCase{
		{"inventory", "/inventory/merchants", "", "", url.Values{"section": {"food"}, "category": {"nasi-lemak"}, "limit": {"5"}, "after": {"MER-001"}}, nil},
		{"inventory", "/inventory/search", "", "", url.Values{"q": {"nasi"}, "section": {"food"}}, []string{"q"}},
		{"orders", "/orders", "support-01", "SUPPORT", url.Values{"status": {"delivered"}, "limit": {"5"}, "after": {"ORD-1001"}}, nil},
		{"orders", "/orders/merchant", "merchant-001", "MERCHANT", url.Values{"status": {"delivered"}, "limit": {"5"}, "after": {"ORD-1001"}}, nil},
		{"orders", "/orders/mine", "cust-001", "CUSTOMER", url.Values{"limit": {"5"}, "after": {"ORD-1001"}}, nil},
		{"orders", "/orders/quote", "cust-001", "CUSTOMER", url.Values{"merchant": {"MER-001"}}, []string{"merchant"}},
		{"reports", "/reports/merchant", "merchant-001", "MERCHANT", dates, nil},
		{"reports", "/reports/sales", "ops-01", "OPERATIONS", dates, nil},
		{"reports", "/reports/summary", "ops-01", "OPERATIONS", dates, nil},
		{"reports", "/reports/top-items", "ops-01", "OPERATIONS", url.Values{"from": dates["from"], "to": dates["to"], "limit": {"5"}}, nil},
		{"support", "/support/queue", "support-01", "SUPPORT", url.Values{"status": {"open"}, "limit": {"5"}, "after": {"TKT-1001"}}, nil},
	} {
		declared, required := contractQueries(t, tc.service, tc.path)
		if !slices.Equal(declared, sortedKeys(tc.params)) || !slices.Equal(required, slices.Sorted(slices.Values(tc.required))) {
			t.Errorf("%s: the contract declares %v (required %v); the handler reads %v (required %v)", tc.path, declared, required, sortedKeys(tc.params), tc.required)
		}
		s := services[tc.service]
		send := func(q url.Values) (int, string) {
			w := serviceRequest(s, "GET", tc.path+"?"+q.Encode(), "", tc.subject, tc.roles, "")
			return w.Code, w.Body.String()
		}
		if status, body := send(tc.params); status != 200 {
			t.Errorf("%s with every declared parameter: %d %s", tc.path, status, body)
		}
		minimal := url.Values{}
		for _, name := range tc.required {
			minimal.Set(name, tc.params.Get(name))
		}
		if status, body := send(minimal); status != 200 {
			t.Errorf("%s with only the required parameters: %d %s", tc.path, status, body)
		}
		minimal.Set("undeclared", "1")
		if status, body := send(minimal); status != 400 || !strings.Contains(body, "invalid_query") {
			t.Errorf("%s with an undeclared parameter: %d %s", tc.path, status, body)
		}
		for _, name := range tc.required {
			partial := url.Values{}
			for other, values := range tc.params {
				if other != name {
					partial[other] = values
				}
			}
			if status, body := send(partial); status != 400 {
				t.Errorf("%s without required %s: %d %s", tc.path, name, status, body)
			}
		}
	}
}

// TestStockContractDeclaresZero: the gateway schema cannot exclude one value,
// so the contract's delta description states the refusal the service makes.
func TestStockContractDeclaresZero(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "inventory.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, delta, _ := strings.Cut(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n                delta:\n")
	line, _, _ := strings.Cut(delta, "\n")
	if !strings.HasPrefix(line, "                  description: The stock change; zero is refused (422 invalid_change)") {
		t.Error("the stock.adjust contract does not say that a zero delta is refused")
	}
	if !strings.Contains(line, "below the units reserved for orders (409 insufficient_stock)") {
		t.Error("the stock.adjust contract does not say that a decrease below the reserved units is refused")
	}
	inventory, err := New(Config{Name: "inventory", Keys: testKeys("inventory")})
	if err != nil {
		t.Fatal(err)
	}
	// ITM-501 has a stock count, so only the zero can be refused.
	w := serviceRequest(inventory, "PATCH", "/inventory/stock/ITM-501", `{"delta":0}`, "ops-01", "OPERATIONS", "")
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"field":"delta"`) {
		t.Errorf("a zero delta: %d %s", w.Code, w.Body)
	}
}

var (
	parameterItem = regexp.MustCompile(`(?m)^        - `)
	parameterName = regexp.MustCompile(`(?m)^ {10}name: (\S+)$`)
)

// contractQueries returns the sorted names of the query parameters declared
// on GET path in service's contract, and the sorted names of the required ones.
func contractQueries(t *testing.T, service, path string) (declared, required []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", service+".openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, block, found := strings.Cut(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n  "+path+":\n    get:\n")
	if !found {
		t.Fatalf("%s: no GET in the %s contract", path, service)
	}
	block = block[:sectionEnd(block, 4)]
	_, block, found = strings.Cut(block, "      parameters:\n")
	if !found {
		return nil, nil
	}
	block = block[:sectionEnd(block, 6)]
	for _, item := range parameterItem.Split(block, -1)[1:] {
		name := parameterName.FindStringSubmatch(item)
		if !strings.Contains(item, "in: query\n") || name == nil {
			continue
		}
		declared = append(declared, name[1])
		if strings.Contains(item, "\n          required: true\n") {
			required = append(required, name[1])
		}
	}
	slices.Sort(declared)
	slices.Sort(required)
	return declared, required
}

// sectionEnd returns where text stops being nested deeper than indent
// spaces: the first line indented by indent or less, or the end of text.
func sectionEnd(text string, indent int) int {
	end := 0
	for line := range strings.SplitAfterSeq(text, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if strings.TrimSpace(trimmed) != "" && len(line)-len(trimmed) <= indent {
			return end
		}
		end += len(line)
	}
	return end
}

func sortedKeys(values url.Values) []string {
	return slices.Sorted(maps.Keys(values))
}
