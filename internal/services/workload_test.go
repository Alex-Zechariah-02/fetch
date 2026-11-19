// The services never limit a measured setup and answer only what their
// tables name: reads share the lock, a body is read only where one is taken,
// sign-ins hash outside the lock in bounded slots, merchant boards page,
// internal calls neither leave the loopback listener nor push out API
// receipts, and order numbers follow the seed.

package services

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Two reads run at once: a read waits for no other read.
func TestReadsShareTheLock(t *testing.T) {
	s := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
	s.mu.RLock()
	defer s.mu.RUnlock()
	done := make(chan int, 1)
	go func() {
		done <- serviceRequest(s, "GET", "/inventory/categories", "", "", "", "").Code
	}()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("read answered %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read waited for another read's lock")
	}
}

// failingBody fails the test if anything reads it.
type failingBody struct{ t *testing.T }

func (b failingBody) Read([]byte) (int, error) {
	b.t.Error("a body was read for a method that takes none")
	return 0, io.EOF
}

// A GET with a body is refused without reading it.
func TestBodyNotReadWhereNoneIsTaken(t *testing.T) {
	s := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
	r := httptest.NewRequest("GET", "/inventory/categories", io.NopCloser(failingBody{t}))
	r.ContentLength = 10
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("Connection") != "close" {
		t.Fatalf("GET with a body: %d %s", w.Code, w.Body)
	}
}

// A path the service's table does not name is not found, though a handler
// would serve it; the gateway-facing TLS listener serves no internal path.
func TestTableDecidesRoutes(t *testing.T) {
	s := newService(t, Config{Name: "orders", Keys: testKeys("orders"), InventoryURL: unusedOrders})
	if w := serviceRequest(s, "HEAD", "/orders/wallet", "", "cust-001", "CUSTOMER", ""); w.Code != 404 {
		t.Fatalf("an unlisted method was served: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/internal/orders", nil)
	r.Header.Set("X-Service-Key", string(testKeyset["reports"]))
	w := httptest.NewRecorder()
	s.external(s.api()).ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("the TLS listener served an internal path: %d %s", w.Code, w.Body)
	}
}

// With every hashing slot taken, a sign-in is refused 503 with Retry-After
// once its wait ends, and the lock is free meanwhile.
func TestSignInBusyRefused(t *testing.T) {
	s, _, _ := accountService(t)
	d := s.data.(*accounts)
	for range cap(d.hashing) {
		d.hashing <- struct{}{}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- serviceRequest(s, "POST", "/accounts/login", `{"email":"customer1@fetch.test","password":"FetchDemo2026!"}`, "", "", "")
	}()
	time.Sleep(200 * time.Millisecond)
	if w := serviceRequest(s, "GET", "/accounts/me", "", "cust-001", "CUSTOMER", ""); w.Code != 200 {
		t.Fatalf("a profile read during a sign-in's wait: %d", w.Code)
	}
	w := <-done
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || !strings.Contains(w.Body.String(), "accounts_busy") {
		t.Fatalf("sign-in with no slot: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}

// A merchant's board pages: 50 orders by default, newest first, then the
// rest after the cursor.
func TestMerchantOrdersPage(t *testing.T) {
	s := newService(t, Config{Name: "orders", Keys: testKeys("orders"), InventoryURL: unusedOrders})
	var page struct {
		Items []Order `json:"items"`
		Next  string  `json:"next"`
	}
	w := serviceRequest(s, "GET", "/orders/merchant", "", "merchant-001", "MERCHANT", "")
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != boardPage || page.Next == "" || page.Items[0].ID != "ORD-1001" {
		t.Fatalf("first page: %d items, next %q", len(page.Items), page.Next)
	}
	total := len(page.Items)
	for page.Next != "" {
		after := page.Next
		page.Next = ""
		w = serviceRequest(s, "GET", "/orders/merchant?limit=100&after="+after, "", "merchant-001", "MERCHANT", "")
		if json.Unmarshal(w.Body.Bytes(), &page) != nil || w.Code != 200 {
			t.Fatalf("page after %s: %d %s", after, w.Code, w.Body)
		}
		total += len(page.Items)
	}
	if total != historyDays+1 {
		t.Fatalf("pages held %d orders, want %d", total, historyDays+1)
	}
}

// Internal calls keep receipts of their own, so many of them never push out
// an API receipt.
func TestInternalReceiptsKeptApart(t *testing.T) {
	s := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
	serviceRequest(s, "GET", "/inventory/categories", "", "", "", "")
	for range maxReceipts + 1 {
		reserveRequest(s, "GET", "/internal/merchants/MER-001", "", "")
	}
	receipts, dropped := s.kept()
	if receipts[0].Target != "/inventory/categories" || dropped != 1 || !receipts[1].Internal {
		t.Fatalf("first receipt %+v, %d dropped", receipts[0], dropped)
	}
}

// The next order number follows the seed's highest.
func TestNextOrderNumberFollowsSeed(t *testing.T) {
	if next := nextNumber([]Order{{ID: "ORD-0516"}, {ID: "ORD-1004"}, {ID: "ORD-0002"}}); next != 1005 {
		t.Fatalf("next order number %d", next)
	}
}

// A memory bounded by bytes forgets its oldest keys past the bound when they
// may go, and refuses a new one when none may.
func TestKeyMemoryBoundedByBytes(t *testing.T) {
	start := time.Now()
	run := arrivals{limit: 100, maxBytes: 10}
	var forgotten []string
	for _, key := range []string{"a", "b", "c"} {
		forgotten = append(forgotten, run.add(key, 4, start)...)
	}
	if strings.Join(forgotten, "") != "a" || run.bytes != 8 {
		t.Fatalf("forgot %v, holding %d bytes", forgotten, run.bytes)
	}
	kept := arrivals{limit: 100, maxBytes: 10, life: time.Hour}
	for _, key := range []string{"a", "b", "c"} {
		if old := kept.add(key, 4, start); old != nil {
			t.Fatalf("forgot %v before they were an hour old", old)
		}
	}
	if !kept.full() {
		t.Fatal("a memory past its bytes of young keys accepts more")
	}
}

// A request document's member names are the contracts' only, once each,
// with no null and bounded nesting.
func TestStrictObject(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxDepth+2) + "1" + strings.Repeat("}", maxDepth+2)
	for body, want := range map[string]bool{
		`{"a":1,"b":[1,{"c":"x"}]}`: true,
		`{}`:                        true,
		`{"a":1,"a":2}`:             false,
		`{"A":1}`:                   false,
		`{"a":null}`:                false,
		`[1]`:                       false,
		`{"a":1} {"b":2}`:           false,
		deep:                        false,
	} {
		if got := strictObject([]byte(body)); got != want {
			t.Errorf("%.40s: %v, want %v", body, got, want)
		}
	}
}

// An operator file that is not a regular file is refused before it is read.
func TestOperatorFileMustBeRegular(t *testing.T) {
	if _, err := readBoundedFile(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("a folder read as an operator file: %v", err)
	}
}

// A report refuses pages from two states of Orders, and answers an Orders
// answer that is not a page 502, not an outage.
func TestReportRefusesMixedOrBadPages(t *testing.T) {
	for _, tc := range []struct {
		pages  []string
		status int
	}{
		{[]string{`{"items":[{"id":"ORD-0002"}],"next":"ORD-0002","epoch":1}`, `{"items":[{"id":"ORD-0001"}],"epoch":2}`}, 503},
		{[]string{`{"error":"invalid_query"}`}, 502},
	} {
		served := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.status == 502 {
				w.WriteHeader(400)
			}
			w.Write([]byte(tc.pages[min(served, len(tc.pages)-1)]))
			served++
		}))
		reports := newService(t, Config{Name: "reports", Keys: testKeys("reports"), OrdersURL: server.URL})
		w := serviceRequest(reports, "GET", "/reports/summary", "", "ops-01", "OPERATIONS", "")
		server.Close()
		if w.Code != tc.status {
			t.Errorf("pages %v: %d %s", tc.pages, w.Code, w.Body)
		}
	}
}
