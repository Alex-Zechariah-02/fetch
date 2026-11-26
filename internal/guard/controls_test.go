// The guard brought to the gateway's behaviour: overload refused before any
// check, refusals no control decides summarised, a rate refusal naming its
// wait, identity headers dropped on internal paths, the blocked list kept
// across a restart, and the handler's writer reachable for flushing.

package guard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testGuard serves one public operation, GET /ping, two requests a minute.
func testGuard(t *testing.T) (*Guard, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "orders-security.log")
	log, err := openLog(path, Storage{})
	if err != nil {
		t.Fatal(err)
	}
	table, err := newTable([]Operation{{ID: "ping", API: "orders", Method: http.MethodGet, Target: "/ping", Count: 2, Window: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{api: "orders", log: log, table: table, limiter: newLimiter(), blockedPath: filepath.Join(dir, BlockedFile)}
	empty := map[string]bool{}
	g.blocked.Store(&empty)
	return g, path
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// Past maxInFlight requests a request is refused 503 with Retry-After before
// any other check, and only counted in the minute's summary.
func TestOverloadRefusedFirst(t *testing.T) {
	g, path := testGuard(t)
	g.inFlight.Store(maxInFlight)
	w := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(ok)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" || !strings.Contains(w.Body.String(), "overloaded") {
		t.Fatalf("answer %d, Retry-After %q, body %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if g.inFlight.Load() != maxInFlight {
		t.Fatal("a refused request kept its place in flight")
	}
	summary, found := g.refusals.take("orders")
	if !found || summary.Counts["overloaded"] != 1 {
		t.Fatalf("overload not summarised: %+v", summary)
	}
	g.log.close()
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Fatalf("an overload refusal wrote a record:\n%s", data)
	}
}

// Route and path refusals are summarised by reason with the busiest
// addresses; a rate refusal keeps its own record and names its wait.
func TestRefusalsSummarisedAndRecorded(t *testing.T) {
	g, path := testGuard(t)
	handler := g.Wrap(http.HandlerFunc(ok))
	send := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, target, nil)
		r.RemoteAddr = "192.0.2.7:4000"
		handler.ServeHTTP(w, r)
		return w
	}
	send(http.MethodGet, "/missing")
	send(http.MethodGet, "/missing")
	send(http.MethodPost, "/ping")
	send(http.MethodGet, "/a/./ping")
	for range 2 {
		if w := send(http.MethodGet, "/ping"); w.Code != http.StatusOK {
			t.Fatalf("admitted request answered %d", w.Code)
		}
	}
	w := send(http.MethodGet, "/ping")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate refusal %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	summary, found := g.refusals.take("orders")
	if !found || summary.Counts["not_found"] != 2 || summary.Counts["method_not_allowed"] != 1 || summary.Counts["path_not_canonical"] != 1 {
		t.Fatalf("summary counts %v", summary.Counts)
	}
	if len(summary.Addresses) != 1 || summary.Addresses[0].Address != "192.0.2.7" || summary.Addresses[0].Count != 4 {
		t.Fatalf("summary addresses %v", summary.Addresses)
	}
	g.log.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	if strings.Contains(log, "not_found") || strings.Count(log, "quota_exceeded") != 1 || strings.Count(log, "request.admitted") != 2 {
		t.Fatalf("records:\n%s", log)
	}
}

// A client-written identity header never reaches the handler, on internal
// paths too.
func TestIdentityHeadersDropped(t *testing.T) {
	g, _ := testGuard(t)
	defer g.log.close()
	var seen string
	handler := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("X-Gateway-Subject") }))
	r := httptest.NewRequest(http.MethodGet, "/internal/orders", nil)
	r.Header.Set("X-Gateway-Subject", "cust-001")
	handler.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "" {
		t.Fatalf("an internal path kept a client's identity header: %q", seen)
	}
}

// A replaced blocked list is written to the settings folder, so a guard
// started again enforces it.
func TestBlockedListSurvivesRestart(t *testing.T) {
	g, _ := testGuard(t)
	defer g.log.close()
	w := httptest.NewRecorder()
	g.Blocked(w, httptest.NewRequest(http.MethodPut, "/blocked", bytes.NewReader([]byte(`["cust-002"]`))))
	if w.Code != http.StatusNoContent {
		t.Fatalf("replacement answered %d", w.Code)
	}
	restarted := &Guard{}
	if err := restarted.loadBlocked(g.blockedPath); err != nil {
		t.Fatal(err)
	}
	if !(*restarted.blocked.Load())["cust-002"] {
		t.Fatal("the blocked list did not survive a restart")
	}
	if entries, _ := os.ReadDir(filepath.Dir(g.blockedPath)); len(entries) != 2 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// A handler behind the guard can flush through http.ResponseController.
func TestHandlerCanFlush(t *testing.T) {
	g, _ := testGuard(t)
	defer g.log.close()
	var flushErr error
	handler := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flushErr = http.NewResponseController(w).Flush()
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", nil))
	if flushErr != nil {
		t.Fatalf("flush behind the guard: %v", flushErr)
	}
}

func TestGuardAbsoluteFormTargets(t *testing.T) {
	g, _ := testGuard(t)
	defer g.log.close()
	var seenHost string
	handler := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://shop.test/ping", nil)
	req.Host = "other.test"
	req.Header.Set("Host", "other.test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || seenHost != "shop.test" {
		t.Fatalf("http absolute-form: status=%d host=%q, want 200 and shop.test", w.Code, seenHost)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://shop.test/ping", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("https absolute-form: status=%d, want 200", w.Code)
	}
	for _, target := range []string{"http://user@shop.test/ping", "ftp://shop.test/ping"} {
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", target, w.Code)
		}
	}
}
