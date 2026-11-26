// Ingress target-form and canonical-path checks: CONNECT, Upgrade, bad target
// forms, control/DEL/backslash characters, trailing dot segments, empty middle
// segments, and boundary printable characters ('!' and '~') and trailing slash.

package guard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestIngressAndCanonicalPathRefusals(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(filepath.Join(dir, "orders-security.log"), Storage{})
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	table, err := newTable([]Operation{
		{ID: "ping", API: "orders", Method: http.MethodGet, Target: "/ping/*", Count: 100, Window: time.Minute},
		{ID: "trail", API: "orders", Method: http.MethodGet, Target: "/trail/", Count: 100, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{api: "orders", log: log, table: table, limiter: newLimiter(), blockedPath: filepath.Join(dir, BlockedFile)}
	empty := map[string]bool{}
	g.blocked.Store(&empty)
	handler := g.Wrap(http.HandlerFunc(ok))

	send := func(method, rawURI, path, upgrade string) int {
		r := &http.Request{
			Method:     method,
			RequestURI: rawURI,
			URL:        &url.URL{Path: path},
			Header:     http.Header{},
			Body:       http.NoBody,
			RemoteAddr: "192.0.2.1:1234",
		}
		if upgrade != "" {
			r.Header.Set("Upgrade", upgrade)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}

	cases := []struct {
		name, method, rawURI, path, upgrade string
		want                                int
	}{
		{"connect without upgrade", http.MethodConnect, "/ping/a", "/ping/a", "", http.StatusBadRequest},
		{"upgrade header", http.MethodGet, "/ping/a", "/ping/a", "websocket", http.StatusBadRequest},
		{"asterisk target", http.MethodOptions, "*", "*", "", http.StatusBadRequest},
		{"trailing single dot", http.MethodGet, "/ping/.", "/ping/.", "", http.StatusBadRequest},
		{"trailing double dot", http.MethodGet, "/ping/..", "/ping/..", "", http.StatusBadRequest},
		{"space in path", http.MethodGet, "/ping/a b", "/ping/a b", "", http.StatusBadRequest},
		{"del byte in path", http.MethodGet, "/ping/a\x7fb", "/ping/a\x7fb", "", http.StatusBadRequest},
		{"backslash in path", http.MethodGet, "/ping/a\\b", "/ping/a\\b", "", http.StatusBadRequest},
		{"empty middle segment", http.MethodGet, "/ping//a", "/ping//a", "", http.StatusBadRequest},
		{"boundary bang 0x21", http.MethodGet, "/ping/!", "/ping/!", "", http.StatusOK},
		{"boundary tilde 0x7e", http.MethodGet, "/ping/~", "/ping/~", "", http.StatusOK},
		{"trailing slash accepted", http.MethodGet, "/trail/", "/trail/", "", http.StatusOK},
	}
	for _, tc := range cases {
		if got := send(tc.method, tc.rawURI, tc.path, tc.upgrade); got != tc.want {
			t.Errorf("%s: status=%d, want %d", tc.name, got, tc.want)
		}
	}
}
