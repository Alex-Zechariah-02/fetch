// The client a request counts for, and its rate key.

package guard

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Only the configured trusted proxy may name the client; the last
// X-Forwarded-For entry is the one it set.
func TestClientOf(t *testing.T) {
	forwarded := http.Header{"X-Forwarded-For": {"198.51.100.7, 203.0.113.9"}}
	proxy := netip.MustParseAddr("127.0.0.3")
	cases := []struct {
		peer    string
		trusted netip.Addr
		header  http.Header
		want    string
	}{
		{"127.0.0.1", netip.Addr{}, forwarded, "127.0.0.1"},
		{"::1", netip.Addr{}, forwarded, "::1"},
		{"127.0.0.3", proxy, forwarded, "203.0.113.9"},
		{"127.0.0.1", proxy, forwarded, "127.0.0.1"},
		{"::1", proxy, forwarded, "::1"},
		{"192.0.2.1", proxy, forwarded, "192.0.2.1"},
		{"127.0.0.3", proxy, http.Header{}, "127.0.0.3"},
		{"127.0.0.3", proxy, http.Header{"X-Forwarded-For": {"not an address"}}, "127.0.0.3"},
		{"127.0.0.3", proxy, http.Header{"X-Forwarded-For": {"fe80::1%eth0"}}, "127.0.0.3"},
	}
	for _, c := range cases {
		if got := clientOf(netip.MustParseAddr(c.peer), c.header, c.trusted).String(); got != c.want {
			t.Errorf("peer %s, trusted %v, header %v: %s, want %s", c.peer, c.trusted, c.header, got, c.want)
		}
	}
}

// An IPv6 client is counted by its /64, so rotating addresses inside it buys
// no fresh quota; an IPv4 client by its own address.
func TestRateKeyMasksIPv6(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
	}
	for address, want := range cases {
		if got := rateKey(netip.MustParseAddr(address)); got != want {
			t.Errorf("%s: %s, want %s", address, got, want)
		}
	}
}

func TestGuardTrustsForwardedForOnlyFromProxy(t *testing.T) {
	g, _ := testGuard(t)
	t.Cleanup(g.log.close)
	handler := g.Wrap(http.HandlerFunc(ok))
	send := func(remote, xff string) int {
		r := httptest.NewRequest(http.MethodGet, "/ping", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	for range 2 {
		if code := send("127.0.0.1:40001", ""); code != http.StatusOK {
			t.Fatalf("within quota: %d, want 200", code)
		}
	}
	if code := send("127.0.0.1:40002", ""); code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d, want 429", code)
	}
	if code := send("127.0.0.1:40003", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("untrusted loopback peer with X-Forwarded-For answered %d, want 429", code)
	}

	g.trustedProxy = netip.MustParseAddr("127.0.0.3")
	if code := send("127.0.0.1:40004", "203.0.113.10"); code != http.StatusTooManyRequests {
		t.Fatalf("non-proxy loopback peer with X-Forwarded-For answered %d, want 429", code)
	}
	if code := send("127.0.0.3:40005", "203.0.113.10"); code != http.StatusOK {
		t.Fatalf("trusted proxy forwarding new client answered %d, want 200", code)
	}
	if code := send("127.0.0.3:40006", "203.0.113.10"); code != http.StatusOK {
		t.Fatalf("trusted proxy second request answered %d, want 200", code)
	}
	if code := send("127.0.0.3:40007", "203.0.113.10"); code != http.StatusTooManyRequests {
		t.Fatalf("trusted proxy third request for same client answered %d, want 429", code)
	}
	if _, err := New(Config{Dir: t.TempDir(), API: "orders", Operations: []Operation{{ID: "ping", API: "orders", Method: http.MethodGet, Target: "/ping", Count: 1, Window: 1}}, TrustedProxy: "not-an-ip"}); err == nil {
		t.Fatal("invalid TrustedProxy accepted")
	}
}
