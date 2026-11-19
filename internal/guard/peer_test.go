// The client a request counts for, and its rate key.

package guard

import (
	"net/http"
	"net/netip"
	"testing"
)

// Only a peer on this host (the demo's proxy) may name the client; the last
// X-Forwarded-For entry is the one it set.
func TestClientOf(t *testing.T) {
	forwarded := http.Header{"X-Forwarded-For": {"198.51.100.7, 203.0.113.9"}}
	cases := []struct {
		peer   string
		header http.Header
		want   string
	}{
		{"127.0.0.1", forwarded, "203.0.113.9"},
		{"::1", forwarded, "203.0.113.9"},
		{"192.0.2.1", forwarded, "192.0.2.1"},
		{"127.0.0.1", http.Header{}, "127.0.0.1"},
		{"127.0.0.1", http.Header{"X-Forwarded-For": {"not an address"}}, "127.0.0.1"},
	}
	for _, c := range cases {
		if got := clientOf(netip.MustParseAddr(c.peer), c.header).String(); got != c.want {
			t.Errorf("peer %s, header %v: %s, want %s", c.peer, c.header, got, c.want)
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
