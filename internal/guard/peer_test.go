// The client a request counts for.

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
