// The client a request counts for: the direct peer, or the visitor the
// demo's own proxy on this host names.

package guard

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientOf is the client a request counts for: the direct peer, or, when
// the peer is on this host (the demo's own proxy in front of the APIs), the
// last X-Forwarded-For entry it set. Any other peer cannot name a client.
func clientOf(peer netip.Addr, header http.Header) netip.Addr {
	if !peer.IsLoopback() {
		return peer
	}
	values := header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	entries := strings.Split(values[len(values)-1], ",")
	named, err := netip.ParseAddr(strings.TrimSpace(entries[len(entries)-1]))
	if err != nil {
		return peer
	}
	return named.Unmap()
}
