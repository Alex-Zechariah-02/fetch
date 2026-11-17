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
	// Only the last entry counts, so only it is cut out: a client-written
	// prefix of many commas costs nothing.
	last := values[len(values)-1]
	last = last[strings.LastIndexByte(last, ',')+1:]
	named, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return peer
	}
	return named.Unmap()
}
