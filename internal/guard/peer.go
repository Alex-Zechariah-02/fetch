// The client a request counts for: the direct peer, or the visitor the
// configured trusted proxy names; and the rate key of that client, an
// IPv6 address cut to its /64 as the gateway's default ipv6_rate_prefix does.

package guard

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientOf is the client a request counts for: the direct peer, or, when
// trusted is valid and matches the peer, the last X-Forwarded-For entry the
// proxy set. Any other peer cannot name a client.
func clientOf(peer netip.Addr, header http.Header, trusted netip.Addr) netip.Addr {
	if !trusted.IsValid() || peer != trusted {
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
	if err != nil || named.Zone() != "" {
		return peer
	}
	return named.Unmap()
}

// ipv6Prefix is the gateway's default data.ipv6_rate_prefix: one /64 is
// what a single subscriber is usually given, so a client rotating addresses
// inside it shares one counter.
const ipv6Prefix = 64

// rateKey is the address a public operation's counter is keyed by: an IPv4
// address as it is, an IPv6 address masked to its /64. The record keeps the
// exact address.
func rateKey(client netip.Addr) string {
	if !client.Is6() {
		return client.String()
	}
	prefix, err := client.Prefix(ipv6Prefix)
	if err != nil {
		return client.String()
	}
	return prefix.String()
}
