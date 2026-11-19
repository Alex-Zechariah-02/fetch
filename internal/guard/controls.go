// The guard's control stages after routing: the token, the blocked list and
// the roles, then the rate limit, each recording its own refusal.

package guard

import (
	"net/http"
	"slices"
	"strconv"
	"time"
)

// authorise verifies the token, then refuses a blocked account, then keeps
// only defined roles and refuses when none is permitted on the operation.
func (g *Guard) authorise(c *check, credentials []string, rule *rule) bool {
	token, reason := bearer(credentials)
	var verified identity
	if reason == "" {
		verified, reason = verify(g.keys, token, time.Now())
	}
	if reason != "" {
		c.w.Header().Set("WWW-Authenticate", "Bearer")
		c.refuse("jwt", http.StatusUnauthorized, "unauthenticated", reason)
		return false
	}
	c.record.Subject = verified.subject
	permitted := false
	for _, role := range verified.roles {
		if !slices.Contains(g.roles, role) {
			c.record.IgnoredRoles = append(c.record.IgnoredRoles, role)
			continue
		}
		c.record.Roles = append(c.record.Roles, role)
		permitted = permitted || slices.Contains(rule.Roles, role)
	}
	switch {
	case (*g.blocked.Load())[verified.subject]:
		c.refuse("rbac", http.StatusForbidden, "account_blocked", "account_blocked")
	case !permitted:
		c.refuse("rbac", http.StatusForbidden, "forbidden", "no_permit")
	default:
		return true
	}
	return false
}

// limit counts the request on the operation's counter for the account, or
// for the client address on a public operation (an IPv6 client by its /64).
func (g *Guard) limit(c *check, rule *rule) bool {
	key := c.record.Subject
	if rule.Public() {
		key = ""
		if c.client.IsValid() {
			key = rateKey(c.client)
		}
	}
	if key == "" {
		c.refuse("rate", http.StatusBadRequest, "bad_request", "invalid_peer_address")
		return false
	}
	verdict, wait := g.limiter.admit(counterKey{rule.ID, key}, rule.Count, rule.Window, g.limiter.now())
	switch verdict {
	case exceeded:
		c.w.Header().Set("Retry-After", strconv.FormatInt(wait, 10))
		c.refuse("rate", http.StatusTooManyRequests, "rate_limited", "quota_exceeded")
		return false
	case full:
		g.capacity.Add(1)
		c.w.Header().Set("Retry-After", strconv.FormatInt(wait, 10))
		c.refuse("rate", http.StatusServiceUnavailable, "gateway_unavailable", "rate_capacity")
		return false
	}
	return true
}
