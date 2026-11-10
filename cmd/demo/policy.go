// The demonstration's baseline policy: every Fetch operation with its roles,
// rate and body rules, the shop's public pages and the upstreams, on this
// machine or, for a gateway host, on the Fetch host over TLS.

package main

import (
	"net/netip"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// websiteOperations are the shop's public GET operations: one per exact
// client route, one per route that takes an ID or name, and the assets. A
// page view loads many images, so the assets allow ten times a page's rate.
func websiteOperations() []guard.Operation {
	var operations []guard.Operation
	for _, page := range sitePages {
		name := strings.TrimPrefix(page, "/")
		if name == "" {
			name = "home"
		}
		operations = append(operations, webOperation("web.page."+name, page, 600))
	}
	for _, route := range []struct{ id, prefix string }{
		{"web.store", "/store/"}, {"web.item", "/item/"}, {"web.my-order", "/my-orders/"}, {"web.help-ticket", "/help/"},
	} {
		operations = append(operations, webOperation(route.id, route.prefix+"*", 600))
	}
	return append(operations, webOperation("web.assets", "/assets/*", 6000))
}

// webOperation is a public GET operation of the shop's website.
func webOperation(id, target string, count int) guard.Operation {
	return guard.Operation{ID: id, API: "web", Method: "GET", Target: target, Count: count, Window: time.Minute}
}

// baselinePolicy is the confirmed policy the demonstration starts from: the
// services' own operation table plus the website, all access allow.
func baselinePolicy() map[string]any {
	definitions := append(services.Operations(), websiteOperations()...)
	upstreams, apis, operations, permits := []map[string]any{}, []map[string]any{}, []map[string]any{}, []map[string]any{}
	for _, service := range fetchServices {
		upstreams = append(upstreams, map[string]any{"id": service.name + "-svc", "dial": service.listen})
		apis = append(apis, map[string]any{"id": service.name, "upstream": service.name + "-svc"})
	}
	upstreams = append(upstreams, map[string]any{"id": "web-svc", "dial": siteListen})
	apis = append(apis, map[string]any{"id": "web", "upstream": "web-svc"})
	for _, definition := range definitions {
		auth, key := "required", "subject"
		if definition.Public() {
			auth, key = "none", "client_address"
		}
		op := map[string]any{"id": definition.ID, "api": definition.API, "method": definition.Method, "target": definition.Target, "access": "allow", "auth": auth,
			"rate": map[string]any{"algorithm": "sliding-window", "count": definition.Count, "window_seconds": int(definition.Window.Seconds()), "key": key}}
		if definition.Schema != nil {
			op["body"] = map[string]any{"max_bytes": definition.MaxBytes, "schema": definition.Schema}
		}
		operations = append(operations, op)
		for _, role := range definition.Roles {
			permits = append(permits, map[string]any{"role": role, "operation": definition.ID})
		}
	}
	roles := []map[string]any{}
	for _, role := range services.Roles {
		roles = append(roles, map[string]any{"id": role})
	}
	return map[string]any{"schema_version": 4, "profile": "core", "upstreams": upstreams, "apis": apis, "operations": operations, "roles": roles, "permits": permits}
}

// fetchProfile is the gateway's TLS profile for the Fetch host: the CA that
// issued Fetch's certificate and the client certificate Fetch admits.
const fetchProfile = "fetch"

// deployedBaseline is the baseline for a gateway host: every upstream is the
// same port on the Fetch host at fetch, reached over TLS with fetchProfile.
func deployedBaseline(fetch netip.Addr) map[string]any {
	policy := baselinePolicy()
	policy["schema_version"] = 5
	for _, upstream := range policy["upstreams"].([]map[string]any) {
		address := deployedAddress(upstream["dial"].(string), fetch)
		delete(upstream, "dial")
		upstream["url"], upstream["tls"] = "https://"+address, fetchProfile
	}
	return policy
}

// deployedAddress is the address at host with the port of the local
// address listen.
func deployedAddress(listen string, host netip.Addr) string {
	return netip.AddrPortFrom(host, netip.MustParseAddrPort(listen).Port()).String()
}
