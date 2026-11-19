// Operator commands: reset tries every service and names each failure, the
// image's health check needs an HTTP answer from each service, a sign-in
// failure says which check failed, -h is not a failure, and a Fetch host
// without a gateway does not offer the shop.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResetTriesEveryService(t *testing.T) {
	t.Parallel()
	var reached atomic.Int32
	answering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		fmt.Fprintf(w, `{"service":"second","sha256":"%s"}`, strings.Repeat("ab", 32))
	}))
	defer answering.Close()
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer refusing.Close()
	services := []demoService{
		{name: "first", control: strings.TrimPrefix(refusing.URL, "http://")},
		{name: "second", control: strings.TrimPrefix(answering.URL, "http://")},
	}
	err := resetAll(answering.Client(), services, "s")
	if err == nil || !strings.Contains(err.Error(), "first") || strings.Contains(err.Error(), "second") || reached.Load() != 1 {
		t.Fatalf("reset after a failure: %v, second reached %d times", err, reached.Load())
	}
}

func TestHealthNeedsAnHTTPAnswer(t *testing.T) {
	t.Parallel()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Service", "orders")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer service.Close()
	address := strings.TrimPrefix(service.URL, "http://")
	if err := answers(service.Client(), demoService{name: "orders", control: address}); err != nil {
		t.Fatalf("a serving control listener: %v", err)
	}
	if err := answers(service.Client(), demoService{name: "inventory", control: address}); err == nil {
		t.Fatal("another service's answer passed")
	}
}

func TestSignInFailureNamesTheCheck(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]string{
		`{"token":`: "no readable reply",
		`{"token":"","expires_at":"2026-11-19T00:00:00Z"}`: "without a token",
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }))
		_, _, err := loginWithClient(server.Client(), server.URL, "a@fetch.test", "")
		server.Close()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", body, err, want)
		}
	}
}

func TestHelpIsNotAFailure(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := exitCode(fmt.Errorf("parsing: %w", flag.ErrHelp), &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("-h: exit %d, %q", code, stderr.String())
	}
	if code := exitCode(fmt.Errorf("refused"), &stderr); code != 1 || !strings.Contains(stderr.String(), "refused") {
		t.Fatalf("failure: exit %d, %q", code, stderr.String())
	}
}

func TestHostBannerOffersTheShopOnlyBehindAGateway(t *testing.T) {
	t.Parallel()
	for checks, shop := range map[hostChecks]bool{gatewayChecks: true, noChecks: false, builtinChecks: false} {
		if got := strings.Contains(hostBanner(checks, "a", "b", "10.0.0.1:9506", "10.0.0.1"), "shop:"); got != shop {
			t.Errorf("checks %d: shop line %v, want %v", checks, got, shop)
		}
	}
}
