package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeasurementArgumentRefusals(t *testing.T) {
	for _, args := range [][]string{{"-samples", "0"}, {"-samples", "51"}, {"-account", "ops-01"}, {"-account", "unknown"}, {"-builtin-offset", "-2"}, {"unexpected"}} {
		var output bytes.Buffer
		if run(args, &output) == nil || output.Len() != 0 {
			t.Errorf("invalid measurement emitted a result: %v", args)
		}
	}
}

func TestPairedMeasurementChecksIdentityAndAnswers(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/orders/wallet")
		calls = append(calls, name)
		if name == "direct" {
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-Gateway-Subject") != "cust-001" || r.Header.Get("X-Gateway-Roles") != "CUSTOMER" {
				t.Error("direct baseline identity incorrect")
			}
		} else {
			if r.Header.Get("Authorization") != "Bearer token-"+name || r.Header.Get("X-Gateway-Subject") != "" {
				t.Error("protected measurement forged identity or used another stack's token")
			}
			w.Header().Set("X-Request-Id", "synthetic-reference")
		}
		w.Header().Set("X-Service", "orders")
		w.Write([]byte(`{"balance_sen":10000}`))
	}))
	defer server.Close()
	conditions := []condition{{"direct", server.URL + "/direct", ""}, {"builtin", server.URL + "/builtin", "token-builtin"}, {"gateway", server.URL + "/gateway", "token-gateway"}}
	result, err := measure(server.Client(), conditions, "cust-001", 3)
	if err != nil || result.Samples != 3 || len(calls) != 3*(3+warmupRounds) {
		t.Fatalf("rotating counts %d: %v", len(calls), err)
	}
	// Each round starts with the next condition, so none always goes first.
	for round, first := range []string{"direct", "builtin", "gateway", "direct"} {
		if calls[round*3] != first {
			t.Fatalf("round %d started with %s, want %s", round, calls[round*3], first)
		}
	}
	if len(result.DirectSamplesMS) != 3 || len(result.BuiltinSamplesMS) != 3 || len(result.GatewaySamplesMS) != 3 {
		t.Fatal("raw observations missing from the reproducible result")
	}
	if result.Direct.MeanMS <= 0 || result.Builtin.P95MS <= 0 || result.Gateway.P95MS <= 0 {
		t.Fatal("measurement did not time complete responses")
	}
}

func TestMeasurementRefusesIncompleteOrNonEquivalentAnswers(t *testing.T) {
	for _, body := range []string{`{"balance_sen":9000}`, `{}`, `{"balance_sen":10000,"unexpected":1}`, strings.Repeat("x", 4097)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Service", "orders")
			if strings.HasPrefix(r.URL.Path, "/direct") {
				w.Write([]byte(`{"balance_sen":10000}`))
				return
			}
			w.Header().Set("X-Request-Id", "synthetic-reference")
			w.Write([]byte(body))
		}))
		_, err := measure(server.Client(), pair(server.URL), "cust-001", 1)
		server.Close()
		if err == nil {
			t.Error("measurement reported non-equivalent answers")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
	defer server.Close()
	if _, err := measure(server.Client(), pair(server.URL), "cust-001", 1); err == nil {
		t.Fatal("rate refusal emitted a latency result")
	}
}

func TestNearestRankLatencySummary(t *testing.T) {
	s := summarize([]float64{5, 1, 4, 2, 3})
	if s.MeanMS != 3 || s.P50MS != 3 || s.P95MS != 5 {
		t.Fatalf("nearest-rank summary: %+v", s)
	}
}

// pair is the standalone and gateway conditions on one test server.
func pair(origin string) []condition {
	return []condition{{"direct", origin + "/direct", ""}, {"gateway", origin + "/gateway", "synthetic-test-token"}}
}
