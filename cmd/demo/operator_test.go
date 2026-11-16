package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrderFloodUsesASeparateCustomerAccount(t *testing.T) {
	signedIn := make(chan string, 1)
	var orders atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/accounts/login" {
			var body struct{ Email string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			signedIn <- body.Email
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"token":"controlled-token","expires_at":"2099-01-01T00:00:00Z"}`))
			return
		}
		if r.URL.Path != "/orders" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer controlled-token" {
			t.Errorf("unexpected flood request: %s %s", r.Method, r.URL.Path)
		}
		orders.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	previous := dataListen
	dataListen = strings.TrimPrefix(server.URL, "http://")
	defer func() { dataListen = previous }()
	if err := attack([]string{"-dir", operatorTestState(t), "-scenario", "flood-orders", "-count", "12"}); err != nil {
		t.Fatal(err)
	}
	if email := <-signedIn; email != "customer2@fetch.test" {
		t.Errorf("flood signs in as %q; want Customer 2, separate from Customer 1", email)
	}
	if orders.Load() != 12 {
		t.Errorf("flood sent %d orders, want 12", orders.Load())
	}
}

func TestOperatorBoundaryRefusals(t *testing.T) {
	// Each case runs against a valid demonstration directory, so only the
	// guard named by its error can refuse it.
	dir := operatorTestState(t)
	refused := func(name string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, want)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-scenario", "unknown"}, "choose flood-search"},
		{[]string{"-scenario", "flood-search", "-from", "8.8.8.8"}, "IPv4 loopback source"},
		{[]string{"-scenario", "flood-search", "-from", "::1"}, "IPv4 loopback source"},
		{[]string{"-scenario", "flood-search", "-count", "0"}, "count from 1 to 10000"},
		{[]string{"-scenario", "flood-search", "-count", "10001"}, "count from 1 to 10000"},
	} {
		refused(strings.Join(c.args, " "), attack(append(c.args, "-dir", dir)), c.want)
	}
	refused("keys retire", keys([]string{"retire", "-dir", dir}), "-kid is required")
	refused("keys unknown", keys([]string{"unknown"}), "choose keys rotate")
	refused("policy export", policy([]string{"export", "-dir", dir}), "output or input file is required")
	refused("policy unknown", policy([]string{"unknown"}), "choose policy export")
	missing := filepath.Join(t.TempDir(), "missing.json")
	if err := policy([]string{"stage", "-dir", dir, "-file", missing}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("policy stage of a missing file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "owned.txt")
	if err := writeNewFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(path, []byte("second")); err == nil {
		t.Fatal("export overwrote an existing file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "first" {
		t.Fatal("exclusive output did not preserve existing data")
	}
	if err := replaceOperatorFile(filepath.Dir(path), []byte("invalid")); err == nil {
		t.Fatal("operator replaced a directory")
	}
}

func operatorTestState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		configFile:  []byte(`{"gateway":{"jwt":{"keys":[{"kid":"active","public_key_file":"active.pem"}]}}}`),
		secretFile:  newSecret(),
		signingFile: []byte(`{"kid":"active","private_key_file":"active-key.pem"}`),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := identifyDemo(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestKeyOperatorRefusalsAndUnconfirmedReload(t *testing.T) {
	dir := operatorTestState(t)
	before, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"active", "unknown"} {
		if _, err := changeKeys(dir, newAdminClient(), "retire", kid); err == nil {
			t.Fatalf("retired %s", kid)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, configFile))
	if string(before) != string(after) {
		t.Fatal("refused retirement changed operator settings")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(422) }))
	defer server.Close()
	old := adminListen
	adminListen = strings.TrimPrefix(server.URL, "http://")
	defer func() { adminListen = old }()
	if _, err := changeKeys(dir, newAdminClient(), "rotate", ""); err == nil {
		t.Fatal("unconfirmed reload reported success")
	}
	signing, _ := os.ReadFile(filepath.Join(dir, signingFile))
	if !strings.Contains(string(signing), `"kid":"active"`) {
		t.Fatal("Accounts switched before gateway reload was confirmed")
	}
	if err := checkDemo(dir); err != nil {
		t.Fatalf("authorized settings update lost deployment identity: %v", err)
	}
}

func TestAdminUnknownWriteIsNotRetried(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(200)
			return
		}
		if writes.Add(1) == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	old := adminListen
	adminListen = strings.TrimPrefix(server.URL, "http://")
	defer func() { adminListen = old }()
	client := newAdminClient()
	defer client.client.CloseIdleConnections()
	if _, _, err := client.send("GET", "/warm", nil, nil, 200); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.send("POST", "/write", nil, mutationHeaders(""), 200); err == nil {
		t.Fatal("lost answer was reported as success")
	}
	if writes.Load() != 1 {
		t.Fatalf("unknown write automatically retried %d times", writes.Load())
	}
}

func TestAdminDoesNotFollowWriteRedirect(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		if r.URL.Path == "/write" {
			w.Header().Set("Location", "/repeated")
			w.WriteHeader(307)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	old := adminListen
	adminListen = strings.TrimPrefix(server.URL, "http://")
	defer func() { adminListen = old }()
	client := newAdminClient()
	defer client.client.CloseIdleConnections()
	if _, _, err := client.send("POST", "/write", nil, mutationHeaders(""), 200); err == nil {
		t.Error("operator followed a write redirect")
	}
	if writes.Load() != 1 {
		t.Errorf("operator sent %d writes for one intent", writes.Load())
	}
}

func TestKeyUseWarning(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	recent, old := now.Add(-3*time.Minute), now.Add(-20*time.Minute)
	items := []keyUse{{Kid: "a", LastVerifiedAt: &recent}, {Kid: "b", LastVerifiedAt: &old}, {Kid: "c"}}
	if got := keyUseWarning(items, "a", now); !strings.Contains(got, "key a verified a token 3m0s ago") {
		t.Errorf("recent use: %q", got)
	}
	for _, kid := range []string{"b", "c", "missing"} {
		if got := keyUseWarning(items, kid, now); got != "" {
			t.Errorf("%s: %q", kid, got)
		}
	}
}
