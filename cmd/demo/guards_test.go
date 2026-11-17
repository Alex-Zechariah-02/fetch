// Demo tool guards: the Fetch host's bind address, the gateway's trusted-key
// and policy size maxima, and reported sign-out and cleanup failures.

package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchBindRefusesLoopback(t *testing.T) {
	t.Parallel()
	const refused = "another address than 127.0.0.1"
	for _, address := range []string{"127.0.0.1", "::ffff:127.0.0.1"} {
		err := upFetch(t.TempDir(), address, t.TempDir(), "", gatewayChecks, false, false)
		if err == nil || !strings.Contains(err.Error(), refused) {
			t.Errorf("-bind %s: %v", address, err)
		}
	}
	// Other loopback addresses hold no internal listener: the documented
	// one-host route binds 127.0.0.3 (it then stops at the empty certificate folder).
	for _, address := range []string{"127.0.0.3", "::1"} {
		if err := upFetch(t.TempDir(), address, t.TempDir(), "", gatewayChecks, false, false); err == nil || strings.Contains(err.Error(), refused) {
			t.Errorf("-bind %s: %v", address, err)
		}
	}
}

func TestKeysRotateStopsAtGatewayMaximum(t *testing.T) {
	dir := operatorTestState(t)
	keys := make([]string, maxTrusted)
	for i := range keys {
		keys[i] = `{"kid":"k` + strings.Repeat("x", i) + `","public_key_file":"k.pem"}`
	}
	config := []byte(`{"gateway":{"jwt":{"keys":[` + strings.Join(keys, ",") + `]}}}`)
	if err := os.WriteFile(filepath.Join(dir, configFile), config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := identifyDemo(dir); err != nil {
		t.Fatal(err)
	}
	_, err := changeKeys(dir, newAdminClient(), "rotate", "")
	if err == nil || !strings.Contains(err.Error(), "at most 64 keys") {
		t.Fatalf("rotate past the gateway's maximum: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil || !bytes.Equal(after, config) {
		t.Fatal("a refused rotation changed the settings")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "fetch-*")); len(matches) != 0 {
		t.Fatalf("a refused rotation wrote keys %v", matches)
	}
}

func TestPolicyFileBounds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// A laid-out document within both bounds compacts to the gateway's size.
	padded := `{"a":"` + strings.Repeat("x", maxPolicy-8) + `"}` + strings.Repeat(" ", maxPolicyFile-maxPolicy)
	if document, err := compactFile(write("fits.json", []byte(padded))); err != nil || len(document) != maxPolicy-8+8 {
		t.Fatalf("fitting policy: %d bytes, %v", len(document), err)
	}
	if _, err := compactFile(write("dense.json", []byte(`{"a":"`+strings.Repeat("x", maxPolicy)+`"}`))); err == nil || !strings.Contains(err.Error(), "accepts at most") {
		t.Fatalf("policy above the gateway's maximum: %v", err)
	}
	if _, err := compactFile(write("long.json", []byte(padded+" "))); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("file above the read bound: %v", err)
	}
}

func TestDemoServerDeadlines(t *testing.T) {
	t.Parallel()
	server := demoServer(http.NotFoundHandler(), 15*time.Second)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout != 15*time.Second || server.IdleTimeout <= 0 {
		t.Fatalf("deadlines %v %v %v %v", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout)
	}
}

// failing answers every request with an error.
type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestSignOutFailureReported(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	(&adminClient{client: &http.Client{Transport: failing{}}}).signOut(&out)
	if !strings.Contains(out.String(), "sign-out failed") || !strings.Contains(out.String(), "connection refused") {
		t.Fatalf("sign-out failure report %q", out.String())
	}
}

func TestRemoveFailedNamesDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "half")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeFailed(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the half-written directory was kept")
	}
	if err := removeFailed("bad\x00name"); err == nil || !strings.Contains(err.Error(), "may hold private keys") {
		t.Fatalf("failed removal: %v", err)
	}
}
