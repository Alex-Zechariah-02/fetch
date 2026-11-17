// Fetch host checks: the -standalone and -local flags of -role fetch select
// who checks requests, and built-in protection trusts exactly the signing
// key Accounts uses.

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
)

func TestFetchHostChecks(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		standalone, local bool
		want              hostChecks
	}{{false, false, gatewayChecks}, {true, false, noChecks}, {false, true, builtinChecks}} {
		if got, err := checksOf(c.standalone, c.local); err != nil || got != c.want {
			t.Errorf("standalone %v local %v: %v %v", c.standalone, c.local, got, err)
		}
	}
	if err := up([]string{"-role", "fetch", "-standalone", "-local", "-bind", "127.0.0.3"}); err == nil || !strings.Contains(err.Error(), "exclude each other") {
		t.Errorf("both: %v", err)
	}
	// Each mode is taken with -role fetch and reaches the bind check.
	for _, mode := range []string{"-standalone", "-local"} {
		err := up([]string{"-role", "fetch", mode, "-measure", "-bind", "127.0.0.1", "-home", t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "another address than 127.0.0.1") {
			t.Errorf("%s: %v", mode, err)
		}
	}
	if err := up([]string{"-role", "gateway", "-local"}); err == nil || !strings.Contains(err.Error(), "does not take -role") {
		t.Errorf("-local with -role gateway: %v", err)
	}
}

func TestHostFilesTrustTheSigningKey(t *testing.T) {
	t.Parallel()
	folder := filepath.Join(writeDeployment(t, "host"), "fetch")
	kid, err := signingKeyID(filepath.Join(folder, privateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files, err := hostFiles(dir, folder, kid, builtinChecks)
	if err != nil {
		t.Fatal(err)
	}
	var keys []guard.Key
	if err := json.Unmarshal(files[guard.KeysFile], &keys); err != nil || len(keys) != 1 || keys[0].Kid != kid || keys[0].PublicKeyFile != filepath.Join(dir, publicKeyFile) {
		t.Fatalf("keys %s: %v", files[guard.KeysFile], err)
	}
	if public, err := keyID(files[publicKeyFile]); err != nil || public != kid {
		t.Fatalf("the trusted public key %q is not the signing key %q: %v", public, kid, err)
	}
	if string(files[guard.BlockedFile]) != "[]\n" {
		t.Fatalf("blocked %q", files[guard.BlockedFile])
	}
	for _, checks := range []hostChecks{gatewayChecks, noChecks} {
		files, err := hostFiles(dir, folder, kid, checks)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := files[guard.KeysFile]; found || len(files) != 2 {
			t.Errorf("checks %d wrote %d files", checks, len(files))
		}
	}
}
