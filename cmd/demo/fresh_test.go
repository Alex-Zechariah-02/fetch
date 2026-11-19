package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// digestOf is demoDigest for a fixture file the test just wrote.
func digestOf(t *testing.T, path string) string {
	t.Helper()
	digest, err := demoDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestFreshReplacesOnlyIdentifiedEarlierNativeState(t *testing.T) {
	for _, valid := range []bool{true, false} {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"version":1}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fixture.secret"), []byte("owned old demo secret"), 0600); err != nil {
			t.Fatal(err)
		}
		config := digestOf(t, filepath.Join(dir, configFile))
		secret := digestOf(t, filepath.Join(dir, "fixture.secret"))
		if !valid {
			config = "different"
		}
		identity := map[string]string{"format": "gateway-demo-1", "directory": dir, "config_sha256": config, "fixture_secret_sha256": secret}
		if err := os.WriteFile(filepath.Join(dir, identityFile), indented(identity), 0600); err != nil {
			t.Fatal(err)
		}
		err := removeState(dir)
		if valid && err != nil {
			t.Errorf("fresh refused identified earlier native state: %v", err)
		}
		_, statErr := os.Stat(dir)
		if valid && !os.IsNotExist(statErr) {
			t.Error("fresh retained its earlier state")
		}
		if !valid && (err == nil || statErr != nil) {
			t.Error("fresh removed a mismatched directory")
		}
	}
}

// -fresh removes nothing when the build fails: the previous deployment's
// database and security log stay.
func TestFreshKeepsStateWhenBuildFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	identity := map[string]string{"format": "gateway-demo-1", "directory": dir, "config_sha256": digestOf(t, filepath.Join(dir, configFile))}
	if err := os.WriteFile(filepath.Join(dir, identityFile), indented(identity), 0600); err != nil {
		t.Fatal(err)
	}
	apiward := t.TempDir()
	if err := os.MkdirAll(filepath.Join(apiward, "cmd", "apiward"), 0700); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("build failed")
	h := gatewayHost{state: dir, build: func(sources) (builtPrograms, error) { return builtPrograms{}, failed }}
	if err := h.up(apiward, true, false); !errors.Is(err, failed) {
		t.Fatalf("up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, configFile)); err != nil {
		t.Fatalf("a failed build removed the earlier state: %v", err)
	}
}
