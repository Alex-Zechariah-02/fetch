// The demonstration identity names the file that changed and demo rebind
// accepts it; a reused deployment is checked against this run; a retired
// key's files from keys rotate are deleted; the default home is a data folder.

package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRebindAcceptsAChangedSettingsFile(t *testing.T) {
	dir := operatorTestState(t)
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"gateway":{"jwt":{"keys":[]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDemo(dir); err == nil || !strings.Contains(err.Error(), configFile) || !strings.Contains(err.Error(), "demo rebind") {
		t.Fatalf("changed settings: %v", err)
	}
	if err := rebind([]string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := checkDemo(dir); err != nil {
		t.Fatalf("after rebind: %v", err)
	}
	// Another directory's identity is never rebound.
	moved := filepath.Join(t.TempDir(), "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := rebind([]string{"-dir", moved}); err == nil || !strings.Contains(err.Error(), "not rebinding") {
		t.Fatalf("moved directory: %v", err)
	}
}

func TestOperatorLockRefusesASecondHolder(t *testing.T) {
	dir := operatorTestState(t)
	lock, err := lockDemo(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := changeKeys(dir, newAdminClient(), "rotate", ""); err == nil || !strings.Contains(err.Error(), "another demo command") {
		t.Fatalf("a second key change: %v", err)
	}
}

func TestRemoveRetiredDeletesOnlyRotatedFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"k1-key.pem", "k1.pem", "issuer.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeRetired(dir, "k1", filepath.Join(dir, "k1.pem"))
	removeRetired(dir, "setup", filepath.Join(dir, "issuer.pem"))
	for name, kept := range map[string]bool{"k1-key.pem": false, "k1.pem": false, "issuer.pem": true} {
		_, err := os.Stat(filepath.Join(dir, name))
		if exists := !errors.Is(err, os.ErrNotExist); exists != kept {
			t.Errorf("%s exists %v, want %v", name, exists, kept)
		}
	}
}

func TestReusedDeploymentMatchesThisRun(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	fetch := netip.MustParseAddr("192.0.2.10")
	if err := os.WriteFile(filepath.Join(state, baselineFile), indented(deployedBaseline(fetch)), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), caFile)
	settings := map[string]any{"upstream": map[string]any{"tls_profiles": []tlsProfile{{ID: fetchProfile, CAFile: ca}}}}
	if err := os.WriteFile(filepath.Join(state, configFile), indented(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkReused(state, deployedBaseline(fetch), ca); err != nil {
		t.Fatalf("same run: %v", err)
	}
	if err := checkReused(state, deployedBaseline(netip.MustParseAddr("192.0.2.11")), ca); err == nil || !strings.Contains(err.Error(), "192.0.2.11") {
		t.Fatalf("another -fetch: %v", err)
	}
	if err := checkReused(state, deployedBaseline(fetch), filepath.Join(t.TempDir(), caFile)); err == nil || !strings.Contains(err.Error(), "-fresh") {
		t.Fatalf("another certs folder: %v", err)
	}
}

func TestDefaultHomeIsADataFolder(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		cache, _ := os.UserCacheDir()
		config, _ := os.UserConfigDir()
		want := map[string]string{"windows": cache, "darwin": config}[runtime.GOOS]
		if data, err := dataFolder(); err != nil || data != want {
			t.Fatalf("data folder %q, want %q: %v", data, want, err)
		}
		return
	}
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	if home, err := homeFolder(""); err != nil || home != filepath.Join(data, "EAT40005-demo") {
		t.Fatalf("home %q: %v", home, err)
	}
	t.Setenv("XDG_DATA_HOME", "relative")
	t.Setenv("HOME", data)
	if home, err := homeFolder(""); err != nil || home != filepath.Join(data, ".local", "share", "EAT40005-demo") {
		t.Fatalf("home with a relative XDG_DATA_HOME %q: %v", home, err)
	}
}
