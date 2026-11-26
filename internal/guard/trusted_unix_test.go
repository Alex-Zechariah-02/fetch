// On Unix the guard refuses key, key-set and blocked-list files another local
// account could rewrite, as the gateway and Fetch services refuse theirs.

//go:build unix

package guard

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardRefusesWritableKeyFile(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ops := []Operation{{ID: "pub", API: "a", Method: "GET", Target: "/p", Count: 1, Window: time.Minute}}

	setup := func(t *testing.T) (dir, pub, keysPath, blockedPath string) {
		t.Helper()
		dir = t.TempDir()
		pub = filepath.Join(dir, "accounts.pem")
		keysPath = filepath.Join(dir, KeysFile)
		blockedPath = filepath.Join(dir, BlockedFile)
		keys, _ := json.Marshal([]Key{{Kid: "k1", PublicKeyFile: pub}})
		for p, b := range map[string][]byte{
			pub:         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
			keysPath:    keys,
			blockedPath: []byte("[]"),
		} {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir, pub, keysPath, blockedPath
	}

	for _, tc := range []struct {
		name string
		pick func(pub, keysPath, blockedPath string) string
		mode os.FileMode
	}{
		{"world-writable public key", func(pub, _, _ string) string { return pub }, 0o666},
		{"group-writable public key", func(pub, _, _ string) string { return pub }, 0o620},
		{"group-writable keys.json", func(_, keysPath, _ string) string { return keysPath }, 0o660},
		{"other-writable blocked.json", func(_, _, blockedPath string) string { return blockedPath }, 0o602},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, pub, keysPath, blockedPath := setup(t)
			target := tc.pick(pub, keysPath, blockedPath)
			if err := os.Chmod(target, tc.mode); err != nil {
				t.Fatal(err)
			}
			g, err := New(Config{Dir: dir, API: "a", Operations: ops, Roles: []string{"READER"}})
			if err == nil {
				g.Close()
				t.Fatalf("guard started with mode %o on %s", tc.mode, filepath.Base(target))
			}
			if !strings.Contains(err.Error(), "writable by the group or others") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	dir, pub, _, _ := setup(t)
	if err := os.Chmod(pub, 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{Dir: dir, API: "a", Operations: ops, Roles: []string{"READER"}})
	if err != nil {
		t.Fatalf("trusted 0644 key refused: %v", err)
	}
	g.Close()
}
