// On Unix a service refuses a gateway key set another local account could
// rewrite, as the gateway refuses its own trust anchors.

//go:build unix

package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayKeySetMustBeTrusted(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(file, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o620, 0o602} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders, GatewayKey: file}); err == nil || !strings.Contains(err.Error(), "writable by the group or others") {
			t.Errorf("key set with mode %o: %v", mode, err)
		}
	}
	// A private file passes the check and is then judged as a key set.
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Name: "support", Keys: testKeys("support"), OrdersURL: unusedOrders, GatewayKey: file}); err == nil || strings.Contains(err.Error(), "writable") {
		t.Errorf("a trusted key set without keys: %v", err)
	}
}
