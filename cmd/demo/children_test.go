// The internal call keys a run writes: one new key per calling service,
// named as the services read them, replaced on each run.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

func TestNewKeysServeEachService(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := newKeys(dir); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "orders.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := newKeys(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inventory", "orders", "reports", "support"} {
		keys, err := services.ReadKeys(dir, name)
		if err != nil || len(keys) == 0 {
			t.Fatalf("%s keys: %v", name, err)
		}
	}
	again, err := os.ReadFile(filepath.Join(dir, "orders.key"))
	if err != nil || bytes.Equal(first, again) {
		t.Errorf("a new run kept the old orders key: %v", err)
	}
}
