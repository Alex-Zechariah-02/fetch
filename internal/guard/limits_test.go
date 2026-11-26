// Rule-table bounds and bounded file reads: exact minimum count and window
// pass, any invalid bound is refused, and readFile reads up to exactly limit
// bytes while refusing one byte more.

package guard

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuleTableAndFileSizeLimits(t *testing.T) {
	// Exact lower bounds (Count=1, Window=1ms, leading '/') are accepted.
	if _, err := newTable([]Operation{
		{ID: "min", API: "orders", Method: http.MethodGet, Target: "/ok", Count: 1, Window: time.Millisecond},
	}); err != nil {
		t.Fatalf("valid rule at lower bounds refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		op   Operation
	}{
		{"zero count", Operation{ID: "c", API: "orders", Method: http.MethodGet, Target: "/ok", Count: 0, Window: time.Second}},
		{"sub-ms window", Operation{ID: "w", API: "orders", Method: http.MethodGet, Target: "/ok", Count: 1, Window: time.Millisecond - 1}},
		{"missing slash", Operation{ID: "t", API: "orders", Method: http.MethodGet, Target: "ok", Count: 1, Window: time.Second}},
	} {
		if _, err := newTable([]Operation{tc.op}); err == nil {
			t.Errorf("%s: invalid rule accepted, want error", tc.name)
		}
	}

	dir := t.TempDir()
	exactPath := filepath.Join(dir, "exact.dat")
	exactBytes := bytes.Repeat([]byte("a"), maxFile)
	if err := os.WriteFile(exactPath, exactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFile(exactPath, maxFile)
	if err != nil {
		t.Fatalf("file at exact %d-byte limit refused: %v", maxFile, err)
	}
	if len(got) != maxFile {
		t.Fatalf("readFile returned %d bytes for %d-byte file, want %d", len(got), maxFile, maxFile)
	}

	overPath := filepath.Join(dir, "over.dat")
	if err := os.WriteFile(overPath, bytes.Repeat([]byte("a"), maxFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(overPath, maxFile); err == nil {
		t.Fatalf("file of %d bytes accepted under %d-byte limit", maxFile+1, maxFile)
	}
}
