// The security log's size bound.

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A log past its size bound rotates, keeping at most logFiles files, and
// a method of any length is recorded at most maxMethod bytes long.
func TestLogRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orders.log")
	l, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.limit = 512
	for range 4 * logFiles {
		if err := l.commit(t.Context(), record{Kind: "request.admitted", Method: strings.Repeat("M", 4096), Path: "/orders"}); err != nil {
			t.Fatal(err)
		}
	}
	l.close()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != logFiles {
		t.Fatalf("%d files, want %d", len(files), logFiles)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil || len(data) > 1024 || strings.Contains(string(data), strings.Repeat("M", maxMethod+1)) {
			t.Fatalf("%s: %d bytes (%v)", file.Name(), len(data), err)
		}
	}
}
