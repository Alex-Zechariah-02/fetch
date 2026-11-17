// The security log's size bound and its failed rotations.

package guard

import (
	"fmt"
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

// A failed rotation keeps the log writing to its active file and retries;
// the log fails only at twice its bound, so no request runs unrecorded.
func TestLogRotationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orders.log")
	l, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	l.limit = 512
	// A non-empty folder in the oldest slot cannot be removed, so each
	// rotation fails on every platform.
	oldest := fmt.Sprintf("%s.%d", path, logFiles-1)
	hold := func() {
		if err := os.MkdirAll(filepath.Join(oldest, "held"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	commit := func() error {
		return l.commit(t.Context(), record{Kind: "request.admitted", Method: "GET", Path: "/orders"})
	}
	hold()
	// commit returns after the writer's send, so l.size is read in order.
	for l.size < 2*l.limit-300 {
		if err := commit(); err != nil {
			t.Fatalf("a commit while the rotation fails: %v", err)
		}
	}
	if err := os.RemoveAll(oldest); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatalf("a commit after the rotation recovered: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no rotation once possible: %v", err)
	}
	hold()
	var refused error
	for range 40 {
		if refused = commit(); refused != nil {
			break
		}
	}
	if refused == nil {
		t.Fatal("commits past twice the bound were admitted")
	}
}
