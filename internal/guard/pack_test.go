// Tests for reading packed guard archive metadata headers.

package guard

import (
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// stored rejects a compressed archive whose header carries malformed times.
func TestStoredRefusesBadHeaderTimes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	name := "orders-security-2026-01-01T00-00-00.000.log.gz"
	path := filepath.Join(dir, name)
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(out)
	zw.Comment = "first=not-a-time last=still-bad sha256=abc bytes=1"
	if _, err := zw.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(zw.Close(), out.Close()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stored(logFile{name: name, dir: dir, bytes: info.Size(), packed: true}); err == nil {
		t.Fatal("stored accepted malformed header timestamps")
	}
}
