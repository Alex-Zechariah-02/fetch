// A full disk on Linux, where /dev/full refuses every write for want of
// space: the writer releases the reserve file and tries once more.

//go:build linux

package guard

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

// A batch that meets a full disk releases the reserve so the write can be
// tried again, and is refused when the retry fails too.
func TestLogFullDiskReleasesReserve(t *testing.T) {
	t.Parallel()
	l, _ := archived(t, Storage{ArchiveBytes: 1 << 30, Reserve: 64 << 10})
	defer l.close()
	waitUntil(t, "the reserve", func() bool { _, err := os.Stat(l.reservePath); return err == nil })
	if err := admit(l, "GET"); err != nil {
		t.Fatal(err)
	}
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	active := l.file
	t.Cleanup(func() { active.Close() })
	l.file = full // the writer is idle between batches
	if err := admit(l, "GET"); err == nil {
		t.Fatal("a record admitted on a full disk")
	}
	if _, err := os.Stat(l.reservePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the reserve survived a full disk: %v", err)
	}
}
