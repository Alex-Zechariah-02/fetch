// A full disk on Linux, where /dev/full refuses every write for want of
// space: the writer releases the reserve file and tries once more.

//go:build linux

package guard

import (
	"errors"
	"io/fs"
	"os"
	"sync/atomic"
	"testing"
)

// A batch that meets a full disk releases the reserve so the write can be
// tried again, and is refused when the retry fails too.
func TestLogFullDiskReleasesReserve(t *testing.T) {
	t.Parallel()
	var opens atomic.Int32
	opener := func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if opens.Add(1) == 1 {
			return os.OpenFile(name, flag, perm)
		}
		return os.OpenFile("/dev/full", os.O_RDWR, 0)
	}
	l, _ := archived(t, Storage{ArchiveBytes: 1 << 30, Reserve: 64 << 10}, withLimit(1), withOpener(opener))
	defer l.close()
	waitUntil(t, "the reserve", func() bool { _, err := os.Stat(l.reservePath); return err == nil })
	// The first admission exceeds the 1-byte limit and rotates onto /dev/full.
	if err := admit(l, "GET"); err != nil {
		t.Fatal(err)
	}
	if err := admit(l, "GET"); err == nil {
		t.Fatal("a record admitted on a full disk")
	}
	if _, err := os.Stat(l.reservePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the reserve survived a full disk: %v", err)
	}
}
