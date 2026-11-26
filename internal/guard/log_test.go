// The security log's rotation, archive, eviction and recovery.

package guard

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// archived opens a log under a fresh folder that archives into its
// "archive" folder with s's other settings.
func archived(t *testing.T, s Storage, opts ...logOption) (*securityLog, string) {
	t.Helper()
	dir := t.TempDir()
	s.Archive = filepath.Join(dir, "archive")
	if s.MinFree == 0 {
		s.MinFree = 1 // a developer's full disk must not evict what a test counts
	}
	allOpts := append([]logOption{withLimit(512)}, opts...)
	l, err := openLog(filepath.Join(dir, "orders-security.log"), s, allOpts...)
	if err != nil {
		t.Fatal(err)
	}
	return l, dir
}

// records reads every record of the log's files, plain or compressed.
func records(t *testing.T, dir string) []record {
	t.Helper()
	var all []record
	filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.Contains(path, "security") || strings.HasSuffix(path, ".reserve") {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		var reader io.Reader = file
		if strings.HasSuffix(path, packedSuffix) {
			zr, err := gzip.NewReader(file)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			reader = zr
		}
		lines := bufio.NewScanner(reader)
		for lines.Scan() {
			var r record
			if json.Unmarshal(lines.Bytes(), &r) == nil {
				all = append(all, r)
			}
		}
		return nil
	})
	return all
}

func count(rs []record, kind string) int {
	n := 0
	for _, r := range rs {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func waitUntil(t *testing.T, what string, done func() bool) {
	t.Helper()
	for limit := time.Now().Add(10 * time.Second); !done(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(limit) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func admit(l *securityLog, method string) error {
	return l.commit(context.Background(), &record{Kind: "request.admitted", Method: method, Path: "/orders"})
}

// A log past its size bound rotates; each rotated file is compressed into
// the archive, recorded, then deleted from the log folder, and a method of
// any length is recorded at most maxMethod bytes long.
func TestLogRotates(t *testing.T) {
	l, dir := archived(t, Storage{ArchiveBytes: 1 << 30})
	for range 4 * logFiles {
		if err := admit(l, strings.Repeat("M", 4096)); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "the archive", func() bool { files, _ := listRotated(dir, "orders-security.log"); return len(files) == 0 })
	l.close()
	packed, err := listRotated(filepath.Join(dir, "archive"), "orders-security.log")
	if err != nil || len(packed) < 2 {
		t.Fatalf("%d archived files (%v)", len(packed), err)
	}
	all := records(t, dir)
	if count(all, "log.archived") != len(packed) {
		t.Fatalf("%d log.archived records for %d files", count(all, "log.archived"), len(packed))
	}
	for _, r := range all {
		if len(r.Method) > maxMethod {
			t.Fatalf("method of %d bytes", len(r.Method))
		}
	}
}

// An API upgraded from an earlier version holds <log>.1 to .7; at start
// they are compressed into the archive, recorded and deleted.
func TestLogUpgradesEarlierFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orders-security.log")
	for n := 1; n <= 3; n++ {
		line := appendRecord(nil, &record{Seq: uint64(n), Time: time.Now().UTC(), Kind: "request.admitted", Path: "/orders"})
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, n), line, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l, err := openLog(path, Storage{Archive: filepath.Join(dir, "archive"), ArchiveBytes: 1 << 30, MinFree: 1})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the earlier files archived", func() bool { files, _ := listRotated(dir, "orders-security.log"); return len(files) == 0 })
	l.close()
	archived, err := listRotated(filepath.Join(dir, "archive"), "orders-security.log")
	if err != nil || len(archived) != 3 || count(records(t, dir), "log.archived") != 3 {
		t.Fatalf("%d archived files, %d records (%v)", len(archived), count(records(t, dir), "log.archived"), err)
	}
}

// A log reopened over a zero tail, as a stopped process leaves its zero-filled
// file, continues at its last record, and a closed log holds no zeros.
func TestLogZeroTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orders.log")
	first := appendRecord(nil, &record{Seq: 1, Kind: "request.admitted", Path: "/orders"})
	if err := os.WriteFile(path, append(first, make([]byte, 4096)...), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := openLog(path, Storage{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.commit(t.Context(), &record{Kind: "request.admitted", Path: "/orders"}); err != nil {
		t.Fatal(err)
	}
	l.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if strings.ContainsRune(string(data), 0) || len(lines) != 2 || lines[0] != strings.TrimSuffix(string(first), "\n") {
		t.Fatalf("log after reopen: %q", data)
	}
}

// A rotation that cannot happen (refuse mode, log folder full) keeps the
// log writing to its active file up to twice its bound; then records are
// refused until files are moved away, and writing resumes without a restart.
func TestLogRotationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orders-security.log")
	const bound = 512
	l, err := openLog(path, Storage{Refuse: true}, withLimit(bound))
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	// The folder holds a full set of rotated files already.
	for i := range logFiles {
		name := rotatedName(path, time.Now().Add(-time.Duration(i+1)*time.Hour))
		if err := os.WriteFile(name, make([]byte, bound), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for l.written.Load() < 2*bound-300 {
		if err := admit(l, "GET"); err != nil {
			t.Fatalf("a commit while the rotation fails: %v", err)
		}
	}
	var refused error
	for range 40 {
		if refused = admit(l, "GET"); refused != nil {
			break
		}
	}
	if refused == nil {
		t.Fatal("commits past twice the bound were admitted")
	}
	moved, _ := listRotated(dir, "orders-security.log")
	for _, f := range moved {
		os.Remove(f.path())
	}
	waitUntil(t, "writing again", func() bool { return admit(l, "GET") == nil })
}

// Over the archive's bound the oldest archived file is deleted only after a
// log.evicted record naming it, and no file a record names remains.
func TestLogEvictsRecordedFirst(t *testing.T) {
	l, dir := archived(t, Storage{ArchiveBytes: 1})
	for range 6 * logFiles {
		if err := admit(l, strings.Repeat("M", 2048)); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "an eviction", func() bool { return l.archive.evictions.Load() >= 2 })
	l.close()
	all := records(t, dir)
	evicted := map[string]bool{}
	for _, r := range all {
		if r.Kind == "log.evicted" && r.Digest != "" && r.Reason == "archive_budget" {
			evicted[r.File] = true
		}
	}
	// Files holding earlier eviction records are evicted too (a 1-byte
	// budget keeps nothing), so at least the latest record remains.
	if len(evicted) < 1 {
		t.Fatal("no eviction record")
	}
	for name := range evicted {
		if _, err := os.Stat(filepath.Join(dir, "archive", name+packedSuffix)); err == nil {
			t.Fatalf("%s recorded as evicted but present", name)
		}
	}
}

// A failed write replaces the active file without a restart: the batch is
// refused, the next attempt opens a new file, and log.recovered names the
// suspect file; a full disk is waited out the same way.
func TestLogRecovers(t *testing.T) {
	for _, fault := range []string{"sync_failed", "storage_space"} {
		t.Run(fault, func(t *testing.T) {
			l, dir := archived(t, Storage{ArchiveBytes: 1 << 30})
			if err := admit(l, "GET"); err != nil {
				t.Fatal(err)
			}
			if fault == "sync_failed" {
				l.file.Close() // the file fails under the writer
			} else {
				// Only the writer touches the trouble state; nothing else runs now.
				l.fail(&os.PathError{Op: "write", Err: fullDisk()})
			}
			if err := admit(l, "GET"); err == nil {
				t.Fatal("a record admitted while the log could not write")
			}
			waitUntil(t, "writing again", func() bool { return admit(l, "GET") == nil })
			l.close()
			for _, r := range records(t, dir) {
				if r.Kind == "log.recovered" && r.Reason == fault {
					return
				}
			}
			t.Fatalf("no log.recovered record with reason %s", fault)
		})
	}
}

// The reserve file is made, released once, and made again.
func TestLogReserve(t *testing.T) {
	t.Parallel()
	l, _ := archived(t, Storage{ArchiveBytes: 1 << 30, Reserve: 64 << 10}, withReservePause(0))
	defer l.close()
	waitUntil(t, "the reserve", func() bool { _, err := os.Stat(l.reservePath); return err == nil })
	if !l.releaseReserve() || l.releaseReserve() {
		t.Fatal("the reserve was not released exactly once")
	}
	waitUntil(t, "the reserve made again", func() bool { _, err := os.Stat(l.reservePath); return err == nil })
}

// fullDisk is the error a write to a full disk gives on this system.
func fullDisk() error {
	if runtime.GOOS == "windows" {
		return syscall.Errno(112) // ERROR_DISK_FULL
	}
	return syscall.ENOSPC
}
