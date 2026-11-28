// Dedicated eviction reserve recovery when the security log has no disk space.

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// While the log refuses admissions for want of space (noSpace), an eviction
// record is written through the eviction reserve before its file is deleted,
// and admission stays refused until recovery writes log.recovered.
func TestGuardEvictionReserveRecoversFullDisk(t *testing.T) {
	l, dir := archived(t, Storage{ArchiveBytes: 1 << 30, Reserve: 1 << 20})
	defer l.close()

	for range 4 {
		if err := admit(l, strings.Repeat("M", 1024)); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "archived files and both reserves", func() bool {
		archivedFiles, _ := listRotated(filepath.Join(dir, "archive"), "orders-security.log")
		_, err1 := os.Stat(filepath.Join(dir, "orders-security.reserve"))
		_, err2 := os.Stat(filepath.Join(dir, "orders-security.evict.reserve"))
		return len(archivedFiles) >= 1 && err1 == nil && err2 == nil
	})
	if got := l.archive.held.Load(); got != 1<<20 {
		t.Fatalf("log_reserve_bytes = %d, want %d", got, 1<<20)
	}

	// Simulate another writer taking the general reserve's space so noSpace is set.
	_ = os.Remove(filepath.Join(dir, "orders-security.reserve"))
	l.fail(&os.PathError{Op: "write", Err: fullDisk()})

	if err := admit(l, "GET"); err == nil {
		t.Fatal("admission succeeded while noSpace was set")
	}

	// Wake the archiver: it must record log.evicted via the eviction reserve
	// and delete the evicted file while noSpace is still set.
	l.archive.signal()
	waitUntil(t, "an eviction under noSpace", func() bool {
		return l.archive.evictions.Load() >= 1
	})

	if _, err := os.Stat(filepath.Join(dir, "orders-security.evict.reserve")); !os.IsNotExist(err) {
		t.Fatalf("eviction reserve still exists after eviction under noSpace: %v", err)
	}

	waitUntil(t, "admission to resume after recovery", func() bool {
		return admit(l, "GET") == nil
	})
	l.close()

	all := records(t, dir)
	if count(all, "log.evicted") < 1 {
		t.Fatal("no log.evicted record written")
	}
	if count(all, "log.recovered") < 1 {
		t.Fatal("no log.recovered record written")
	}
}

// Under noSpace the archiver evicts one file per failed write, so a full
// disk costs the oldest file, not the whole history, before the writer tries
// again.
func TestGuardNoSpaceEvictsOneFile(t *testing.T) {
	l, dir := archived(t, Storage{ArchiveBytes: 1 << 30, Reserve: 1 << 20})
	defer l.close()

	for range 10 {
		if err := admit(l, strings.Repeat("M", 1024)); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "three archived files and the eviction reserve", func() bool {
		archivedFiles, _ := listRotated(filepath.Join(dir, "archive"), "orders-security.log")
		_, err := os.Stat(filepath.Join(dir, "orders-security.evict.reserve"))
		return len(archivedFiles) >= 3 && err == nil
	})

	l.fail(&os.PathError{Op: "write", Err: fullDisk()})
	waitUntil(t, "an eviction under noSpace", func() bool {
		return l.archive.evictions.Load() >= 1
	})
	time.Sleep(300 * time.Millisecond)
	if n := l.archive.evictions.Load(); n != 1 {
		t.Fatalf("%d files evicted before the writer tried again, want 1", n)
	}
}

func TestFailedEvictionLeavesPressurePending(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log := &securityLog{path: filepath.Join(dir, "orders-security.log"), limit: 1 << 20}
	if err := log.fail(fullDisk()); !errors.Is(err, errLogFailed) {
		t.Fatalf("log failure result: %v", err)
	}
	if health := log.currentHealth(); health != healthNoSpace {
		t.Fatalf("log health %v, want no space", health)
	}

	path := rotatedName(log.path, time.Unix(0, 0)) + ".gz"
	if err := os.WriteFile(path, []byte("invalid archive metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := rotatedFiles(log.path, "")
	if err != nil || len(files) != 1 || !files[0].packed {
		t.Fatalf("rotated files %v, error %v", files, err)
	}
	archiver := &archiver{live: dir, log: log, ctx: t.Context()}
	archiver.trim()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed eviction removed its file: %v", err)
	}
	if selected := archiver.underPressure(files, archiver.spaceSeen).at; selected != 0 {
		t.Fatalf("failed eviction left selection %d, want the pending file", selected)
	}
}

func TestMakeReserveNeverTruncatesInPlace(t *testing.T) {
	dir := t.TempDir()
	reserve := filepath.Join(dir, "orders-security.reserve")
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, reserve+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := makeReserve(reserve, 4096); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-me" {
		t.Fatalf("makeReserve overwrote linked .tmp target in place: got %d bytes (%q), want \"keep-me\"", len(got), got[:min(len(got), 16)])
	}
}
