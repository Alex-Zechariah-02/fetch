// Archiver durability and state checks: temp file cleanup on rename failure
// and single-source-of-truth archive usability tracking.

package guard

import (
	"os"
	"path/filepath"
	"testing"
)

// When renaming the temporary copy into the archive folder fails, place
// removes the temporary file instead of leaving an orphan .tmp behind.
func TestPlaceRemovesTmpOnRenameFailure(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	archive := t.TempDir()
	src := filepath.Join(live, "orders-security-2026-01-01T00-00-00.000.log")
	if err := os.WriteFile(src, []byte(`{"kind":"request.admitted","time":"2026-01-01T00:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pack(src, live); err != nil {
		t.Fatal(err)
	}
	packedName := filepath.Base(src) + packedSuffix
	info, err := os.Stat(filepath.Join(live, packedName))
	if err != nil {
		t.Fatal(err)
	}
	// Block the destination path with a directory so os.Rename fails on every OS.
	target := filepath.Join(archive, packedName)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	f := logFile{name: packedName, dir: live, bytes: info.Size(), packed: true}
	if _, err := place(f, archive); err == nil {
		t.Fatal("place succeeded over a directory target")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("orphan temporary file remained after rename failure: %v", err)
	}
}

// When archiving into the archive folder fails, usability flips to false in
// one place so a subsequent recovery transition is detected rather than lost.
func TestArchiverFailureSyncsUsabilityState(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	archive := t.TempDir()
	src := filepath.Join(live, "orders-security-2026-01-01T00-00-00.000.log")
	if err := os.WriteFile(src, []byte(`{"kind":"request.admitted","time":"2026-01-01T00:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Block target in archive so pack fails inside r.archive.
	if err := os.Mkdir(filepath.Join(archive, filepath.Base(src)+packedSuffix), 0o700); err != nil {
		t.Fatal(err)
	}
	l := &securityLog{path: filepath.Join(live, "orders-security.log")}
	r := newArchiver(l, Storage{Archive: archive}, defaultReservePause)
	f := logFile{name: filepath.Base(src), dir: live}
	if err := r.archive(f); err == nil {
		t.Fatal("archive succeeded over a directory target")
	}
	if r.usable.Load() {
		t.Fatal("usable stayed true after archive failed")
	}
	if r.note(false) {
		t.Fatal("note(false) reported a second change after archive already marked unusable")
	}
	if !r.note(true) {
		t.Fatal("note(true) did not report recovery after archive failure")
	}
	if r.note(true) {
		t.Fatal("note(true) reported a second change when already usable")
	}
}
