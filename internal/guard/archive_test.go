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
