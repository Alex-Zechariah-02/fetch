// Whole-file writes of the demo tool: new export and key files, and
// replaced operator files; neither leaves a partial file in place.

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// writeNewFile writes data whole beside path and links it into place: a new
// export or key file is never overwritten, only this user reads it (0600),
// and a command stopped while writing leaves no partial file at path.
func writeNewFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".new-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Chmod(0o600), file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Link(temporary, path)
}

// Operator updates replace a whole regular file. The temporary file is owned
// by this invocation; a failed write cannot leave a partially parsed key set.
func replaceOperatorFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return errors.New("operator target must be an existing regular file")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".fetch-operator-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	// 0600 before any write, so the rename lands a file no other user can read.
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
