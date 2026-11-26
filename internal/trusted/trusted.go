// Mode, owner and bounded-read checks for operator files: a trust anchor or
// settings file must not be writable by another local account; a secret must
// not be readable by one either.

package trusted

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// Trusted refuses a file that on Unix is writable by the group or others or
// belongs to neither the process user nor root. Windows grants access by
// ACL, which the operator sets.
func Trusted(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("the file must not be writable by the group or others (chmod go-w)")
	}
	return owner(info)
}

// Private refuses a file that on Unix any group or other account may read or
// write, or that belongs to neither the process user nor root (chmod 600).
func Private(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("the file must be readable by its owner only (chmod 600)")
	}
	return owner(info)
}

// CheckFile opens nothing: it judges the regular file at path with check.
func CheckFile(path string, check func(os.FileInfo) error) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New(path + ": not a regular file")
	}
	if err := check(info); err != nil {
		return errors.New(path + ": " + err.Error())
	}
	return nil
}

// ReadBounded reads at most limit bytes of a regular file at path, applying
// check when not nil, and refuses a longer file.
func ReadBounded(path string, limit int64, check func(os.FileInfo) error) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if check != nil {
		if err := check(info); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New(path + " is too large")
	}
	return data, nil
}
