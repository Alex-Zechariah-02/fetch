// The mode and owner check of a trust anchor a service reads (the gateway's
// assertion key set), as the gateway checks its own: another local account
// that could rewrite the file could make the service trust what it signs.

package services

import (
	"errors"
	"os"
	"runtime"
)

// trusted refuses a file that on Unix is writable by the group or others or
// belongs to neither the service's user nor root. Windows grants access by
// ACL, which the operator sets.
func trusted(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("the file must not be writable by the group or others (chmod go-w)")
	}
	return owner(info)
}
