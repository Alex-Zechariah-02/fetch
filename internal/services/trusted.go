// The mode and owner checks of the files a service reads: a trust anchor or
// settings file (the gateway's assertion key set, the signing settings, the
// API's certificate and client CA) must not be writable by another local
// account, as the gateway checks its own; a secret (the control secret, an
// internal call key, a private key) must not be readable by one either.

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

// private refuses a file that on Unix any group or other account may read or
// write, or that belongs to neither the service's user nor root (chmod 600).
func private(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("the file must be readable by its owner only (chmod 600)")
	}
	return owner(info)
}

// checkFile opens nothing: it judges the file at path with check.
func checkFile(path string, check func(os.FileInfo) error) error {
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
