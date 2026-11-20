// Linux: the active security log file is zero-filled and synced with
// fdatasync; full-disk and quota errors are told apart from others.

package guard

import (
	"errors"
	"os"
	"syscall"
)

const prefill = true

// syncData flushes the file's data and only the metadata needed to read it
// back (fdatasync(2)); a write into blocks already written and synced
// changes neither size nor allocation, so no journal commit is needed.
func syncData(file *os.File) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var syncErr error
	err = conn.Control(func(fd uintptr) {
		for {
			syncErr = syscall.Fdatasync(int(fd))
			if syncErr != syscall.EINTR {
				return
			}
		}
	})
	if err != nil {
		return err
	}
	if syncErr != nil {
		return &os.PathError{Op: "fdatasync", Path: file.Name(), Err: syncErr}
	}
	return nil
}

// noSpace reports a write refused because the file system or the user's
// quota has no space left.
func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
