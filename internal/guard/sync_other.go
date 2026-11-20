//go:build !linux

// Other systems: the active security log file is written at its end and
// synced with File.Sync (FlushFileBuffers on Windows); the gateway measured
// no gain from a zero-filled file on NTFS. Windows reports a full disk as
// ERROR_DISK_FULL or ERROR_HANDLE_DISK_FULL.

package guard

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

const prefill = false

func syncData(file *os.File) error { return file.Sync() }

const (
	errorDiskFull       = syscall.Errno(112)
	errorHandleDiskFull = syscall.Errno(39)
)

// noSpace reports a write refused because the file system has no space left.
func noSpace(err error) bool {
	if runtime.GOOS == "windows" {
		return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
	}
	return errors.Is(err, syscall.ENOSPC)
}
