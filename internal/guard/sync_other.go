//go:build !linux

// Other systems: the active security log file is written at its end and
// synced with File.Sync (FlushFileBuffers on Windows); the gateway measured
// no gain from a zero-filled file on NTFS.

package guard

import "os"

const prefill = false

func syncData(file *os.File) error { return file.Sync() }
