// Writing the active security log file: zero-filling ahead of the writer,
// writing in place at the logical end, and trimming the zero tail at rotation
// and close.
//
// On ext4 an append changes the file's size and allocation, so every sync
// commits the journal. Writing into blocks already zero-filled and synced
// changes neither, so fdatasync flushes only the data (the technique of
// PostgreSQL's wal_init_zero, as the gateway's audit log uses it). The file
// is filled in steps of fillStep, so the zero tail stays within one step.

package guard

import (
	"bytes"
	"errors"
	"io"
	"os"
)

const fillStep = 1 << 20

// zeros is written at every fill step and never written to, so its pages
// stay the shared zero page.
var zeros [fillStep]byte

// persist writes data at the logical end and makes it durable.
func (l *securityLog) persist(data []byte) error {
	if err := l.reserve(l.size + int64(len(data))); err != nil {
		return err
	}
	if _, err := l.file.WriteAt(data, l.size); err != nil {
		return err
	}
	l.size += int64(len(data))
	return l.sync()
}

// sync flushes the active file: fdatasync for a zero-filled file, whose
// record writes change no size, else fsync, as an append needs.
func (l *securityLog) sync() error {
	if prefill {
		return syncData(l.file)
	}
	return l.file.Sync()
}

// reserve zero-fills the file up to the fillStep boundary past need, but not
// past the rotation size unless need is, and syncs the zeros.
func (l *securityLog) reserve(need int64) error {
	if !prefill || need <= l.filled {
		return nil
	}
	target := min((need+fillStep-1)/fillStep*fillStep, max(l.limit, need))
	for at := l.filled; at < target; {
		n, err := l.file.WriteAt(zeros[:min(int64(fillStep), target-at)], at)
		if err != nil {
			return err
		}
		at += int64(n)
	}
	if err := l.file.Sync(); err != nil {
		return err
	}
	l.filled = target
	return nil
}

// trim truncates the active file to its logical end and syncs the new size,
// so a rotated or closed file holds no zero tail.
func (l *securityLog) trim() error {
	if l.filled <= l.size {
		return nil
	}
	if err := l.file.Truncate(l.size); err != nil {
		return err
	}
	l.filled = l.size
	return l.file.Sync()
}

// logicalEnd is the offset just past the last non-zero byte of file: its
// size, less a zero tail a stopped process left unfilled.
func logicalEnd(file *os.File) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	end := info.Size()
	window := make([]byte, min(end, fillStep))
	for end > 0 {
		base := max(end-int64(len(window)), 0)
		chunk := window[:end-base]
		if _, err := file.ReadAt(chunk, base); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if kept := len(bytes.TrimRight(chunk, "\x00")); kept > 0 {
			return base + int64(kept), nil
		}
		end = base
	}
	return 0, nil
}
