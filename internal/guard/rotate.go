// Security log files: opening the active file, rotating it at its size
// bound, and keeping it open when a rotation fails.

package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// keepActive handles a failed rotation, such as a rotated file held open on
// Windows or an active file moved away: the batch is already synced, so the
// active path is reopened and the rotation retried at each later write. The
// active file may grow to twice its bound; past that, or when the path cannot
// be reopened, the log fails, so no request runs without a record.
func (l *securityLog) keepActive(err error) error {
	if l.size >= 2*l.limit {
		return l.fail(err)
	}
	if reopenErr := l.open(); reopenErr != nil {
		return l.fail(errors.Join(err, reopenErr))
	}
	if !l.rotating {
		l.rotating = true
		fmt.Fprintf(os.Stderr, "security log rotation failed; writing continues to %s and the rotation is retried: %v\n", l.path, err)
	}
	return nil
}

// open continues the active file at its logical end, creating it private to
// this user; a zero tail a stopped process left is overwritten in place.
func (l *securityLog) open() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	end, err := logicalEnd(file)
	if err != nil {
		return errors.Join(err, file.Close())
	}
	l.file, l.size, l.filled = file, end, info.Size()
	l.written.Store(l.size)
	return nil
}

// rotate closes the full active file as <path>.1, shifting older files up
// and deleting the oldest, so the log keeps at most logFiles files.
func (l *securityLog) rotate() error {
	if err := errors.Join(l.trim(), l.file.Close()); err != nil {
		return err
	}
	if err := os.Remove(fmt.Sprintf("%s.%d", l.path, logFiles-1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for n := logFiles - 2; n >= 1; n-- {
		err := os.Rename(fmt.Sprintf("%s.%d", l.path, n), fmt.Sprintf("%s.%d", l.path, n+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.open()
}
