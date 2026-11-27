// Security log files: opening the active file, rotating it at its size
// bound to a name holding the UTC time (as the gateway names its rotated
// files), and keeping it open when a rotation fails. Rotation deletes
// nothing: the archiver moves, compresses and evicts rotated files.

package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// rotatedLayout is the time in a rotated file's name; it holds no colon,
// which Windows refuses in file names.
const rotatedLayout = "2006-01-02T15-04-05.000"

// keepActive handles a failed rotation, such as a rotated file held open on
// Windows or an active file moved away: the batch is already synced, so the
// active path is reopened and the rotation retried at each later write. The
// active file may grow to twice its bound; past that, or when the path cannot
// be reopened, the file is replaced (recover.go).
func (l *securityLog) keepActive(err error) error {
	if l.size >= 2*l.limit {
		return l.fail(err)
	}
	// A full folder (refuse) left the active file open; nothing to reopen.
	if errors.Is(err, errFolderFull) {
		return nil
	}
	if reopenErr := l.open(); reopenErr != nil {
		return l.fail(errors.Join(err, reopenErr))
	}
	if l.moveHealth(healthWriting, healthRotating) {
		fmt.Fprintf(os.Stderr, "security log rotation failed; writing continues to %s and the rotation is retried: %v\n", l.path, err)
	}
	return nil
}

// open continues the active file at its logical end, creating it private to
// this user; a zero tail a stopped process left is overwritten in place.
func (l *securityLog) open() error {
	openFn := l.openFile
	if openFn == nil {
		openFn = os.OpenFile
	}
	file, err := openFn(l.path, os.O_CREATE|os.O_RDWR, 0o600)
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

// rotate closes the full active file under its rotated name and opens a new
// one, then wakes the archiver. Under refuse it first checks the log folder
// has room for another file.
func (l *securityLog) rotate() error {
	if l.refuse && l.folderFull() {
		l.moveHealth(healthWriting, healthRotating)
		return errFolderFull
	}
	err := errors.Join(l.trim(), l.file.Close())
	l.file = nil
	if err != nil {
		return err
	}
	if err := l.setAside(); err != nil {
		return err
	}
	if err := l.open(); err != nil {
		return err
	}
	l.archive.signal()
	return nil
}

// setAside renames the active file to its rotated name and syncs the
// folder. A name never repeats: its time is later than the last one used,
// and a millisecond later for each name taken in either folder, plain or
// compressed (an evicted file's record would otherwise name two files).
func (l *securityLog) setAside() error {
	at := time.Now()
	if !at.After(l.lastName) {
		at = l.lastName.Add(time.Millisecond)
	}
	for {
		name := rotatedName(l.path, at)
		taken, err := l.taken(filepath.Base(name))
		if err != nil {
			return err
		}
		if !taken {
			if err := os.Rename(l.path, name); err != nil {
				return err
			}
			l.suspect, l.lastName = filepath.Base(name), at
			return syncDir(filepath.Dir(l.path))
		}
		at = at.Add(time.Millisecond)
	}
}

// taken reports whether a rotated file of that name exists in the log or
// archive folder, plain or compressed.
func (l *securityLog) taken(name string) (bool, error) {
	dirs := []string{filepath.Dir(l.path)}
	if l.archive != nil {
		dirs = append(dirs, l.archive.dir)
	}
	for _, dir := range dirs {
		for _, candidate := range []string{name, name + packedSuffix} {
			_, err := os.Lstat(filepath.Join(dir, candidate))
			if err == nil {
				return true, nil
			}
			// A folder that is missing, or is a file, holds no such name.
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				return false, err
			}
		}
	}
	return false, nil
}

// rotatedName is the path a file rotated at at gets: <stem>-<time><ext>.
func rotatedName(active string, at time.Time) string {
	dir, base := filepath.Split(active)
	ext := filepath.Ext(base)
	return filepath.Join(dir, strings.TrimSuffix(base, ext)+"-"+at.UTC().Format(rotatedLayout)+ext)
}
