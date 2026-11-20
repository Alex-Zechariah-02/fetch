// When the log cannot take a batch. A disk without space: the writer first
// deletes the reserve file and writes again (reserve.go); with no reserve
// left the batch is refused and the write tried again at most once per
// retryEvery. A failed write or sync replaces the active file: after a
// failed sync the system may have dropped written pages, so nothing later
// written to that file proves durable. The suspect file is kept under its
// rotated name, a new file opened, and log.recovered names the suspect file
// and the end of its last synced batch. Under refuse, a full log folder
// refuses batches until files are moved away. No state latches: requests
// are refused only while no record can be stored.

package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// retryEvery bounds how often a log that cannot write tries again: often
	// enough that admission resumes within a second.
	retryEvery = time.Second
	// slowSave is the save wait counted as slow: a twentieth of commitWait.
	slowSave = 100 * time.Millisecond
)

var errFolderFull = errors.New("security log folder full; move rotated files away (refuse mode)")

// trouble is the writer's recovery state; only the writer uses it.
type trouble struct {
	refuse      bool      // never delete; a full folder refuses records
	reason      string    // why the log went down: sync_failed or storage_space
	since       time.Time // when it went down
	tried       time.Time // the last attempt to write again
	suspect     string    // the replaced file's rotated name
	suspectEnd  int64     // the end of its last synced batch
	fresh       bool      // the active file was opened by a recovery and holds nothing synced
	synced      int64     // the end of the last synced batch of the active file
	reservePath string    // the reserve file ("" for none)
	lastName    time.Time // the time in the last rotated name, which only rises
}

// fail refuses the batch whose write failed with err: for want of space the
// log waits for space, any other failure replaces the active file.
func (l *securityLog) fail(err error) error {
	l.tried = time.Now()
	if errors.Is(err, errFolderFull) {
		if l.full.CompareAndSwap(false, true) {
			fmt.Fprintf(os.Stderr, "security log folder full; admission refused until rotated files are moved away: %v\n", err)
		}
		return errLogFailed
	}
	l.reason, l.since = "sync_failed", time.Now()
	flag := &l.down
	if spaceError(err) {
		l.reason, flag = "storage_space", &l.noSpace
	} else {
		l.suspect, l.suspectEnd = "", l.synced
	}
	if flag.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "security log cannot write (%s); admission refused until it can: %v\n", l.reason, err)
	}
	return errLogFailed
}

// ready reports whether the log can take a batch, trying again at most once
// per retryEvery: a down log replaces its file, then any log that was down
// or out of space writes log.recovered, which must be synced first.
func (l *securityLog) ready() bool {
	if l.full.Load() {
		if time.Since(l.tried) < retryEvery {
			return false
		}
		l.tried = time.Now()
		if l.folderFull() {
			return false
		}
		l.full.Store(false)
	}
	if !l.down.Load() && !l.noSpace.Load() {
		return true
	}
	if time.Since(l.tried) < retryEvery {
		return false
	}
	l.tried = time.Now()
	if l.down.Load() {
		if err := l.reopen(); err != nil {
			fmt.Fprintf(os.Stderr, "security log file not replaced yet: %v\n", err)
			return false
		}
	}
	lost := l.lost.Swap(0)
	r := record{Seq: l.seq.Add(1), Time: time.Now().UTC(), Kind: "log.recovered", Reason: l.reason, File: l.suspect, Offset: l.suspectEnd,
		Lost: lost, DurationMS: float64(time.Since(l.since)) / float64(time.Millisecond)}
	if err := l.persist(appendRecord(nil, &r)); err != nil {
		l.lost.Add(lost)
		l.down.Store(false)
		l.noSpace.Store(false)
		l.fail(err)
		return false
	}
	if l.down.Swap(false) {
		l.recoveries.Add(1)
	}
	l.noSpace.Store(false)
	l.fresh = false
	fmt.Fprintf(os.Stderr, "security log writing again (%s)\n", l.reason)
	return true
}

// reopen closes the suspect file and moves it aside (deleting one this
// recovery opened that holds nothing), then opens a new active file.
func (l *securityLog) reopen() error {
	if l.file != nil {
		// The file is already suspect; its close error adds nothing.
		_ = l.file.Close()
		l.file = nil
	}
	if _, err := os.Lstat(l.path); err == nil {
		if l.fresh {
			if err := os.Remove(l.path); err != nil {
				return err
			}
		} else if err := l.setAside(); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	l.file, l.size, l.filled, l.synced, l.fresh = file, 0, 0, 0, true
	l.written.Store(0)
	l.archive.signal()
	return syncDir(filepath.Dir(l.path))
}

// lose counts the records of a refused batch nobody waits for, and the
// loss count it carried, as lost.
func (l *securityLog) lose(batch []entry, carried uint64) {
	n := carried
	for _, e := range batch {
		if e.done == nil {
			n++
		}
	}
	l.lost.Add(n)
	l.dropped.Add(n - carried)
}

// unavailable reports whether the log refuses records now.
func (l *securityLog) unavailable() bool {
	return l.down.Load() || l.noSpace.Load() || l.full.Load()
}
