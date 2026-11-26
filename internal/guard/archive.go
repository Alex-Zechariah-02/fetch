// The archiver: one goroutine beside each API's log writer, as the
// gateway runs one. After each rotation, and every archiveCheck, it
// compresses each rotated file of the log folder into the archive folder
// (or, while that fails, into the log folder), records log.archived through
// the writer and only then deletes the original; compressed files left in
// the log folder move once the archive works. It then evicts (evict.go) and
// keeps the reserve file. It never runs on the request path.

package guard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// archiveCheck is how often the archiver looks without a rotation.
const archiveCheck = 10 * time.Second

// reservePause is how long the reserve is not made again after a release,
// so a disk near full does not release and rewrite it over and over.
var reservePause = time.Minute

type archiver struct {
	log                   *securityLog
	live, dir             string
	budget                int64
	minFree               float64
	reserve               int64
	generalReserve        int64
	evictReserve          int64
	wake, stop, done      chan struct{}
	halted                sync.Once
	ctx                   context.Context
	cancel                context.CancelFunc
	failing               bool          // the archive failed at the last pass; archiver only
	spaceSeen             uint64        // the spaceFails count last answered by an eviction; archiver only
	released              atomic.Int64  // when the writer last released the general reserve (Unix ns)
	evictReleased         atomic.Int64  // when the writer last released the eviction reserve (Unix ns)
	pause                 time.Duration // how long a reserve is not made again after release
	usable                atomic.Bool
	stored, waiting, held atomic.Int64
	freeLog, freeArchive  atomic.Int64
	evictions, pressure   atomic.Int64
}

func newArchiver(l *securityLog, s Storage) *archiver {
	ctx, cancel := context.WithCancel(context.Background())
	general, evict := reserveSplit(s.Reserve)
	r := &archiver{log: l, live: filepath.Dir(l.path), dir: s.Archive, budget: s.ArchiveBytes, minFree: float64(s.MinFree) / 100,
		reserve: s.Reserve, generalReserve: general, evictReserve: evict, pause: reservePause, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	if s.Reserve > 0 {
		l.reservePath = reserveName(l.path)
		l.evictReservePath = evictReserveName(l.path)
	}
	r.usable.Store(true)
	r.freeLog.Store(-1)
	r.freeArchive.Store(-1)
	return r
}

// signal wakes the archiver without waiting; nil ignores it.
func (r *archiver) signal() {
	if r == nil {
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *archiver) run() {
	defer close(r.done)
	tick := time.NewTicker(archiveCheck)
	defer tick.Stop()
	for {
		r.pass()
		select {
		case <-r.stop:
			return
		case <-r.wake:
		case <-tick.C:
		}
	}
}

// halt stops the archiver and waits for its pass; nil ignores it. A file
// half done stays as it was and is done at the next start.
func (r *archiver) halt() {
	if r == nil {
		return
	}
	r.halted.Do(func() {
		r.cancel()
		close(r.stop)
	})
	<-r.done
}

// pass archives what waits, then evicts and keeps the reserve.
func (r *archiver) pass() {
	r.note(r.probe())
	files, err := rotatedFiles(r.log.path, r.dir)
	if err != nil {
		return
	}
	for _, f := range files {
		if r.ctx.Err() != nil {
			return
		}
		if f.dir != r.live {
			continue
		}
		if err := r.archive(f); err != nil {
			fmt.Fprintf(os.Stderr, "security log file %s not archived yet: %v\n", f.name, err)
			break
		}
	}
	if !r.log.refuse {
		r.trim()
	}
	r.keepReserve()
	r.measure()
}

// archive compresses or moves one rotated file of the log folder, records
// it and deletes the original.
func (r *archiver) archive(f logFile) error {
	target, where := r.live, "live"
	if r.usable.Load() && !(r.log.refuse && r.budget > 0 && r.stored.Load() >= r.budget) {
		target, where = r.dir, "archive"
	}
	var e record
	var err error
	switch {
	case target == r.live && f.packed:
		return nil
	case f.packed:
		e, err = place(f, target)
	default:
		e, err = pack(f.path(), target)
	}
	if err != nil {
		if target == r.dir {
			r.usable.Store(false)
		}
		return err
	}
	e.Kind, e.API, e.File, e.Target = "log.archived", r.log.api(), f.plain(), where
	// Not cancelled by halt: a record the writer took must be followed by
	// the deletion; commit bounds the wait itself.
	if err := r.log.commit(context.Background(), &e); err != nil {
		return err
	}
	return errors.Join(os.Remove(f.path()), syncDir(r.live))
}

// place copies a compressed file into dir under its name and describes it.
func place(f logFile, dir string) (record, error) {
	e, err := stored(f)
	if err != nil {
		return record{}, err
	}
	target := filepath.Join(dir, f.name)
	if err := copyFile(f.path(), target+".tmp"); err != nil {
		return record{}, errors.Join(err, os.Remove(target+".tmp"))
	}
	if err := os.Rename(target+".tmp", target); err != nil {
		return record{}, errors.Join(err, os.Remove(target+".tmp"))
	}
	e.Archived = f.bytes
	return e, syncDir(dir)
}

// copyFile copies src to a new file dst and syncs it.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}

// probe checks the archive folder takes a synced write, creating it first.
func (r *archiver) probe() bool {
	// 0700 keeps the archive folder this user's own.
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return false
	}
	path := filepath.Join(r.dir, "."+filepath.Base(r.log.path)+".probe")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_, err = file.Write([]byte{'\n'})
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close(), os.Remove(path)) == nil
}

// note publishes the archive's health and reports each change once.
func (r *archiver) note(usable bool) {
	r.usable.Store(usable)
	if usable == r.failing {
		state := "unavailable; rotated files are compressed in the log folder"
		if usable {
			state = "available again"
		}
		fmt.Fprintf(os.Stderr, "security log archive folder %s %s\n", r.dir, state)
	}
	r.failing = !usable
}
