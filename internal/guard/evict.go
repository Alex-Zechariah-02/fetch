// Eviction (unless refuse): the oldest file is deleted only after a synced
// log.evicted record naming it, its size, SHA-256 and first and last record
// times; the archive is kept within its bound, the log folder within
// logFiles × maxLogBytes and each disk above its free-space threshold, as
// the gateway does. Also the archiver's measurements and the reserve file.

package guard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// trim evicts until every bound holds or nothing is left to evict.
func (r *archiver) trim() {
	files, err := rotatedFiles(r.log.path, r.dir)
	if err != nil {
		return
	}
	for _, rule := range []struct {
		reason string
		pick   func([]logFile) int
	}{
		{"archive_budget", func(fs []logFile) int { return oldestOver(fs, r.dir, r.budget) }},
		{"log_budget", func(fs []logFile) int { return oldestOver(fs, r.live, logFiles*r.log.limit-r.log.written.Load()) }},
		{"disk_pressure", r.underPressure},
	} {
		for len(files) > 0 && r.ctx.Err() == nil {
			at := rule.pick(files)
			if at < 0 {
				break
			}
			if err := r.evict(files[at], rule.reason); err != nil {
				fmt.Fprintf(os.Stderr, "security log file %s not evicted yet: %v\n", files[at].name, err)
				return
			}
			files = slices.Delete(files, at, at+1)
		}
	}
}

// oldestOver picks the oldest file in dir while the files there hold more
// than bound bytes, or -1.
func oldestOver(files []logFile, dir string, bound int64) int {
	var held int64
	first := -1
	for i, f := range files {
		if f.dir != dir {
			continue
		}
		held += f.bytes
		if first < 0 {
			first = i
		}
	}
	if first < 0 || bound <= 0 || held <= bound {
		return -1
	}
	return first
}

// underPressure picks the oldest file on a disk below its threshold, or -1.
func (r *archiver) underPressure(files []logFile) int {
	for _, dir := range []string{r.live, r.dir} {
		d, err := diskOf(dir)
		if err != nil || !d.below(r.minFree) {
			continue
		}
		for i, f := range files {
			if same, err := diskOf(f.dir); err == nil && same.id == d.id {
				return i
			}
		}
	}
	return -1
}

// evict records f, then deletes it.
func (r *archiver) evict(f logFile, reason string) error {
	e, err := stored(f)
	if err != nil {
		return err
	}
	where := "live"
	if f.dir == r.dir {
		where = "archive"
	}
	e.Kind, e.API, e.File, e.Bytes, e.Reason, e.Target = "log.evicted", r.log.api(), f.plain(), f.bytes, reason, where
	// Not cancelled by halt: a record the writer already took is written,
	// so the deletion it announces must follow.
	if err := r.log.commit(context.Background(), &e); err != nil {
		return err
	}
	if err := errors.Join(os.Remove(f.path()), syncDir(f.dir)); err != nil {
		return err
	}
	r.evictions.Add(1)
	if reason == "disk_pressure" {
		r.pressure.Add(1)
	}
	return nil
}

// measure publishes the archive's bytes, the files waiting and free space.
func (r *archiver) measure() {
	files, err := rotatedFiles(r.log.path, r.dir)
	if err != nil {
		return
	}
	var stored, waiting int64
	for _, f := range files {
		switch {
		case f.dir == r.dir:
			stored += f.bytes
		case !f.packed:
			waiting++
		}
	}
	r.stored.Store(stored)
	r.waiting.Store(waiting)
	for dir, free := range map[string]func(int64){r.live: r.freeLog.Store, r.dir: r.freeArchive.Store} {
		d, err := diskOf(dir)
		if err != nil {
			d.free = -1
		}
		free(d.free)
	}
}

// reserveName is the reserve file of the active file: <stem>.reserve.
func reserveName(active string) string {
	return strings.TrimSuffix(active, filepath.Ext(active)) + ".reserve"
}

// keepReserve makes the reserve file when it is missing and the disk has
// room for it above the threshold.
func (r *archiver) keepReserve() {
	path := r.log.reservePath
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		r.held.Store(r.reserve)
		return
	}
	r.held.Store(0)
	if time.Since(time.Unix(0, r.released.Load())) < r.pause {
		return
	}
	if d, err := diskOf(r.live); err != nil || d.below(r.minFree) || (d.total > 0 && d.free < 2*r.reserve) {
		return
	}
	if err := makeReserve(path, r.reserve); err != nil {
		fmt.Fprintf(os.Stderr, "security log reserve not made yet: %v\n", err)
		return
	}
	r.held.Store(r.reserve)
}

// makeReserve writes size zero bytes to path, synced, through a temporary
// name, so a partial reserve never counts as one.
func makeReserve(path string, size int64) error {
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for at := int64(0); at < size && err == nil; at += fillStep {
		_, err = file.WriteAt(zeros[:min(fillStep, size-at)], at)
	}
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err == nil {
		err = os.Rename(path+".tmp", path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(path+".tmp"))
	}
	return syncDir(filepath.Dir(path))
}

// releaseReserve deletes the reserve file so a write that met no space can
// be tried again; only the writer calls it.
func (l *securityLog) releaseReserve() bool {
	if l.reservePath == "" || os.Remove(l.reservePath) != nil {
		return false
	}
	fmt.Fprintf(os.Stderr, "security log reserve released: the disk is full; the oldest files are evicted to make room\n")
	if l.archive != nil {
		l.archive.released.Store(time.Now().UnixNano())
	}
	l.archive.signal()
	return true
}

// folderFull reports, under refuse, that the log folder has no room for
// another file: its rotated files and two files' room past logFiles ×
// maxLogBytes.
func (l *securityLog) folderFull() bool {
	files, err := listRotated(filepath.Dir(l.path), filepath.Base(l.path))
	if err != nil {
		return false
	}
	var held int64
	for _, f := range files {
		held += min(f.bytes, l.limit)
	}
	return held+2*l.limit > logFiles*l.limit
}

// api is the API the log belongs to: its file name before "-security".
func (l *securityLog) api() string {
	name, _, _ := strings.Cut(filepath.Base(l.path), "-security")
	return name
}
