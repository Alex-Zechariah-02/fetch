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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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
// Each write refused for want of space also picks one file on the log disk,
// whatever its free space reads (a quota or inode limit).
func (r *archiver) underPressure(files []logFile) int {
	fails := r.log.spaceFails.Load()
	for _, dir := range []string{r.live, r.dir} {
		d, err := diskOf(dir)
		full := dir == r.live && r.log.currentHealth() == healthNoSpace && fails != r.spaceSeen
		if err != nil || !full && !d.below(r.minFree) {
			continue
		}
		for i, f := range files {
			if same, err := diskOf(f.dir); err == nil && same.id == d.id {
				if full {
					r.spaceSeen = fails
				}
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
	if err := r.log.commitEviction(context.Background(), &e); err != nil {
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
	for _, target := range []struct {
		dir   string
		store func(int64)
	}{
		{r.live, r.freeLog.Store},
		{r.dir, r.freeArchive.Store},
	} {
		d, err := diskOf(target.dir)
		if err != nil {
			d.free = -1
		}
		target.store(d.free)
	}
}

// reserveName is the reserve file of the active file: <stem>.reserve.
func reserveName(active string) string {
	return strings.TrimSuffix(active, filepath.Ext(active)) + ".reserve"
}

// evictReserveName is the eviction reserve file: <stem>.evict.reserve.
func evictReserveName(active string) string {
	return strings.TrimSuffix(active, filepath.Ext(active)) + ".evict.reserve"
}

// evictReserveCap is the dedicated eviction reserve taken from the budget;
// at or below 1 MiB the budget is split evenly between both files.
const evictReserveCap = 1 << 20

func reserveSplit(budget int64) (general, evict int64) {
	if budget <= 0 {
		return 0, 0
	}
	if budget <= evictReserveCap {
		evict = budget / 2
		return budget - evict, evict
	}
	return budget - evictReserveCap, evictReserveCap
}

// keepReserve makes each reserve file when it is missing and the disk has
// room for it above the threshold, reporting the sum of both in r.held.
func (r *archiver) keepReserve() {
	var held int64
	for _, item := range []struct {
		path     string
		size     int64
		released *atomic.Int64
	}{
		{r.log.reservePath, r.generalReserve, &r.released},
		{r.log.evictReservePath, r.evictReserve, &r.evictReleased},
	} {
		if item.path == "" || item.size <= 0 {
			continue
		}
		if _, err := os.Stat(item.path); err == nil {
			held += item.size
			continue
		}
		if time.Since(time.Unix(0, item.released.Load())) < r.pause {
			continue
		}
		if d, err := diskOf(r.live); err != nil || d.below(r.minFree) || (d.total > 0 && d.free < 2*r.reserve) {
			continue
		}
		if err := makeReserve(item.path, item.size); err != nil {
			fmt.Fprintf(os.Stderr, "security log reserve not made yet: %v\n", err)
			continue
		}
		held += item.size
	}
	r.held.Store(held)
}

// makeReserve writes size zero bytes to path, synced, through a new temporary
// file, so a partial reserve never counts as one and nothing is truncated in place.
func makeReserve(path string, size int64) error {
	temporary := path + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for at := int64(0); at < size && err == nil; {
		var n int
		n, err = file.WriteAt(zeros[:min(fillStep, size-at)], at)
		at += int64(n)
	}
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(temporary))
	}
	return syncDir(filepath.Dir(path))
}

// releaseReserve deletes the reserve file so a write that met no space can
// be tried again; only the writer calls it.
func (l *securityLog) releaseReserve() bool {
	if l.reservePath == "" || os.Remove(l.reservePath) != nil {
		return false
	}
	if err := syncDir(filepath.Dir(l.reservePath)); err != nil {
		fmt.Fprintf(os.Stderr, "security log reserve folder sync failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "security log reserve released: the disk is full; the oldest files are evicted to make room\n")
	if l.archive != nil {
		l.archive.released.Store(time.Now().UnixNano())
	}
	l.archive.signal()
	return true
}

// releaseEvictReserve deletes the eviction reserve file and syncs its folder
// so an eviction record can be written while the log is in noSpace.
func (l *securityLog) releaseEvictReserve() bool {
	if l.evictReservePath == "" || os.Remove(l.evictReservePath) != nil {
		return false
	}
	if err := syncDir(filepath.Dir(l.evictReservePath)); err != nil {
		fmt.Fprintf(os.Stderr, "security log eviction reserve folder sync failed: %v\n", err)
	}
	if l.archive != nil {
		l.archive.evictReleased.Store(time.Now().UnixNano())
	}
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
