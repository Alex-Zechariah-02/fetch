// Each archiver pass publishes file totals and one disk observation per path.

package guard

import "sync/atomic"

func (r *archiver) measure(readDisk func(string) (disk, error)) {
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
	targets := make(map[string][]*atomic.Int64)
	targets[r.live] = append(targets[r.live], &r.freeLog)
	targets[r.dir] = append(targets[r.dir], &r.freeArchive)
	for path, fields := range targets {
		d, err := readDisk(path)
		if err != nil {
			d.free = -1
		}
		for _, field := range fields {
			field.Store(d.free)
		}
	}
}
