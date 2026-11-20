// The security log's storage settings and their defaults.

package guard

import "path/filepath"

// Storage is where rotated files go: the archive folder ("" runs no
// archiver), its size bound, whether nothing is ever deleted (Refuse), the
// free share of a disk in percent below which the oldest files are evicted
// early, and the reserve file's size.
type Storage struct {
	Archive      string
	ArchiveBytes int64
	Refuse       bool
	MinFree      int
	Reserve      int64
}

// Defaults of the log's storage: the gateway's (10 GiB archive, 10 % free,
// a 64 MiB reserve), with the archive split over the five APIs, so the
// protected setups keep about the same history on one disk.
const (
	DefaultArchiveBytes = 2 << 30
	defaultMinFree      = 10
	defaultReserve      = maxLogBytes
)

// withDefaults fills s's unset values: the archive folder "archive" in dir.
func (s Storage) withDefaults(dir string) Storage {
	if s.Archive == "" {
		s.Archive = filepath.Join(dir, "archive")
	}
	if s.ArchiveBytes == 0 {
		s.ArchiveBytes = DefaultArchiveBytes
	}
	if s.MinFree == 0 {
		s.MinFree = defaultMinFree
	}
	if s.Reserve == 0 {
		s.Reserve = defaultReserve
	}
	return s
}
