// A disk as the archiver sees it: free and total bytes (-1 unknown) and an
// identity shared by folders on one file system.

package guard

import "math"

type disk struct {
	free, total int64
	id          string
}

// below reports whether free space is under share of the size; never for
// an unknown size.
func (d disk) below(share float64) bool {
	return d.total > 0 && float64(d.free) < share*float64(d.total)
}

// bytesOf converts a byte count, capped at the largest int64.
func bytesOf(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}
