//go:build !linux && !windows

// Other systems (development only): free space is not read, so disk
// pressure never evicts.

package guard

func diskOf(dir string) (disk, error) { return disk{free: -1, total: -1, id: dir}, nil }
