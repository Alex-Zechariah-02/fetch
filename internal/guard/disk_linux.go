// Linux: free space as an unprivileged user sees it (statfs f_bavail) and
// the device number.

package guard

import (
	"strconv"
	"syscall"
)

func diskOf(dir string) (disk, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return disk{}, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return disk{}, err
	}
	if fs.Bsize <= 0 {
		return disk{free: -1, total: -1, id: strconv.FormatUint(st.Dev, 10)}, nil
	}
	block := uint64(fs.Bsize)
	return disk{free: bytesOf(fs.Bavail * block), total: bytesOf(fs.Blocks * block), id: strconv.FormatUint(st.Dev, 10)}, nil
}
