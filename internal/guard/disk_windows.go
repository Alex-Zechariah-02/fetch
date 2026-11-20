// Windows: free space for this user (quotas included) and the volume name.

package guard

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func diskOf(dir string) (disk, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return disk{}, err
	}
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return disk{}, err
	}
	var free, total, unused uint64
	if err := windows.GetDiskFreeSpaceEx(name, &free, &total, &unused); err != nil {
		return disk{}, err
	}
	return disk{free: bytesOf(free), total: bytesOf(total), id: strings.ToLower(filepath.VolumeName(abs))}, nil
}
