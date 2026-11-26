// The owner check of a trusted file on Unix: the file's owner must be the
// process user or root.

//go:build unix

package trusted

import (
	"errors"
	"os"
	"syscall"
)

func owner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the file's owner cannot be read")
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Getuid() {
		return errors.New("the file must belong to the service's user or root")
	}
	return nil
}
