// The log's rotated files in the log folder and the archive folder: their
// names (<stem>-<UTC time><ext>, with ".gz" once compressed; files named
// <name>.<n> by earlier versions, older the higher n), oldest first.

package guard

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const packedSuffix = ".gz"

// logFile is one rotated file.
type logFile struct {
	name, dir string
	at        time.Time
	number    int // set for an earlier version's <name>.<n>
	bytes     int64
	packed    bool
}

func (f logFile) path() string  { return filepath.Join(f.dir, f.name) }
func (f logFile) plain() string { return strings.TrimSuffix(f.name, packedSuffix) }

// rotatedFiles lists the rotated files of active in its folder and in
// archive ("" for none), oldest first, one per plain name (the original
// while both copies exist). An unreadable archive adds nothing.
func rotatedFiles(active, archive string) ([]logFile, error) {
	files, err := listRotated(filepath.Dir(active), filepath.Base(active))
	if err != nil {
		return nil, err
	}
	if archive != "" {
		if archived, err := listRotated(archive, filepath.Base(active)); err == nil {
			files = append(files, archived...)
		}
	}
	slices.SortFunc(files, func(a, b logFile) int {
		packed := func(f logFile) int {
			if f.packed {
				return 1
			}
			return 0
		}
		return cmp.Or(olderFirst(a, b), cmp.Compare(packed(a), packed(b)))
	})
	return slices.CompactFunc(files, func(a, b logFile) bool { return a.plain() == b.plain() }), nil
}

// olderFirst orders earlier-version files first (higher numbers are older),
// then by rotation time.
func olderFirst(a, b logFile) int {
	switch {
	case a.number > 0 && b.number > 0:
		return cmp.Compare(b.number, a.number)
	case a.number > 0:
		return -1
	case b.number > 0:
		return 1
	}
	return a.at.Compare(b.at)
}

// listRotated lists the rotated files of base found in dir.
func listRotated(dir, base string) ([]logFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext) + "-"
	var files []logFile
	for _, entry := range entries {
		f, ok := parseRotated(entry.Name(), base, stem, ext)
		if !ok {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // moved while listed
		}
		if err != nil {
			return nil, err
		}
		f.dir, f.bytes = dir, info.Size()
		files = append(files, f)
	}
	return files, nil
}

// parseRotated reads name as a rotated file of base.
func parseRotated(name, base, stem, ext string) (logFile, bool) {
	plain, packed := strings.CutSuffix(name, packedSuffix)
	f := logFile{name: name, packed: packed}
	if suffix, found := strings.CutPrefix(plain, base+"."); found {
		n, err := strconv.Atoi(suffix)
		f.number = n
		return f, err == nil && n >= 1 && strconv.Itoa(n) == suffix
	}
	middle, found := strings.CutPrefix(plain, stem)
	if !found || !strings.HasSuffix(middle, ext) {
		return logFile{}, false
	}
	at, err := time.Parse(rotatedLayout, strings.TrimSuffix(middle, ext))
	f.at = at
	return f, err == nil
}
