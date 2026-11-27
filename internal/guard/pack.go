// Compressing a rotated file, as the gateway does: one pass describes it
// (size, SHA-256, first and last record times), a second writes it gzip-
// compressed (RFC 1952, Go's default level) to a temporary name, syncs it,
// renames it and syncs the folder, so a crash leaves either no compressed
// file or a complete one. The description goes in the gzip header comment.

package guard

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// describe reads a plain file once: its size, SHA-256 and the times of its
// first and last records.
func describe(path string) (record, error) {
	file, err := os.Open(path)
	if err != nil {
		return record{}, err
	}
	defer file.Close()
	sum := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(file, sum), 64<<10)
	var r record
	for {
		line, err := reader.ReadSlice('\n')
		r.Bytes += int64(len(line))
		if at, ok := lineTime(line); ok && err == nil {
			if r.First.IsZero() {
				r.First = at
			}
			r.Last = at
		}
		if err == io.EOF {
			break
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return record{}, err
		}
	}
	r.Digest = hex.EncodeToString(sum.Sum(nil))
	return r, nil
}

// lineTime reads a record's time without decoding the rest of it.
func lineTime(line []byte) (time.Time, bool) {
	_, rest, found := bytes.Cut(line, []byte(`"time":"`))
	text, _, closed := bytes.Cut(rest, []byte(`"`))
	if !found || !closed {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, string(text))
	return at, err == nil
}

// pack compresses the plain file src into dir as <name>.gz; the result's
// Archived is the stored size.
func pack(src, dir string) (record, error) {
	r, err := describe(src)
	if err != nil {
		return record{}, err
	}
	target := filepath.Join(dir, filepath.Base(src)+packedSuffix)
	temporary := target + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return record{}, err
	}
	if r.Archived, err = writePacked(src, temporary, r); err != nil {
		return record{}, errors.Join(err, os.Remove(temporary))
	}
	if err := os.Rename(temporary, target); err != nil {
		return record{}, errors.Join(err, os.Remove(temporary))
	}
	return r, syncDir(dir)
}

// writePacked writes src compressed to temporary, synced, and returns its size.
func writePacked(src, temporary string, r record) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	// 0600 keeps an archived file readable only by this user.
	out, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	zw := gzip.NewWriter(out)
	zw.Name, zw.Comment, zw.ModTime = filepath.Base(src), packedComment(r), r.Last
	_, err = io.Copy(zw, in)
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = out.Sync()
	}
	var size int64
	if err == nil {
		var info os.FileInfo
		info, err = out.Stat()
		if err == nil {
			size = info.Size()
		}
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return 0, err
	}
	return size, nil
}

func packedComment(r record) string {
	return fmt.Sprintf("first=%s last=%s sha256=%s bytes=%d", r.First.Format(time.RFC3339Nano), r.Last.Format(time.RFC3339Nano), r.Digest, r.Bytes)
}

// stored describes a file as it is stored: a compressed file from its
// header, with Digest the SHA-256 of the stored bytes.
func stored(f logFile) (record, error) {
	if !f.packed {
		return describe(f.path())
	}
	file, err := os.Open(f.path())
	if err != nil {
		return record{}, err
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		return record{}, err
	}
	defer zr.Close()
	r := record{Bytes: f.bytes}
	for field := range strings.FieldsSeq(zr.Comment) {
		key, value, _ := strings.Cut(field, "=")
		switch key {
		case "first":
			r.First, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return record{}, fmt.Errorf("archive header first time: %w", err)
			}
		case "last":
			r.Last, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return record{}, fmt.Errorf("archive header last time: %w", err)
			}
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return record{}, err
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return record{}, err
	}
	r.Digest = hex.EncodeToString(sum.Sum(nil))
	return r, nil
}
