// The blocked-accounts list of one API: read from the settings folder at
// start and replaced as a whole through the API's control listener. A
// replacement is written to the folder's file before it is in force, so a
// restart keeps every block. A blocked account is refused even with a valid
// token.

package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// setBlocked replaces the blocked list as a whole.
func (g *Guard) setBlocked(subjects []string) error {
	list, err := blockedSet(subjects)
	if err != nil {
		return err
	}
	g.blocked.Store(&list)
	return nil
}

// blockedSet checks subjects and returns them as a set.
func blockedSet(subjects []string) (map[string]bool, error) {
	if len(subjects) > maxBlocked {
		return nil, fmt.Errorf("at most %d blocked accounts", maxBlocked)
	}
	list := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if !subjectID(subject) {
			return nil, errors.New("a blocked account ID is invalid")
		}
		list[subject] = true
	}
	return list, nil
}

// loadBlocked puts the blocked list of the file at path in force.
func (g *Guard) loadBlocked(path string) error {
	data, err := readFile(path, maxBlockedBytes)
	if err != nil {
		return err
	}
	subjects, err := decodeBlocked(data)
	if err != nil {
		return err
	}
	return g.setBlocked(subjects)
}

// decodeBlocked reads a blocked list: one JSON array of strings and nothing
// else. Its size is bounded by the caller and its count by setBlocked, not by
// the request-body bounds, which a list of maxBlocked IDs would exceed.
func decodeBlocked(data []byte) ([]string, error) {
	var subjects []string
	if err := json.Unmarshal(data, &subjects); err != nil {
		return nil, err
	}
	if subjects == nil {
		return nil, errors.New("the blocked list is not an array")
	}
	return subjects, nil
}

// Blocked serves PUT /blocked on the API's control listener (behind its
// secret): the body is the new list, a JSON array of account IDs. The list
// is written to the settings folder, then put in force, then recorded; a
// replacement whose record cannot be written answers 503 with the list in
// force, and repeating the PUT is safe.
func (g *Guard) Blocked(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlockedBytes))
	if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
		answer(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	if err != nil {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	subjects, err := decodeBlocked(data)
	if err != nil {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	list, err := blockedSet(subjects)
	if err != nil {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	// One replacement at a time, so the file and the list in force agree.
	g.replacing.Lock()
	defer g.replacing.Unlock()
	if err := writeDurably(g.blockedPath, data); err != nil {
		answer(w, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}
	g.blocked.Store(&list)
	if g.log.commit(r.Context(), &record{Kind: "blocked.replaced", API: g.api, Accounts: len(list)}) != nil {
		answer(w, http.StatusServiceUnavailable, "gateway_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeDurably replaces path with data: a private temporary file in the same
// folder, synced, renamed over path, and the folder synced, so a crash leaves
// the old file or the new one, never a part of either.
func writeDurably(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".blocked-*.json")
	if err != nil {
		return err
	}
	temporary := file.Name()
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Chmod(0o600), file.Sync(), file.Close()); err != nil {
		return errors.Join(err, os.Remove(temporary))
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.Join(err, os.Remove(temporary))
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable. Windows cannot open a folder for a
// sync, and NTFS journals the rename itself.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	folder, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(folder.Sync(), folder.Close())
}
