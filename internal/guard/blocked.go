// The blocked-accounts list of one API: read from the settings folder at
// start and replaced as a whole through the API's control listener. A
// blocked account is refused even with a valid token.

package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// setBlocked replaces the blocked list as a whole.
func (g *Guard) setBlocked(subjects []string) error {
	if len(subjects) > maxBlocked {
		return fmt.Errorf("at most %d blocked accounts", maxBlocked)
	}
	list := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if !subjectID(subject) {
			return errors.New("a blocked account ID is invalid")
		}
		list[subject] = true
	}
	g.blocked.Store(&list)
	return nil
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
// secret): the body is the new list, a JSON array of account IDs.
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
	if err != nil || g.setBlocked(subjects) != nil {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	g.log.note(record{Kind: "blocked.replaced", API: g.api, Accounts: len(subjects)})
	w.WriteHeader(http.StatusNoContent)
}
