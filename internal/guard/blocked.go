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

// Blocked serves PUT /blocked on the API's control listener (behind its
// secret): the body is the new list, a JSON array of account IDs.
func (g *Guard) Blocked(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFile))
	var subjects []string
	if _, reason := decodeJSON(data); err != nil || reason != "" || json.Unmarshal(data, &subjects) != nil || subjects == nil || g.setBlocked(subjects) != nil {
		answer(w, http.StatusBadRequest, "bad_request")
		return
	}
	g.log.note(record{Kind: "blocked.replaced", API: g.api, Accounts: len(subjects)})
	w.WriteHeader(http.StatusNoContent)
}
