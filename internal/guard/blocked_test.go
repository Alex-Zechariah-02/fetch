// The blocked list's bounds: the contract's 10,000 accounts fit, one more
// does not.

package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A list of maxBlocked IDs of the longest allowed length is taken as a
// whole; one more ID is refused and the list in force stays.
func TestBlockedListBounds(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(filepath.Join(dir, "orders-security.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	g := &Guard{api: "orders", log: log, blockedPath: filepath.Join(dir, BlockedFile)}
	put := func(count int) int {
		ids := make([]string, count)
		for i := range ids {
			id := fmt.Sprintf("acct-%d-", i)
			ids[i] = id + strings.Repeat("x", maxSubject-len(id))
		}
		body, _ := json.Marshal(ids)
		w := httptest.NewRecorder()
		g.Blocked(w, httptest.NewRequest(http.MethodPut, "/blocked", bytes.NewReader(body)))
		return w.Code
	}
	if code := put(maxBlocked); code != http.StatusNoContent {
		t.Fatalf("%d blocked accounts: %d", maxBlocked, code)
	}
	if code := put(maxBlocked + 1); code == http.StatusNoContent {
		t.Fatalf("%d blocked accounts accepted", maxBlocked+1)
	}
	if list := g.blocked.Load(); list == nil || len(*list) != maxBlocked {
		t.Fatal("a refused list replaced the one in force")
	}
}
