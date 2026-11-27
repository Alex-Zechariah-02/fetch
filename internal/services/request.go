// Request reading shared by the Fetch services: bounded strict JSON bodies,
// queries, pagination and small field checks.

package services

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
)

func decodeBody(r *http.Request, body []byte, limit int, value any) *result {
	if len(body) > limit {
		v := failure(413, "payload_too_large", "The request body is too large.", "")
		return &v
	}
	if !jsonMedia(r.Header.Values("Content-Type")) {
		v := failure(415, "unsupported_media_type", "Send a JSON request body.", "")
		return &v
	}
	// The member names are checked by one token walk before the typed decode:
	// no repeated or uppercase names, no null, at most maxDepth levels.
	if !utf8.Valid(body) || guard.LoneSurrogate(body) || !strictObject(body) {
		v := failure(400, "invalid_request", "The JSON request is invalid.", "")
		return &v
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		v := failure(400, "invalid_request", "The JSON request is invalid.", "")
		return &v
	}
	if _, err := decoder.Token(); err != io.EOF {
		v := failure(400, "invalid_request", "Send exactly one JSON value.", "")
		return &v
	}
	return nil
}

// jsonMedia accepts exactly one Content-Type field naming application/json,
// optionally with charset=utf-8.
func jsonMedia(fields []string) bool {
	if len(fields) != 1 {
		return false
	}
	if fields[0] == "application/json" || fields[0] == "application/json; charset=utf-8" {
		return true
	}
	media, parameters, err := mime.ParseMediaType(fields[0])
	if err != nil || media != "application/json" {
		return false
	}
	for name, value := range parameters {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// maxDepth bounds a request document's nesting.
const maxDepth = 16

// strictObject reports that data is one JSON object whose member names, at
// every level, are lowercase letters, digits and underscores, never repeated
// within an object, with no null value and at most maxDepth levels: the
// service contracts' names only, and one meaning for every reader.
func strictObject(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	// names holds each open level's member names; nil for an array.
	var names [][]string
	expectName := false
	first := true
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return !first && len(names) == 0
		}
		// Nothing may follow the one object, and null is refused.
		if err != nil || token == nil || !first && len(names) == 0 {
			return false
		}
		if first {
			if delim, ok := token.(json.Delim); !ok || delim != '{' {
				return false
			}
			first = false
		}
		top := len(names) - 1
		if expectName {
			if delim, ok := token.(json.Delim); ok && delim == '}' {
				names = names[:top]
				expectName = len(names) > 0 && names[len(names)-1] != nil
				continue
			}
			name, _ := token.(string)
			if !memberName(name) || slices.Contains(names[top], name) {
				return false
			}
			names[top] = append(names[top], name)
			expectName = false
			continue
		}
		switch token {
		case json.Delim('{'):
			if len(names) > maxDepth {
				return false
			}
			names = append(names, []string{})
			expectName = true
			continue
		case json.Delim('['):
			if len(names) > maxDepth {
				return false
			}
			names = append(names, nil)
			continue
		case json.Delim(']'):
			names = names[:top]
		}
		expectName = len(names) > 0 && names[len(names)-1] != nil
	}
}

// memberName accepts the contracts' member names.
func memberName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func query(r *http.Request, names ...string) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}
	for name, list := range values {
		if len(list) != 1 || !slices.Contains(names, name) {
			return nil, false
		}
	}
	return values, true
}

// pagination reads limit (1 to 100, def when absent) and the after cursor.
func pagination(q url.Values, def int) (int, string, bool) {
	n := def
	var err error
	if text := q.Get("limit"); text != "" {
		n, err = strconv.Atoi(text)
		if strconv.Itoa(n) != text {
			return 0, "", false
		}
	}
	return n, q.Get("after"), err == nil && n >= 1 && n <= maxPage
}
func invalidQuery() result { return failure(400, "invalid_query", "Check the query parameters.", "") }
func length(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max
}

// hasRole reports role in the comma-separated roles header, without
// splitting it into a new slice.
func hasRole(r *http.Request, role string) bool {
	rest := r.Header.Get("X-Gateway-Roles")
	for rest != "" {
		var name string
		name, rest, _ = strings.Cut(rest, ",")
		if name == role {
			return true
		}
	}
	return false
}
func idempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
