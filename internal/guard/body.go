// Request body checks before the handler: no body where none is declared,
// the size ceiling on declared and read length, exactly one JSON media type,
// a bounded unambiguous JSON document, and the operation's schema.

package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Bounds of a decoded JSON document, as the gateway applies them.
const (
	maxDepth        = 16
	maxValues       = 4096
	maxNumberLength = 32
	maxExponent     = 3
	// maxBody is the global ceiling over every operation's own (the demo
	// gateway's max_body_bytes).
	maxBody = 16384
)

// refusal is a request refused by a body check: status, code and the reason
// the security log keeps.
type refusal struct {
	status       int
	code, reason string
}

// readBody enforces the rule's body declaration and replaces the request
// body with the bytes read, so the handler reads exactly what was checked.
func readBody(r *http.Request, rule *rule) *refusal {
	if rule.Schema == nil {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			return &refusal{http.StatusBadRequest, "bad_request", "unexpected_body"}
		}
		return nil
	}
	limit := int64(min(rule.MaxBytes, maxBody))
	tooLarge := &refusal{http.StatusRequestEntityTooLarge, "payload_too_large", "too_large"}
	if r.ContentLength > limit {
		return tooLarge
	}
	if !jsonMedia(r.Header.Values("Content-Type")) {
		return &refusal{http.StatusUnsupportedMediaType, "unsupported_media_type", "media_type"}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return &refusal{http.StatusBadRequest, "bad_request", "read_failed"}
	}
	if int64(len(body)) > limit {
		return tooLarge
	}
	document, reason := decodeJSON(body)
	if reason != "" {
		return &refusal{http.StatusBadRequest, "bad_request", reason}
	}
	if rule.schema.Validate(document) != nil {
		return &refusal{http.StatusBadRequest, "bad_request", "schema_mismatch"}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return nil
}

// jsonMedia accepts exactly one Content-Type field naming application/json,
// optionally with charset=utf-8.
func jsonMedia(fields []string) bool {
	if len(fields) != 1 {
		return false
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

// decodeJSON decodes exactly one JSON value into the form the schema library
// validates. It refuses invalid UTF-8, lone surrogate escapes, repeated
// member names, trailing data, nesting deeper than maxDepth, more than
// maxValues values and long number literals: encoding/json alone would keep
// the last repeated member and replace bad text, so the check and the
// handler could read different documents. It returns the refusal reason.
func decodeJSON(data []byte) (any, string) {
	if !utf8.Valid(data) || LoneSurrogate(data) {
		return nil, "invalid_encoding"
	}
	type container struct {
		members map[string]any // nil for an array
		items   []any
		name    string
		named   bool
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var stack []*container
	values := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, "malformed_json"
		}
		var top *container
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, isDelim := token.(json.Delim); top != nil && top.members != nil && !top.named && (!isDelim || delim != '}') {
			name := token.(string)
			if _, exists := top.members[name]; exists {
				return nil, "duplicate_member"
			}
			top.name, top.named = name, true
			continue
		}
		values++
		var value any
		switch t := token.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				if values > maxValues || len(stack) == maxDepth {
					return nil, "limit_exceeded"
				}
				opened := &container{}
				if t == '{' {
					opened.members = map[string]any{}
				}
				stack = append(stack, opened)
				continue
			}
			values-- // a closing delimiter is not a new value
			stack = stack[:len(stack)-1]
			switch {
			case top.members != nil:
				value = top.members
			case top.items == nil:
				value = []any{}
			default:
				value = top.items
			}
		case json.Number:
			if values > maxValues || !boundedNumber(t) {
				return nil, "limit_exceeded"
			}
			value = t
		default:
			if values > maxValues {
				return nil, "limit_exceeded"
			}
			value = t
		}
		if len(stack) == 0 {
			if _, err := decoder.Token(); err != io.EOF {
				return nil, "trailing_data"
			}
			return value, ""
		}
		parent := stack[len(stack)-1]
		if parent.members != nil {
			parent.members[parent.name] = value
			parent.named = false
		} else {
			parent.items = append(parent.items, value)
		}
	}
}

// boundedNumber accepts number literals the schema library compares cheaply.
func boundedNumber(number json.Number) bool {
	literal := string(number)
	if len(literal) > maxNumberLength {
		return false
	}
	_, exponent, found := strings.Cut(strings.ToLower(literal), "e")
	return !found || len(strings.TrimLeft(exponent, "+-")) <= maxExponent
}

// LoneSurrogate reports a \u escape of a UTF-16 surrogate that is not part of
// a high-low pair: valid JSON syntax that encodes no character, which
// decoders replace, keep or refuse differently.
func LoneSurrogate(data []byte) bool {
	surrogate := func(i int) (rune, bool) {
		if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
			return 0, false
		}
		code, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		return rune(code), err == nil && code >= 0xd800 && code <= 0xdfff
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		code, found := surrogate(i)
		switch {
		case !found:
			i++ // skip the escaped character, which may be a backslash
		case code >= 0xdc00:
			return true
		default:
			low, ok := surrogate(i + 6)
			if !ok || low < 0xdc00 {
				return true
			}
			i += 11
		}
	}
	return false
}
