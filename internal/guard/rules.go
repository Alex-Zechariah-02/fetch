// An API's operation table: the operations it serves, each with the roles
// that may call it, its rate rule and its body rule, compiled once at start
// and matched against each request's canonical path and method.

package guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Operation is one row of an API's table. A target ending in "/*" matches any
// longer path below it; Roles empty means the operation is public, and then
// its rate counts per client address instead of per account.
type Operation struct {
	ID, API, Method, Target string
	Roles                   []string
	Count                   int
	Window                  time.Duration
	MaxBytes                int
	Schema                  map[string]any
}

// Public reports whether the operation needs no signed-in account.
func (o Operation) Public() bool { return len(o.Roles) == 0 }

// rule is a compiled operation.
type rule struct {
	Operation
	schema *jsonschema.Schema
}

// table holds an API's compiled rules by exact target and by prefix.
type table struct {
	exact    map[string][]*rule
	prefixes []string // longest first, so the most specific prefix wins
	byPrefix map[string][]*rule
}

// newTable compiles the operations of one API. Each schema is compiled from
// its JSON form by the same JSON Schema 2020-12 library the gateway uses.
func newTable(operations []Operation) (*table, error) {
	t := &table{exact: map[string][]*rule{}, byPrefix: map[string][]*rule{}}
	for _, op := range operations {
		if op.Count < 1 || op.Window < time.Millisecond || !strings.HasPrefix(op.Target, "/") {
			return nil, fmt.Errorf("operation %s: invalid rule", op.ID)
		}
		compiled := &rule{Operation: op}
		if op.Schema != nil {
			schema, err := compileSchema(op.ID, op.Schema)
			if err != nil {
				return nil, err
			}
			compiled.schema = schema
		}
		if prefix, found := strings.CutSuffix(op.Target, "*"); found {
			if _, seen := t.byPrefix[prefix]; !seen {
				t.prefixes = append(t.prefixes, prefix)
			}
			t.byPrefix[prefix] = append(t.byPrefix[prefix], compiled)
			continue
		}
		t.exact[op.Target] = append(t.exact[op.Target], compiled)
	}
	slices.SortFunc(t.prefixes, func(a, b string) int { return len(b) - len(a) })
	return t, nil
}

func compileSchema(id string, schema map[string]any) (*jsonschema.Schema, error) {
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	document, reason := decodeJSON(raw)
	if reason != "" {
		return nil, fmt.Errorf("operation %s: schema: %s", id, reason)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	// No loader schemes: a schema can never fetch a file or URL.
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	location := "urn:fetch:" + id
	if err := compiler.AddResource(location, document); err != nil {
		return nil, fmt.Errorf("operation %s: schema: %w", id, err)
	}
	return compiler.Compile(location)
}

// match finds the most specific target for path, then the method on that
// target only, as the gateway does: no target is 404, a target without the
// method is 405 with the target's methods in allow.
func (t *table) match(path, method string) (found *rule, allow string, status int) {
	rules, ok := t.exact[path]
	if !ok {
		for _, prefix := range t.prefixes {
			if rest, below := strings.CutPrefix(path, prefix); below && rest != "" {
				rules, ok = t.byPrefix[prefix], true
				break
			}
		}
	}
	if !ok {
		return nil, "", http.StatusNotFound
	}
	methods := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.Method == method {
			return r, "", http.StatusOK
		}
		methods = append(methods, r.Method)
	}
	return nil, strings.Join(methods, ", "), http.StatusMethodNotAllowed
}

// canonical accepts only a path with one meaning for every reader: printable
// ASCII without backslash or percent, no dot segments, no empty segment but a
// trailing one, and no escaped slash, backslash, dot or NUL in the target.
func canonical(r *http.Request) bool {
	escaped := strings.ToLower(r.URL.EscapedPath())
	for _, banned := range []string{"%2f", "%5c", "%2e", "%00"} {
		if strings.Contains(escaped, banned) {
			return false
		}
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		return false
	}
	for i := 0; i < len(path); i++ {
		if c := path[i]; c < 0x21 || c > 0x7e || c == '\\' || c == '%' {
			return false
		}
	}
	segments := strings.Split(path[1:], "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." || segment == "" && i != len(segments)-1 {
			return false
		}
	}
	return true
}
