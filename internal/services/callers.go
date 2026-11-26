// The calls between services and their keys: which service calls which
// (Orders calls Inventory, Reports and Support call Orders), the internal
// endpoints each caller may use, the key files a service reads (its own and
// those of the callers it accepts), and the caller a request's key names.

package services

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/fetch/internal/trusted"
)

// callees maps each calling service to the one service it calls.
var callees = map[string]string{"orders": "inventory", "reports": "orders", "support": "orders"}

// Callers are the services that call another, each with its own key, sorted.
func Callers() []string {
	names := make([]string, 0, len(callees))
	for caller := range callees {
		names = append(names, caller)
	}
	slices.Sort(names)
	return names
}

// needs names the keys service name holds, sorted: its own when it calls
// another service, and that of each caller it accepts.
func needs(name string) []string {
	var names []string
	for caller, callee := range callees {
		if caller == name || callee == name {
			names = append(names, caller)
		}
	}
	slices.Sort(names)
	return names
}

// called reports whether another service calls name.
func called(name string) bool {
	for _, callee := range callees {
		if callee == name {
			return true
		}
	}
	return false
}

// permitted reports whether caller may make this internal call: Orders
// reserves stock and reads merchants at Inventory, Reports reads the order
// list and Support one order at Orders.
func permitted(caller, method, path string) bool {
	switch caller {
	case "orders":
		// Orders is Inventory's only caller and uses each of its internal endpoints.
		return true
	case "reports":
		return method == "GET" && path == "/internal/orders"
	case "support":
		return method == "GET" && strings.HasPrefix(path, "/internal/orders/")
	}
	return false
}

// ReadKeys reads, from folder, the key file <service>.key of each key that
// service name holds, each readable by its owner only.
func ReadKeys(folder, name string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, key := range needs(name) {
		data, err := readBoundedFile(filepath.Join(folder, key+".key"), trusted.Private)
		if err != nil {
			return nil, fmt.Errorf("reading the %s key: %w", key, err)
		}
		keys[key] = bytes.TrimSpace(data)
	}
	return keys, nil
}

// checkKeys refuses keys unless they are exactly the ones service name
// holds, each 32 to 4096 bytes and no two the same, so a key names one caller.
func checkKeys(name string, keys map[string][]byte) error {
	want := needs(name)
	if len(keys) != len(want) {
		return fmt.Errorf("%s takes the keys of %v, no others", name, want)
	}
	for i, key := range want {
		value, found := keys[key]
		if !found {
			return fmt.Errorf("%s takes the keys of %v; the %s key is missing", name, want, key)
		}
		if len(value) < 32 || len(value) > 4096 {
			return fmt.Errorf("the %s key must contain 32 to 4096 bytes", key)
		}
		for _, other := range want[i+1:] {
			if bytes.Equal(value, keys[other]) {
				return errors.New("each service needs its own key: " + key + " and " + other + " share one")
			}
		}
	}
	return nil
}

// caller is the service whose key the request carries, compared in constant
// time against every accepted caller.
func (s *Service) caller(r *http.Request) (string, bool) {
	values := r.Header.Values("X-Service-Key")
	if len(values) != 1 {
		return "", false
	}
	found := ""
	for name, key := range s.callers {
		if subtle.ConstantTimeCompare([]byte(values[0]), key) == 1 {
			found = name
		}
	}
	return found, found != ""
}
