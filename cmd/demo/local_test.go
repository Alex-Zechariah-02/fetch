// demo block -local: every API is offered the blocked list even after one
// refuses it, and each refusal is named.

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPutBlockedTriesEveryService(t *testing.T) {
	t.Parallel()
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer refusing.Close()
	var taken atomic.Int32
	taking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer s" {
			taken.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer taking.Close()
	services := []demoService{
		{name: "first", control: strings.TrimPrefix(refusing.URL, "http://")},
		{name: "second", control: strings.TrimPrefix(taking.URL, "http://")},
		{name: "third", control: strings.TrimPrefix(refusing.URL, "http://")},
	}
	err := putBlocked(services, []byte("[]"), "s")
	if err == nil {
		t.Fatal("refused lists were reported as updated")
	}
	if taken.Load() != 1 {
		t.Fatalf("the API after a refusal got %d lists, want 1", taken.Load())
	}
	for _, name := range []string{"first", "third"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
	if strings.Contains(err.Error(), "second") {
		t.Errorf("error %q names the API that took the list", err)
	}
}
