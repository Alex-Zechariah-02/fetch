// The OpenAPI descriptions import into the baseline's operations.

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMigrationMatchesBaseline imports every description with the gateway,
// as demo migrate does, and requires the baseline's operations back: the same
// endpoints, targets, sign-in and body schemas, with no roles or rate limits
// taken from a description. It fails when a description drifts from the
// services or the importer refuses Fetch's own x-fetch-* members.
func TestMigrationMatchesBaseline(t *testing.T) {
	source, err := findSources("")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	gateway := filepath.Join(work, executable("gateway"))
	build := exec.Command("go", "build", "-C", source.apiward, "-o", gateway, "./cmd/gateway")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the gateway: %v\n%s", err, out)
	}
	result, err := importDescriptions(gateway, filepath.Join(source.fetch, "openapi"), work)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var migrated struct {
		Operations []map[string]any `json:"operations"`
		Permits    []any            `json:"permits"`
	}
	if err := json.Unmarshal(data, &migrated); err != nil {
		t.Fatal(err)
	}
	if len(migrated.Permits) != 0 {
		t.Fatalf("the migration granted roles: %v", migrated.Permits)
	}
	var baseline struct {
		Operations []map[string]any `json:"operations"`
	}
	if err := json.Unmarshal(indented(baselinePolicy()), &baseline); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, op := range migrated.Operations {
		got[op["id"].(string)] = op
	}
	if len(got) != len(baseline.Operations) {
		t.Fatalf("migrated %d operations, the baseline has %d", len(got), len(baseline.Operations))
	}
	for _, want := range baseline.Operations {
		op, found := got[want["id"].(string)]
		if !found {
			t.Errorf("%s: not migrated", want["id"])
			continue
		}
		if op["api"] == "web" {
			continue
		}
		if op["rate"] != nil {
			t.Errorf("%s: a rate limit came from the description", want["id"])
		}
		for _, field := range []string{"api", "method", "target", "access", "auth"} {
			if op[field] != want[field] {
				t.Errorf("%s: %s is %v, the baseline has %v", want["id"], field, op[field], want[field])
			}
		}
		if body, ok := want["body"].(map[string]any); ok {
			gotBody, _ := op["body"].(map[string]any)
			if gotSchema, _ := json.Marshal(gotBody["schema"]); string(gotSchema) != mustJSON(t, body["schema"]) {
				t.Errorf("%s: body schema %s differs from the baseline", want["id"], gotSchema)
			}
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
