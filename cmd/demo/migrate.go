// Demo migrate: moves the Fetch APIs behind APIWard from their OpenAPI
// descriptions, the way a team brings an existing application to a gateway.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

// migrate imports every <service>.openapi.yaml in openapi/ with the gateway's
// policy import-openapi, one API after another onto a base that holds only
// the upstreams, the roles and the shop's pages, and writes the result to a
// new file for an administrator to stage, review and confirm in the
// Dashboard. The import takes no roles or rate limits from a description:
// the administrator sets them before confirming.
func migrate(args []string) error {
	set := flag.NewFlagSet("migrate", flag.ContinueOnError)
	apiward := set.String("apiward", "", "APIWard checkout that builds the gateway (default: ../apiward beside this repository)")
	out := set.String("out", "", "new policy file to write")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *out == "" {
		return errors.New("migrate takes -out and optionally -apiward\n" + usage)
	}
	if _, err := os.Lstat(*out); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s already exists; name a new file", *out)
	}
	source, err := findSources(*apiward)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "fetch-migrate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	gateway := filepath.Join(work, executable("gateway"))
	build := exec.Command("go", "build", "-o", gateway, "./cmd/gateway")
	build.Dir = source.apiward
	if log, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("building the gateway: %w\n%s", err, log)
	}
	result, err := importDescriptions(gateway, filepath.Join(source.fetch, "openapi"), work)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(result)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Stage it with: go run ./cmd/demo policy stage -dir <home>/state -file %s\n", *out, *out)
	fmt.Println("Then, in the Dashboard, give each operation its roles and rate limit, review the change and confirm it.")
	return nil
}

// importDescriptions imports the description of every Fetch API in specs onto
// the migration base, in work, and returns the final policy file. Each step's
// report stays in work; a refused operation stops the migration.
func importDescriptions(gateway, specs, work string) (string, error) {
	current := filepath.Join(work, "base.json")
	if err := os.WriteFile(current, indented(migrationBase(baselinePolicy())), 0o600); err != nil {
		return "", err
	}
	for _, service := range fetchServices {
		next := filepath.Join(work, service.name+".json")
		report := filepath.Join(work, service.name+"-report.json")
		cmd := exec.Command(gateway, "policy", "import-openapi", "--spec", filepath.Join(specs, service.name+".openapi.yaml"),
			"--api", service.name, "--upstream", service.name+"-svc", "--base", current, "--out", next, "--report", report)
		output, err := cmd.CombinedOutput()
		fmt.Print(string(output))
		// 0: every operation mapped; 2: written with widened targets, which
		// the baseline's wildcard targets are. Any refusal fails below.
		if cmd.ProcessState == nil || !slices.Contains([]int{0, 2}, cmd.ProcessState.ExitCode()) {
			return "", fmt.Errorf("importing %s: %v", service.name, err)
		}
		if err := checkNoneRefused(report); err != nil {
			return "", fmt.Errorf("importing %s: %w", service.name, err)
		}
		current = next
	}
	return current, nil
}

// migrationBase is the baseline without the five Fetch APIs: their upstreams,
// the roles and the shop's public pages stay, so the shop loads before any
// API is imported.
func migrationBase(baseline map[string]any) map[string]any {
	base := maps.Clone(baseline)
	var apis []map[string]any
	for _, api := range baseline["apis"].([]map[string]any) {
		if api["id"] == "web" {
			apis = append(apis, api)
		}
	}
	var operations []map[string]any
	for _, op := range baseline["operations"].([]map[string]any) {
		if op["api"] == "web" {
			operations = append(operations, op)
		}
	}
	base["apis"], base["operations"], base["permits"] = apis, operations, []map[string]any{}
	return base
}

// checkNoneRefused fails when the import report at name lists any refused
// operation, naming each one.
func checkNoneRefused(name string) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	var report struct {
		Refused []json.RawMessage `json:"refused"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("reading the import report: %w", err)
	}
	if len(report.Refused) > 0 {
		refused, _ := json.Marshal(report.Refused)
		return fmt.Errorf("%d operations refused: %s", len(report.Refused), refused)
	}
	return nil
}
