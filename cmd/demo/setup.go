// Demo setup: a new private demonstration directory with its signing keys,
// secrets, gateway configuration and policy documents, and the gateway's
// install of the first administrator.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
)

// setup creates a new demonstration directory: a signing key pair whose
// private half stays in this directory, the service control secret, the
// gateway configuration and two policy documents for the administrator to
// stage. It then runs the gateway's install command, which prints the first
// administrator's one-time enrolment secret. An existing directory is never
// reused, so setup cannot overwrite state, and a failed setup removes the
// directory it created, private key included, so it can simply be run again.
func setup(args []string) (err error) {
	set := flag.NewFlagSet("setup", flag.ContinueOnError)
	web := set.String("web", "", "built frontend directory holding admin/ and demo/")
	gateway := set.String("gateway", "", "gateway binary")
	admin := set.String("admin", "admin", "name of the first administrator")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if *web == "" || *gateway == "" {
		return errors.New("-web and -gateway are required")
	}
	webDir, err := filepath.Abs(*web)
	if err != nil {
		return err
	}
	if err := createDemo(dir, webDir, *gateway, *admin, os.Stdout); err != nil {
		return err
	}
	fmt.Printf("demonstration directory %s is ready; start it with: demo run -dir %s -gateway %s -services <services binary> -accounts <accounts binary>\n", dir, dir, *gateway)
	return nil
}

// createDemo does setup's work for one machine. The gateway's install output,
// which holds the enrolment secret, goes to out.
func createDemo(dir, webDir, gateway, admin string, out io.Writer) error {
	for _, page := range []string{"admin", "demo"} {
		if _, err := os.Stat(filepath.Join(webDir, page, "index.html")); err != nil {
			return fmt.Errorf("-web %s has no %s/index.html: build the frontend first", webDir, page)
		}
	}
	files, err := serviceFiles(dir)
	if err != nil {
		return err
	}
	files[configFile] = indented(gatewayConfig(dir, webDir))
	return createState(dir, files, baselinePolicy(), gateway, admin, out)
}

// createState makes the new private directory dir holding files, the
// baseline and deny-all documents and the identity, then runs the gateway's
// install. An existing directory is never reused, and a failure removes the
// directory, private keys included, so setup can simply run again.
func createState(dir string, files map[string][]byte, baseline map[string]any, gateway, admin string, out io.Writer) (err error) {
	if err := privateDirectory(dir); err != nil {
		return fmt.Errorf("creating a new demonstration directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	files[baselineFile] = indented(baseline)
	files[denyAllFile] = indented(denyAll(baseline))
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}
	if err := identifyDemo(dir); err != nil {
		return err
	}
	install := exec.Command(gateway, "install", "--config", filepath.Join(dir, configFile), "--admin", admin)
	install.Stdout, install.Stderr = out, os.Stderr
	if err := install.Run(); err != nil {
		return fmt.Errorf("gateway install: %w", err)
	}
	return nil
}

// localKid names the signing key of a one-machine demonstration.
const localKid = "fetch-2026-10-a"

// serviceFiles are the files the services and Accounts run with in dir: the
// shared service secret and a new signing key pair with its settings.
func serviceFiles(dir string) (map[string][]byte, error) {
	private, public, err := signingKeys()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		privateKeyFile: private,
		publicKeyFile:  public,
		secretFile:     newSecret(),
		signingFile:    signingSettings(localKid, filepath.Join(dir, privateKeyFile)),
	}, nil
}

// signingKeys makes a new Accounts RS256 key pair: the private key as PKCS #8,
// the public key as PKIX, both PEM.
func signingKeys() (private, public []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("PRIVATE KEY", privateDER), pemBlock("PUBLIC KEY", publicDER), nil
}

// signingSettings is the Accounts settings file: the key ID and private key.
func signingSettings(kid, privateKey string) []byte {
	return indented(map[string]string{"kid": kid, "private_key_file": privateKey})
}

// newSecret is a new service and control secret, hex encoded.
func newSecret() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	return []byte(hex.EncodeToString(secret))
}

func indented(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// trustedKey is a public key the gateway verifies Accounts tokens with.
type trustedKey struct {
	Kid           string `json:"kid"`
	PublicKeyFile string `json:"public_key_file"`
}

// gatewayConfig is the one-machine gateway settings: HTTP on the data
// address and this directory's signing key.
func gatewayConfig(dir, web string) map[string]any {
	return gatewaySettings(dir, web, trustedKey{localKid, filepath.Join(dir, publicKeyFile)}, map[string]any{"listen": dataListen}, nil)
}

// gatewaySettings names the native controller, data listener and proxy
// settings: data holds the data listener's own members and profiles the
// upstream TLS profiles, if any. The native gateway validates this file
// before opening deployment state.
func gatewaySettings(dir, web string, key trustedKey, data map[string]any, profiles []tlsProfile) map[string]any {
	data["max_body_bytes"] = 16384
	data["read_header_timeout"] = "5s"
	data["read_timeout"] = "10s"
	data["write_timeout"] = "30s"
	upstream := map[string]any{"dial_timeout": "2s", "response_header_timeout": "5s", "read_idle_timeout": "5s"}
	if len(profiles) > 0 {
		upstream["tls_profiles"] = profiles
	}
	return map[string]any{
		"version": 1,
		"gateway": map[string]any{
			"database":       filepath.Join(dir, databaseFile),
			"audit_log":      filepath.Join(dir, auditFile),
			"admin_listen":   adminListen,
			"metrics_listen": metricsListen,
			"admin_ui":       filepath.Join(web, "admin"),
			"jwt":            map[string]any{"issuer": issuerName, "audience": audience, "keys": []trustedKey{key}},
		},
		"data":     data,
		"upstream": upstream,
	}
}

// denyAll is the baseline with every operation denied and no permits.
func denyAll(baseline map[string]any) map[string]any {
	policy := maps.Clone(baseline)
	var operations []map[string]any
	for _, op := range baseline["operations"].([]map[string]any) {
		denied := maps.Clone(op)
		denied["access"] = "deny"
		operations = append(operations, denied)
	}
	policy["operations"] = operations
	policy["permits"] = []any{}
	return policy
}
