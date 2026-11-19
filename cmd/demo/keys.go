// Signing key rotation and retirement through Fetch Accounts and the Admin
// API, with a warning before retiring a key that recently verified a token.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// maxTrusted mirrors the gateway's limit on gateway.jwt.keys (APIWard's
// pipeline.MaxKeys, internal/pipeline/keys.go there); a 65th key written to the settings
// would make the reload and every later start refuse them, so the demo
// refuses first.
const maxTrusted = 64

func keys(args []string) error {
	if len(args) == 0 || args[0] != "rotate" && args[0] != "retire" {
		return errors.New("choose keys rotate or keys retire")
	}
	set := flag.NewFlagSet("keys "+args[0], flag.ContinueOnError)
	var kid string
	if args[0] == "retire" {
		set.StringVar(&kid, "kid", "", "old key ID")
	}
	dir, err := parse(set, args[1:])
	if err != nil {
		return err
	}
	if args[0] == "retire" && kid == "" {
		return errors.New("-kid is required")
	}
	admin, err := operatorSession(dir)
	if err != nil {
		return err
	}
	defer admin.signOut(os.Stderr)
	if args[0] == "retire" {
		warnRecentKeyUse(admin, kid, time.Now())
	}
	selected, err := changeKeys(dir, admin, args[0], kid)
	if err == nil {
		fmt.Printf("keys %s complete; key %s\n", args[0], selected)
	}
	return err
}

// changeKeys rotates or retires an Accounts key under dir's operator lock.
// A retired key's files that rotate made are deleted once the gateway's
// reload is confirmed.
func changeKeys(dir string, admin *adminClient, action, kid string) (string, error) {
	if err := checkFiles(dir); err != nil {
		return "", err
	}
	lock, err := lockDemo(dir)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err := checkDemo(dir); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, signingFile))
	if err != nil {
		return "", err
	}
	var signing struct {
		Kid            string `json:"kid"`
		PrivateKeyFile string `json:"private_key_file"`
	}
	if json.Unmarshal(data, &signing) != nil || signing.Kid == "" {
		return "", errors.New("invalid Accounts settings")
	}
	data, err = os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return "", err
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		return "", errors.New("invalid gateway settings")
	}
	gateway, ok := config["gateway"].(map[string]any)
	if !ok {
		return "", errors.New("missing gateway settings")
	}
	jwt, ok := gateway["jwt"].(map[string]any)
	if !ok {
		return "", errors.New("missing JWT settings")
	}
	trusted, ok := jwt["keys"].([]any)
	if !ok {
		return "", errors.New("missing trusted keys")
	}
	newPrivate, retired := "", ""
	switch action {
	case "rotate":
		if len(trusted) >= maxTrusted {
			return "", fmt.Errorf("the gateway trusts at most %d keys: retire one before rotating", maxTrusted)
		}
		// The stamp names the rotation and eight random hex digits keep two in the same second apart.
		kid = "fetch-" + time.Now().UTC().Format("20060102T150405") + "-" + newKey()[:8]
		private, public, err := signingKeys()
		if err != nil {
			return "", err
		}
		newPrivate = filepath.Join(dir, kid+"-key.pem")
		publicPath := filepath.Join(dir, kid+".pem")
		if err := writeNewFile(newPrivate, private); err != nil {
			return "", err
		}
		if err := writeNewFile(publicPath, public); err != nil {
			return "", err
		}
		trusted = append(trusted, map[string]any{"kid": kid, "public_key_file": publicPath})
	case "retire":
		if kid == signing.Kid {
			return "", errors.New("cannot retire the current Accounts signing key")
		}
		kept, found := []any{}, false
		for _, value := range trusted {
			entry, ok := value.(map[string]any)
			if !ok {
				return "", errors.New("invalid trusted key entry")
			}
			if entry["kid"] == kid {
				found = true
				retired, _ = entry["public_key_file"].(string)
			} else {
				kept = append(kept, value)
			}
		}
		if !found {
			return "", errors.New("that key is not configured")
		}
		trusted = kept
	default:
		return "", errors.New("unknown key action")
	}
	jwt["keys"] = trusted
	if err := replaceOperatorFile(filepath.Join(dir, configFile), indented(config)); err != nil {
		return "", err
	}
	if err := identifyDemo(dir); err != nil {
		return "", fmt.Errorf("settings written but not bound; check them and run demo rebind -dir %s: %w", dir, err)
	}
	if _, _, err := admin.send("POST", "/admin/keys/reload", nil, mutationHeaders(""), 200); err != nil {
		return "", fmt.Errorf("settings written; key reload was not confirmed, Accounts signing is unchanged; inspect /admin/keys before continuing: %w", err)
	}
	if action == "rotate" {
		if err := replaceOperatorFile(filepath.Join(dir, signingFile), signingSettings(kid, newPrivate)); err != nil {
			return "", fmt.Errorf("gateway trusts new key but Accounts did not switch: %w", err)
		}
		return kid, nil
	}
	removeRetired(dir, kid, retired)
	return kid, nil
}

// removeRetired deletes the key pair rotate wrote for kid, which the
// settings named at public. The pair setup made, and any file outside dir,
// stays and is named instead: it may serve another purpose.
func removeRetired(dir, kid, public string) {
	if public != filepath.Join(dir, kid+".pem") {
		fmt.Printf("retired key %s; its files were not made by keys rotate and stay: %s\n", kid, public)
		return
	}
	for _, path := range []string{filepath.Join(dir, kid+"-key.pem"), public} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: retired key file %s was not deleted: %v\n", path, err)
			continue
		}
		fmt.Println("deleted", path)
	}
}

// recentKeyUse is how recently a key must have verified a token for retiring
// it to warrant a warning.
// Fifteen minutes is the Accounts token lifetime, so a key used in it may still have live tokens.
const recentKeyUse = 15 * time.Minute

// warnRecentKeyUse warns, without stopping the retirement, when the gateway
// verified a token with the key recently: tokens it signed stop working once
// it is retired. A failed read is reported, not treated as "unused".
func warnRecentKeyUse(admin *adminClient, kid string, now time.Time) {
	_, body, err := admin.send("GET", "/admin/keys", nil, nil, 200)
	var keys struct {
		Items []keyUse `json:"items"`
	}
	if err == nil {
		err = json.Unmarshal(body, &keys)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read when key %s was last used: %v\n", kid, err)
		return
	}
	if message := keyUseWarning(keys.Items, kid, now); message != "" {
		fmt.Fprintln(os.Stderr, message)
	}
}

// keyUse is the part of a trusted key's report that the warning reads.
type keyUse struct {
	Kid            string     `json:"kid"`
	LastVerifiedAt *time.Time `json:"last_verified_at"`
}

// keyUseWarning words the warning for kid, or returns "" when the key has not
// verified a token within recentKeyUse.
func keyUseWarning(items []keyUse, kid string, now time.Time) string {
	for _, item := range items {
		if item.Kid != kid || item.LastVerifiedAt == nil || now.Sub(*item.LastVerifiedAt) > recentKeyUse {
			continue
		}
		ago := max(now.Sub(*item.LastVerifiedAt).Round(time.Second), 0)
		return fmt.Sprintf("warning: key %s verified a token %s ago; tokens it signed will be refused once it is retired", kid, ago)
	}
	return ""
}
