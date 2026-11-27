// The demonstration directory's identity, which binds state-changing demo
// commands to the directory and files setup made; demo rebind accepts a
// settings file changed by hand; the operator lock keeps two key changes apart.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	identityFile = "demo.json"
	lockFile     = "operator.lock"
)

// demoIdentity binds state-changing demonstration operations to the exact
// directory and files setup created. It grants no policy or admin authority.
type demoIdentity struct {
	Format    string `json:"format"`
	Directory string `json:"directory"`
	Config    string `json:"config_sha256"`
	Secret    string `json:"service_secret_sha256"`
}

func demoDigest(path string) (string, error) {
	// A digest covers every byte, so the whole file is read and no size cap applies.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// secretDigest is the digest of dir's service secret, or "" for a gateway
// host's directory, which holds none: the identity binds the secret's absence
// as firmly as its content.
func secretDigest(dir string) (string, error) {
	digest, err := demoDigest(filepath.Join(dir, secretFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return digest, err
}

func identifyDemo(dir string) error {
	config, err := demoDigest(filepath.Join(dir, configFile))
	if err != nil {
		return err
	}
	secret, err := secretDigest(dir)
	if err != nil {
		return err
	}
	identity := demoIdentity{Format: "fetch-demo-1", Directory: dir, Config: config, Secret: secret}
	// The identity names the directory and both digests; it is created readable by its owner only.
	return os.WriteFile(filepath.Join(dir, identityFile), indented(identity), 0o600)
}

// checkDemo refuses dir unless it is the identified demonstration directory
// setup made, with the settings and service secret it last bound.
func checkDemo(dir string) error {
	if err := checkFiles(dir); err != nil {
		return err
	}
	identity, err := readIdentity(dir)
	if err != nil {
		return err
	}
	config, err := demoDigest(filepath.Join(dir, configFile))
	if err != nil {
		return err
	}
	secret, err := secretDigest(dir)
	if err != nil {
		return err
	}
	switch {
	case identity.Format != "fetch-demo-1" || identity.Directory != dir:
		return fmt.Errorf("%s was made for %s, not this directory; refusing the operation", identityFile, identity.Directory)
	case identity.Config != config:
		return fmt.Errorf("%s changed since setup or the last demo key change; refusing the operation (if you changed it, accept it with: demo rebind -dir %s)", configFile, dir)
	case identity.Secret != secret:
		return fmt.Errorf("%s changed since setup; refusing the operation (if you changed it, accept it with: demo rebind -dir %s)", secretFile, dir)
	}
	return nil
}

// checkFiles refuses dir when one of its demonstration files is a link or a directory.
func checkFiles(dir string) error {
	// These files belong to the demonstration directory; a link or directory may not stand in for one.
	for _, name := range append([]string{identityFile, lockFile, configFile, privateKeyFile, publicKeyFile, assertionKeyFile, assertionSetFile, signingFile, secretFile, databaseFile, "gateway.log", "orders.log", "inventory.log", "reports.log", "support.log", "accounts.log"}, keyFiles()...) {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("demonstration file %s must be a regular file, not a link or directory", name)
		}
	}
	return nil
}

const maxIdentityBytes = 4096

// readIdentity reads dir's identity as setup wrote it: one object, nothing after it.
func readIdentity(dir string) (demoIdentity, error) {
	var identity demoIdentity
	if _, err := os.Lstat(filepath.Join(dir, "caddy.json")); !errors.Is(err, os.ErrNotExist) {
		return identity, errors.New("legacy Caddy demonstration configuration is unsupported; create a new native demonstration directory")
	}
	file, err := os.Open(filepath.Join(dir, identityFile))
	if err != nil {
		return identity, fmt.Errorf("not an identified demonstration directory: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxIdentityBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		return identity, fmt.Errorf("invalid demonstration identity: %w", err)
	}
	// A second value or trailing text means this is not the identity that setup wrote.
	if _, err := decoder.Token(); err != io.EOF {
		return identity, errors.New("data after the demonstration identity")
	}
	return identity, nil
}

// rebind is demo rebind: it accepts the settings and service secret now in
// the directory, after an operator changed them by hand or a key change
// stopped between its two writes. Only a directory setup made for this path
// is rebound; the old and new digests are printed.
func rebind(args []string) error {
	dir, err := parse(flag.NewFlagSet("rebind", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	if err := checkFiles(dir); err != nil {
		return err
	}
	lock, err := lockDemo(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	identity, err := readIdentity(dir)
	if err != nil {
		return err
	}
	if identity.Format != "fetch-demo-1" || identity.Directory != dir {
		return fmt.Errorf("%s was made for %s, not this directory; not rebinding", identityFile, identity.Directory)
	}
	if err := identifyDemo(dir); err != nil {
		return err
	}
	now, err := readIdentity(dir)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s -> %s\n%s: %s -> %s\n", configFile, identity.Config, now.Config, secretFile, identity.Secret, now.Secret)
	return nil
}

// lockDemo holds dir's operator lock, so two demo commands never rewrite its
// settings at once; a second one is refused at once. The caller closes it.
func lockDemo(dir string) (*os.File, error) {
	path := filepath.Join(dir, lockFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	file.Close()
	lock, err := lockEarlierDemoFile(path)
	if err != nil {
		return nil, fmt.Errorf("another demo command is changing %s: %w", dir, err)
	}
	return lock, nil
}

func checkEarlierDemoForFresh(dir string) error {
	for _, name := range []string{identityFile, configFile, "fixture.secret"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("earlier demo identity requires regular owned files")
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "caddy.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("earlier Caddy state is not an identified native demo")
	}
	file, err := os.Open(filepath.Join(dir, identityFile))
	if err != nil {
		return err
	}
	defer file.Close()
	var identity struct {
		Format    string `json:"format"`
		Directory string `json:"directory"`
		Config    string `json:"config_sha256"`
		Secret    string `json:"fixture_secret_sha256"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxIdentityBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&identity) != nil {
		return errors.New("invalid earlier demo identity")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("data after earlier demo identity")
	}
	config, err := demoDigest(filepath.Join(dir, configFile))
	if err != nil {
		return err
	}
	secret, err := demoDigest(filepath.Join(dir, "fixture.secret"))
	if err != nil {
		return err
	}
	if identity.Format != "gateway-demo-1" || identity.Directory != dir || identity.Config != config || identity.Secret != secret {
		return errors.New("earlier demo binding does not match")
	}
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return err
	}
	var native struct {
		Version int `json:"version"`
	}
	// Only the native configuration format version 1 is read here; another version is refused.
	if json.Unmarshal(data, &native) != nil || native.Version != 1 {
		return errors.New("earlier configuration is not native version 1")
	}
	return nil
}
