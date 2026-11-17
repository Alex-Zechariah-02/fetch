// Who checks the requests a Fetch host of demo up -role fetch serves: the
// gateway (the APIs answer only its signed assertion), nothing (-standalone:
// the APIs believe the identity headers, for measuring the unprotected
// floor), or each API itself (-local: built-in protection). The run folder's
// files follow from it.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
)

// hostChecks is who checks the requests of a Fetch host's APIs.
type hostChecks int

const (
	gatewayChecks hostChecks = iota
	noChecks
	builtinChecks
)

// checksOf is the checks the -standalone and -local flags of -role fetch select.
func checksOf(standalone, local bool) (hostChecks, error) {
	switch {
	case standalone && local:
		return 0, errors.New("-standalone and -local exclude each other")
	case standalone:
		return noChecks, nil
	case local:
		return builtinChecks, nil
	}
	return gatewayChecks, nil
}

// hostFiles are the run folder dir's files on a Fetch host: the service
// secret and the signing settings of the key in folder (ID kid) and, with
// built-in protection, that key's public half as the one key every API
// trusts and an empty blocked list.
func hostFiles(dir, folder, kid string, checks hostChecks) (map[string][]byte, error) {
	private := filepath.Join(folder, privateKeyFile)
	files := map[string][]byte{secretFile: newSecret(), signingFile: signingSettings(kid, private)}
	if checks != builtinChecks {
		return files, nil
	}
	public, err := publicHalf(private)
	if err != nil {
		return nil, err
	}
	files[publicKeyFile] = public
	files[guard.KeysFile] = indented([]guard.Key{{Kid: kid, PublicKeyFile: filepath.Join(dir, publicKeyFile)}})
	files[guard.BlockedFile] = indented([]string{})
	return files, nil
}

// publicHalf is the PKIX PEM public key of the PKCS #8 PEM private key at path.
func publicHalf(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s holds no private key", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s is not a signing key", path)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	return pemBlock("PUBLIC KEY", der), nil
}

// hostBanner is what a Fetch host prints once it serves the APIs from first
// to last and the shop at site.
func hostBanner(checks hostChecks, first, last, site, bind string) string {
	addresses := fmt.Sprintf("  APIs and Accounts: https://%s to %s\n  shop:              https://%s/\n", first, last, site)
	switch checks {
	case noChecks:
		return standaloneWarning + "\nFetch admits only the gateway's client certificate; its APIs check nothing else:\n" + addresses + "Press Ctrl+C to stop."
	case builtinChecks:
		return "BUILT-IN PROTECTION: no gateway; Fetch admits only the gateway's client certificate, and each API checks every request itself:\n" + addresses + "Press Ctrl+C to stop."
	}
	return "Fetch admits only the gateway's client certificate, and its four APIs only requests the gateway signed:\n" + addresses +
		"On the gateway host: go run ./cmd/demo up -role gateway -fetch " + bind + " -certs <gateway folder>\nPress Ctrl+C to stop."
}
