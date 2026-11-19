// Fetch Accounts' signing key: read from the file its settings name, parsed
// and checked once, and kept with its signer until either file changes, so a
// token costs one signature and two file stats, not a key parse.

package services

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"github.com/go-jose/go-jose/v4"
)

// stamp tells a file's versions apart: its size and modification time.
type stamp struct {
	size     int64
	modified time.Time
}

func stampOf(path string) (stamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{info.Size(), info.ModTime()}, nil
}

// signingKey is a loaded key with its signer and the stamps of its files.
type signingKey struct {
	settings, key stamp
	path          string // the private key file
	signer        jose.Signer
}

// signerCache holds the current signing key; reloads take mu, so two
// changes are never loaded at once.
type signerCache struct {
	held atomic.Pointer[signingKey]
	mu   sync.Mutex
}

// current returns the signing key of the settings file, loading it again
// when the settings or the key file changed since it was loaded.
func (c *signerCache) current(file string) (*signingKey, error) {
	settingsStamp, err := stampOf(file)
	if err != nil {
		return nil, err
	}
	if held := c.held.Load(); held != nil && held.settings == settingsStamp {
		if keyStamp, err := stampOf(held.path); err == nil && keyStamp == held.key {
			return held, nil
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	settings, key, err := loadSigningKey(file)
	if err != nil {
		return nil, err
	}
	keyStamp, err := stampOf(settings.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", settings.Kid))
	if err != nil {
		return nil, err
	}
	loaded := &signingKey{settings: settingsStamp, key: keyStamp, path: settings.PrivateKeyFile, signer: signer}
	c.held.Store(loaded)
	return loaded, nil
}

func loadSigningKey(file string) (signingSettings, *rsa.PrivateKey, error) {
	settings := signingSettings{}
	data, err := readBoundedFile(file, trusted)
	if err != nil {
		return settings, nil, err
	}
	if !utf8.Valid(data) || guard.LoneSurrogate(data) || !strictObject(data) {
		return settings, nil, errors.New("invalid signing settings")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || !validKid(settings.Kid) || !filepath.IsAbs(settings.PrivateKeyFile) {
		return settings, nil, errors.New("signing settings require a key ID and absolute private key file")
	}
	data, err = readBoundedFile(settings.PrivateKeyFile, private)
	if err != nil {
		return settings, nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		return settings, nil, errors.New("invalid private key PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return settings, nil, err
		}
		key, _ = parsed.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return settings, nil, err
		}
	default:
		return settings, nil, errors.New("an RSA private key is required")
	}
	// A key outside 2048 to 8192 bits is refused before it can sign a token.
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
		return settings, nil, errors.New("an RSA private key of 2048 to 8192 bits is required")
	}
	return settings, key, nil
}
func validKid(kid string) bool {
	// The key ID must be 1 to 64 letters, digits, _ - . so it is safe in a JWT header.
	if len(kid) < 1 || len(kid) > 64 {
		return false
	}
	for _, c := range kid {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
