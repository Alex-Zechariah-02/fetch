// Fetch Accounts: sign-in with the demo password, RS256 token issue and
// refresh with the signing key named in its settings file, and the signed-in
// account's profile.

package services

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
	"golang.org/x/crypto/argon2"
)

const demoPassword = "FetchDemo2026!"

type signingSettings struct {
	Kid            string `json:"kid"`
	PrivateKeyFile string `json:"private_key_file"`
}
type accounts struct {
	users        []User
	signingFile  string
	salt         []byte
	passwordHash []byte
	measure      bool // also the load accounts
	log          *slog.Logger
}

func newAccounts(file string, measure bool, log *slog.Logger) (*accounts, error) {
	if _, _, err := loadSigningKey(file); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	return &accounts{signingFile: file, salt: salt, passwordHash: passwordKey(demoPassword, salt), measure: measure, log: log}, nil
}
func passwordKey(password string, salt []byte) []byte {
	// Two passes over 64 MiB per attempt make each password guess costly.
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
}
func (d *accounts) reset() {
	d.users = Users()
	if d.measure {
		d.users = append(d.users, loadUsers()...)
	}
}
func (d *accounts) snapshot() any { return map[string]any{"users": d.users} }

// maxOperatorFile bounds every settings, key and secret file a service
// reads; the largest, a key set of a few keys, is a few KiB.
const maxOperatorFile = 64 << 10

// readBoundedFile reads an operator file of at most maxOperatorFile bytes;
// check, when not nil, judges the opened file first.
func readBoundedFile(path string, check func(os.FileInfo) error) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if check != nil {
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if err := check(info); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxOperatorFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOperatorFile {
		return nil, errors.New("operator file is too large")
	}
	return data, nil
}
func loadSigningKey(file string) (signingSettings, *rsa.PrivateKey, error) {
	settings := signingSettings{}
	data, err := readBoundedFile(file, nil)
	if err != nil {
		return settings, nil, err
	}
	var document any
	if !utf8.Valid(data) || guard.LoneSurrogate(data) || josejson.Unmarshal(data, &document) != nil || !validMembers(document, 0) {
		return settings, nil, errors.New("invalid signing settings")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || !validKid(settings.Kid) || !filepath.IsAbs(settings.PrivateKeyFile) {
		return settings, nil, errors.New("signing settings require a key ID and absolute private key file")
	}
	data, err = readBoundedFile(settings.PrivateKeyFile, nil)
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

// issue answers a sign-in or refresh with a new token for user. A token that
// cannot be signed answers 503 and records the cause, which the caller never
// sees.
func (d *accounts) issue(user User) result {
	token, expires, err := d.sign(user, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		d.log.Error("token not signed; sign-in refused", "settings", d.signingFile, "error", err)
		return failure(503, "accounts_unavailable", "Sign-in is temporarily unavailable. Try again later.", "")
	}
	return result{status: 200, body: map[string]any{"token": token, "expires_at": expires, "user": user}}
}

// sign makes user's token, issued at now, with the current signing key.
func (d *accounts) sign(user User, now time.Time) (string, time.Time, error) {
	settings, key, err := loadSigningKey(d.signingFile)
	if err != nil {
		return "", time.Time{}, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", settings.Kid))
	if err != nil {
		return "", time.Time{}, err
	}
	// A token lives 15 minutes, so an expired one is refused until the client refreshes.
	expires := now.Add(15 * time.Minute)
	claims, _ := json.Marshal(map[string]any{"iss": "fetch-accounts", "aud": "fetch-gateway", "sub": user.ID, "roles": user.Roles, "name": user.Name, "iat": now.Unix(), "nbf": now.Unix(), "exp": expires.Unix()})
	signed, err := signer.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := signed.CompactSerialize()
	return token, expires, err
}
func (d *accounts) handle(r *http.Request, body []byte) result {
	if _, ok := query(r); !ok {
		return invalidQuery()
	}
	if r.URL.Path == "/accounts/login" && r.Method == "POST" {
		var request struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if rejected := decodeBody(r, body, loginBody, &request); rejected != nil {
			return *rejected
		}
		// Lengths are checked before hashing, so no oversized credential reaches the password step.
		if !length(request.Email, 3, 254) || !length(request.Password, 1, 256) {
			return failure(400, "invalid_request", "Enter an email address and password within the allowed lengths.", "")
		}
		// Every credential attempt performs the identical password operation,
		// before checking whether the email names any account.
		valid := subtle.ConstantTimeCompare(passwordKey(request.Password, d.salt), d.passwordHash) == 1
		var selected User
		found := false
		for _, user := range d.users {
			if strings.EqualFold(user.Email, strings.TrimSpace(request.Email)) {
				selected = user
				found = true
			}
		}
		if !valid || !found {
			return failure(401, "invalid_credentials", "The email or password is incorrect.", "")
		}
		return d.issue(selected)
	}
	if r.URL.Path == "/accounts/refresh" && r.Method == "POST" || r.URL.Path == "/accounts/me" && r.Method == "GET" {
		if len(body) != 0 {
			return failure(400, "invalid_request", "This operation accepts no request body.", "")
		}
		for _, user := range d.users {
			if user.ID == r.Header.Get("X-Gateway-Subject") {
				if r.Method == "POST" {
					return d.issue(user)
				}
				return result{status: 200, body: map[string]any{"user": user}}
			}
		}
		return failure(401, "unauthenticated", "A valid signed-in account is required.", "")
	}
	return notFound()
}
