// Fetch Accounts: sign-in with the demo password, RS256 token issue and
// refresh with the signing key named in its settings file, and the signed-in
// account's profile.

package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/trusted"
	"golang.org/x/crypto/argon2"
)

const (
	demoPassword  = "FetchDemo2026!"
	tokenLifetime = 15 * time.Minute
	minEmail      = 3
	maxEmail      = 254
	maxPassword   = 256
)

type signingSettings struct {
	Kid            string `json:"kid"`
	PrivateKeyFile string `json:"private_key_file"`
}
type accounts struct {
	users []User
	// byID and byEmail index users by ID and by lowercased e-mail address.
	byID, byEmail map[string]int
	signingFile   string
	salt          []byte
	passwordHash  []byte
	measure       bool // also the load accounts
	log           *slog.Logger
	// outside runs password hashing and token signing without the service
	// lock; hashing holds one slot per derivation running.
	outside func(context.Context, func())
	hashing chan struct{}
	signer  signerCache
}

// hashWait bounds a sign-in's wait for a hashing slot; past it the sign-in
// is refused 503 with Retry-After rather than queued without end.
const hashWait = 2 * time.Second

func newAccounts(file string, measure bool, log *slog.Logger, outside func(context.Context, func())) (*accounts, error) {
	d := &accounts{signingFile: file, measure: measure, log: log, outside: outside}
	if _, err := d.signer.current(file); err != nil {
		return nil, err
	}
	d.salt = make([]byte, 16)
	if _, err := rand.Read(d.salt); err != nil {
		return nil, err
	}
	d.passwordHash = passwordKey(demoPassword, d.salt)
	// Each derivation runs two threads, so half the processors keep every
	// one busy; each slot holds 64 MiB while it runs.
	d.hashing = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))
	return d, nil
}
func passwordKey(password string, salt []byte) []byte {
	// Two passes over 64 MiB per attempt make each password guess costly.
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
}

// checkPassword derives password's key in a hashing slot and compares it;
// busy reports that no slot came free within hashWait.
func (d *accounts) checkPassword(ctx context.Context, password string) (valid, busy bool) {
	wait, cancel := context.WithTimeout(ctx, hashWait)
	defer cancel()
	select {
	case d.hashing <- struct{}{}:
	case <-wait.Done():
		return false, true
	}
	defer func() { <-d.hashing }()
	return subtle.ConstantTimeCompare(passwordKey(password, d.salt), d.passwordHash) == 1, false
}

func (d *accounts) reset() {
	d.users = Users()
	if d.measure {
		d.users = append(d.users, loadUsers()...)
	}
	d.byID = make(map[string]int, len(d.users))
	d.byEmail = make(map[string]int, len(d.users))
	for i, user := range d.users {
		d.byID[user.ID] = i
		d.byEmail[strings.ToLower(user.Email)] = i
	}
}
func (d *accounts) snapshot() any { return map[string]any{"users": d.users} }

// maxOperatorFile bounds every settings, key and secret file a service
// reads; the largest, a key set of a few keys, is a few KiB.
const maxOperatorFile = 64 << 10

// readBoundedFile reads an operator file of at most maxOperatorFile bytes:
// a regular file (a FIFO or device would hang or never end), judged by check
// when not nil.
func readBoundedFile(path string, check func(os.FileInfo) error) ([]byte, error) {
	return trusted.ReadBounded(path, maxOperatorFile, check)
}

// issue answers a sign-in or refresh with a new token for user. A token that
// cannot be signed answers 503 and records the cause, which the caller never
// sees. It reads no service data, so it runs outside the lock.
func (d *accounts) issue(user User) result {
	token, expires, err := d.sign(user, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		d.log.Error("token not signed; sign-in refused", "settings", d.signingFile, "error", err)
		return failure(503, "accounts_unavailable", "Sign-in is temporarily unavailable. Try again later.", "")
	}
	return result{status: http.StatusOK, body: map[string]any{"token": token, "expires_at": expires, "user": user}}
}

// sign makes user's token, issued at now, with the current signing key.
func (d *accounts) sign(user User, now time.Time) (string, time.Time, error) {
	key, err := d.signer.current(d.signingFile)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(tokenLifetime)
	claims, err := json.Marshal(map[string]any{"iss": "fetch-accounts", "aud": "fetch-gateway", "sub": user.ID, "roles": user.Roles, "name": user.Name, "iat": now.Unix(), "nbf": now.Unix(), "exp": expires.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	signed, err := key.signer.Sign(claims)
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
		return d.login(r, body)
	}
	if r.URL.Path == "/accounts/refresh" && r.Method == "POST" || r.URL.Path == "/accounts/me" && r.Method == "GET" {
		if len(body) != 0 {
			return failure(400, "invalid_request", "This operation accepts no request body.", "")
		}
		i, found := d.byID[r.Header.Get("X-Gateway-Subject")]
		if !found {
			return failure(401, "unauthenticated", "A valid signed-in account is required.", "")
		}
		user := d.users[i]
		if r.Method == "GET" {
			return result{status: 200, body: map[string]any{"user": user}}
		}
		var res result
		d.outside(r.Context(), func() { res = d.issue(user) })
		return res
	}
	return notFound()
}

// login checks the password outside the service lock, in a bounded number
// of hashing slots, so sign-ins use every processor and never hold up other
// requests.
func (d *accounts) login(r *http.Request, body []byte) result {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if rejected := decodeBody(r, body, loginBody, &request); rejected != nil {
		return *rejected
	}
	// Lengths are checked before hashing, so no oversized credential reaches the password step.
	if !length(request.Email, minEmail, maxEmail) || !length(request.Password, 1, maxPassword) {
		return failure(400, "invalid_request", "Enter an email address and password within the allowed lengths.", "")
	}
	i, found := d.byEmail[strings.ToLower(strings.TrimSpace(request.Email))]
	var selected User
	if found {
		selected = d.users[i]
	}
	// Every credential attempt performs the identical password operation,
	// whether or not the email names any account.
	var res result
	d.outside(r.Context(), func() {
		valid, busy := d.checkPassword(r.Context(), request.Password)
		switch {
		case busy:
			res = failure(503, "accounts_busy", "Sign-in is busy. Try again in a moment.", "")
			res.retryAfter = 1
		case !valid || !found:
			res = failure(401, "invalid_credentials", "The email or password is incorrect.", "")
		default:
			res = d.issue(selected)
		}
	})
	return res
}
