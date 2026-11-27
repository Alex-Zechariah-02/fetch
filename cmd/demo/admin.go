// The demo tool's Admin API client: the Dashboard's protocol (Origin, session
// cookie, CSRF token) for enrolment, sign-in, staging and the baseline's
// confirmed activation.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// adminClient speaks the Admin API's protocol as the Dashboard does: the
// admin Origin on every request and, once signed in, the session cookie and
// the session's CSRF token on every change.
type adminClient struct {
	address string
	client  *http.Client
	cookie  string
	csrf    string
}

// The gateway's administrator session cookie.
const adminSessionCookie = "__Host-gateway-admin"

func newAdminClient() *adminClient {
	return newAdminClientAt(adminListen)
}

func newAdminClientAt(address string) *adminClient {
	// 30 s: an Admin API call that never answers fails instead of blocking setup forever.
	return &adminClient{address: address, client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: refuseRedirect}}
}

// send makes one request and requires the wanted status. It never resends: a
// request without an answer may still have been applied.
func (a *adminClient) send(method, path string, body []byte, headers map[string]string, wanted int) (*http.Response, []byte, error) {
	request, err := http.NewRequest(method, "http://"+a.address+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Origin", "http://"+a.address)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if a.cookie != "" {
		request.Header.Set("Cookie", a.cookie)
	}
	if a.csrf != "" && method != http.MethodGet {
		request.Header.Set("X-CSRF-Token", a.csrf)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: no answer from the gateway, so it may or may not have been applied; check the Dashboard: %w", method, path, err)
	}
	defer response.Body.Close()
	const maxAdminBody = 1 << 20
	reply, err := io.ReadAll(io.LimitReader(response.Body, maxAdminBody))
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode != wanted {
		return nil, nil, fmt.Errorf("%s %s: %d %s", method, path, response.StatusCode, strings.TrimSpace(string(reply)))
	}
	return response, reply, nil
}

func marshal(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func mutationHeaders(ifMatch string) map[string]string {
	headers := map[string]string{"Idempotency-Key": newKey()}
	if ifMatch != "" {
		headers["If-Match"] = ifMatch
	}
	return headers
}

func newKey() string {
	// 16 random bytes (128 bits) in hex: every mutation gets its own idempotency key.
	key := make([]byte, 16)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func (a *adminClient) health() (string, error) {
	_, reply, err := a.send(http.MethodGet, "/admin/health", nil, nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var health struct {
		State string `json:"state"`
	}
	// Unmarshal first: a return statement may read health.State before the call.
	err = json.Unmarshal(reply, &health)
	return health.State, err
}

func (a *adminClient) enrol(secret, password string) error {
	_, _, err := a.send(http.MethodPost, "/admin/enrol", marshal(map[string]string{"name": upAdmin, "secret": secret, "password": password}), nil, http.StatusCreated)
	return err
}

func (a *adminClient) signIn(password string) error {
	response, reply, err := a.send(http.MethodPost, "/admin/session", marshal(map[string]string{"name": upAdmin, "password": password}), nil, http.StatusCreated)
	if err != nil {
		return fmt.Errorf("signing in as %s: %w", upAdmin, err)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == adminSessionCookie {
			a.cookie = cookie.Name + "=" + cookie.Value
		}
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(reply, &session); err != nil || a.cookie == "" || session.CSRF == "" {
		return errors.New("the sign-in answer held no session")
	}
	a.csrf = session.CSRF
	return nil
}

// signOut ends the session; a failure is reported to out, as the command's own
// result already stands and the session still ends at the idle timeout.
func (a *adminClient) signOut(out io.Writer) {
	if _, _, err := a.send(http.MethodDelete, "/admin/session", nil, nil, http.StatusNoContent); err != nil {
		fmt.Fprintf(out, "sign-out failed; the session ends at the gateway's idle timeout: %v\n", err)
	}
}

type stagedCandidate struct {
	ID       int64  `json:"id"`
	Checksum string `json:"checksum"`
}

// stage stores a complete policy document as a candidate prepared against
// the confirmed revision named by ifMatch.
func (a *adminClient) stage(document []byte, ifMatch string) (stagedCandidate, error) {
	body := append(append([]byte(`{"policy":`), document...), '}')
	_, reply, err := a.send(http.MethodPost, "/admin/candidates", body, mutationHeaders(ifMatch), http.StatusCreated)
	if err != nil {
		return stagedCandidate{}, err
	}
	var staged struct {
		Candidate stagedCandidate `json:"candidate"`
	}
	err = json.Unmarshal(reply, &staged)
	return staged.Candidate, err
}

// establishBaseline makes the demonstration's deny-all document the first
// policy, then activates the baseline document and confirms it, as the
// Dashboard's Changes page would. Both documents are the ones setup wrote
// into the demonstration directory.
func (a *adminClient) establishBaseline(state string) error {
	denyAllDocument, err := compactFile(filepath.Join(state, denyAllFile))
	if err != nil {
		return err
	}
	baselineDocument, err := compactFile(filepath.Join(state, baselineFile))
	if err != nil {
		return err
	}

	first, err := a.stage(denyAllDocument, genesisRevision)
	if err != nil {
		return err
	}
	genesis := map[string]any{"candidate": first.ID, "checksum": first.Checksum}
	if _, _, err := a.send(http.MethodPost, "/admin/genesis", marshal(genesis), nil, http.StatusOK); err != nil {
		return err
	}

	confirmed, _, err := a.send(http.MethodGet, "/admin/policy", nil, nil, http.StatusOK)
	if err != nil {
		return err
	}
	revision := confirmed.Header.Get("ETag")
	baseline, err := a.stage(baselineDocument, revision)
	if err != nil {
		return err
	}
	// 300 s is generous: the confirm follows within two calls, each capped at 30 s.
	activation := map[string]any{"candidate": baseline.ID, "checksum": baseline.Checksum, "confirm_within_seconds": 300}
	if _, _, err := a.send(http.MethodPost, "/admin/provisional", marshal(activation), mutationHeaders(revision), http.StatusOK); err != nil {
		return err
	}

	provisional, reply, err := a.send(http.MethodGet, "/admin/provisional", nil, nil, http.StatusOK)
	if err != nil {
		return err
	}
	var waiting struct {
		Activation struct {
			Revision int64 `json:"revision"`
		} `json:"activation"`
	}
	if err := json.Unmarshal(reply, &waiting); err != nil {
		return err
	}
	confirm := marshal(map[string]int64{"revision": waiting.Activation.Revision})
	_, _, err = a.send(http.MethodPost, "/admin/provisional/confirm", confirm, mutationHeaders(provisional.Header.Get("ETag")), http.StatusOK)
	return err
}

// maxPolicyFile bounds the read of a policy file. The gateway decides the
// policy's size by its own limits.policy_bytes and names both sizes when it
// refuses one; 4 MiB is far above any limit it accepts.
const maxPolicyFile = 4 << 20

// genesisRevision is the ETag APIWard's Admin API gives a deployment before
// its first policy ("r" and confirmed revision 0); staging the first
// candidate against any other value is refused there, and the round-trip
// test stages against it.
const genesisRevision = `"r0"`

// compactFile reads the policy file at path, at most maxPolicyFile bytes, and
// returns it compacted.
func compactFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxPolicyFile)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return compact.Bytes(), nil
}
