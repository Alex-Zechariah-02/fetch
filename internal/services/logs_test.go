// The service log keeps what answers and receipts cannot: a reset that
// clears the receipts, and why Accounts could not sign a token.

package services

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestServiceLogsResetAndSigningFailure(t *testing.T) {
	t.Parallel()
	var record bytes.Buffer
	log := slog.New(slog.NewTextHandler(&record, nil))
	s := newService(t, Config{Name: "support", Secret: testSecret, Log: log})
	serviceRequest(s, "GET", "/support/mine", "", "cust-002", "CUSTOMER", "")
	reset := httptest.NewRequest("POST", "/reset", nil)
	reset.Header.Set("Authorization", "Bearer "+string(testSecret))
	w := httptest.NewRecorder()
	s.Control(testSecret).ServeHTTP(w, reset)
	if w.Code != 200 || !strings.Contains(record.String(), "reset to the seed") || !strings.Contains(record.String(), "answers=1") {
		t.Fatalf("reset %d, recorded %q", w.Code, record.String())
	}

	_, _, settings := accountService(t)
	accounts := newService(t, Config{Name: "accounts", Secret: testSecret, SigningSettingsFile: settings, Log: log})
	if err := os.Remove(settings); err != nil {
		t.Fatal(err)
	}
	login := serviceRequest(accounts, "POST", "/accounts/login", `{"email":"customer1@fetch.test","password":"FetchDemo2026!"}`, "", "", "")
	if login.Code != 503 || strings.Contains(login.Body.String(), settings) {
		t.Fatalf("sign-in without signing settings: %d %s", login.Code, login.Body)
	}
	if !strings.Contains(record.String(), "token not signed") || !strings.Contains(record.String(), "accounts.json") {
		t.Fatalf("the signing failure was not recorded with its cause: %q", record.String())
	}
}
