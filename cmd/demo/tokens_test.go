// Demo tokens: every measurement account signs in once, from loopback with
// its own visitor address, over TLS with the gateway's client certificate,
// and a server certificate from another CA is refused.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// accountsServer is a stand-in Accounts over TLS that admits only clients
// with a certificate of folder's CA and records each sign-in's visitor.
func accountsServer(t *testing.T, folder string, visitors *sync.Map) *httptest.Server {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(filepath.Join(folder, serverCertFile), filepath.Join(folder, serverKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := os.ReadFile(filepath.Join(folder, caFile))
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	clients.AppendCertsFromPEM(authority)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email string }
		if r.URL.Path != "/accounts/login" || json.NewDecoder(r.Body).Decode(&body) != nil || !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		if _, again := visitors.LoadOrStore(r.Header.Get("X-Forwarded-For"), body.Email); again {
			http.Error(w, "visitor reused", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"token": "t-" + body.Email, "expires_at": time.Now().Add(maxTokenTTL)})
	}))
	// The refused handshakes of the other-CA case are expected; they are not logged.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestTokensSignEveryAccountOnce(t *testing.T) {
	t.Parallel()
	root := writeDeployment(t, "host")
	var visitors sync.Map
	server := accountsServer(t, filepath.Join(root, "fetch"), &visitors)
	out := filepath.Join(t.TempDir(), "tokens.json")
	address := strings.TrimPrefix(server.URL, "https://")
	if err := tokens([]string{"-accounts", address, "-certs", filepath.Join(root, "gateway"), "-out", out}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var file tokenFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	// Customer 999 (index 998) is load-0999 and the next is load-1001: load-1000 is the limited account only.
	if len(file.Customers) != loadAccounts-1 || file.Customers[0].ID != "load-0001" || file.Customers[0].Token != "t-load0001@fetch.test" ||
		file.Customers[998].ID != "load-0999" || file.Customers[999].ID != "load-1001" || file.Customers[len(file.Customers)-1].ID != "load-10000" {
		t.Fatalf("customers: %d, first %+v", len(file.Customers), file.Customers[0])
	}
	if file.Limited.ID != "load-1000" || file.Limited.Token != "t-load1000@fetch.test" || len(file.Merchants) != 2 || file.Merchants[0].Merchant != "MER-005" || file.Merchants[0].Token == "" {
		t.Fatalf("limited %+v merchants %+v", file.Limited, file.Merchants)
	}
	count := 0
	visitors.Range(func(any, any) bool { count++; return true })
	if count != loadAccounts+2 {
		t.Fatalf("%d visitors for %d sign-ins", count, loadAccounts+2)
	}
	if file.Expires.IsZero() {
		t.Fatal("no expiry")
	}
	// A run that needs fewer customers signs in only the first ones, still
	// skipping load-1000.
	if few := measurementSigners(1000); len(few.Customers) != 1000 || few.Customers[999].ID != "load-1001" || few.Limited.ID != "load-1000" {
		t.Fatalf("1,000 customers: %d, last %s, limited %s", len(few.Customers), few.Customers[len(few.Customers)-1].ID, few.Limited.ID)
	}
	if err := tokens([]string{"-accounts", address, "-certs", filepath.Join(root, "gateway"), "-out", out, "-customers", "0"}); err == nil {
		t.Fatal("zero customers accepted")
	}

	// A server whose certificate another CA issued is not Fetch's.
	other := accountsServer(t, filepath.Join(writeDeployment(t, "other"), "fetch"), &sync.Map{})
	err = tokens([]string{"-accounts", strings.TrimPrefix(other.URL, "https://"), "-certs", filepath.Join(root, "gateway"), "-out", filepath.Join(t.TempDir(), "x.json")})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("another CA's server: %v", err)
	}
}
