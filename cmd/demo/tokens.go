// Demo tokens: before a load run, sign the measurement accounts in at Fetch
// Accounts on this host and write their tokens to a file the load script
// reads, so sign-in is never timed. It connects from this host's loopback
// address and names each account's own visitor address, as the demo's proxy
// does, so built-in protection counts every sign-in against its own visitor.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// loadAccounts is how many load accounts measurement mode seeds; limited
// (load-1000) is the account a load run sends over its rate, the others are
// its customers.
const (
	loadAccounts = 10000
	limited      = 1000
)

// signer is one account a load run signs in as.
type signer struct {
	ID       string `json:"id"`
	Merchant string `json:"merchant,omitempty"`
	Token    string `json:"token"`
	email    string
}

// tokenFile is what demo tokens writes: the customers load-0001 to
// load-10000 except load-1000, the merchants whose stock a mix reads, and
// load-1000.
type tokenFile struct {
	Customers []signer  `json:"customers"`
	Merchants []signer  `json:"merchants"`
	Limited   signer    `json:"limited"`
	Expires   time.Time `json:"expires"`
}

// tokens is demo tokens: it signs every measurement account in at the
// Accounts address with the client certificate in certs and writes the
// tokens to out, readable by its owner only.
func tokens(args []string) error {
	set := flag.NewFlagSet("tokens", flag.ContinueOnError)
	address := set.String("accounts", "", "Fetch Accounts on this host, IP:port")
	certs := set.String("certs", "", "the gateway's folder from demo certs (its client certificate and CA)")
	out := set.String("out", "", "the token file to write")
	// Accounts signs in one account at a time (about 0.1 s of Argon2id each), and
	// tokens live 15 minutes: a run signs in only the customers it needs.
	customers := set.Int("customers", loadAccounts-1, "how many customers to sign in, the first ones of load-0001 to load-10000 without load-1000")
	if err := set.Parse(args); err != nil {
		return err
	}
	target, err := netip.ParseAddrPort(*address)
	if set.NArg() != 0 || err != nil || *out == "" || *customers < 1 || *customers > loadAccounts-1 {
		return errors.New("use: demo tokens -accounts IP:PORT -certs DIR -out FILE [-customers 1-9999]")
	}
	client, err := tokenClient(*certs)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	file := measurementSigners(*customers)
	everyone := []*signer{&file.Limited}
	for i := range file.Customers {
		everyone = append(everyone, &file.Customers[i])
	}
	for i := range file.Merchants {
		everyone = append(everyone, &file.Merchants[i])
	}
	if file.Expires, err = signAll(client, "https://"+target.String(), everyone); err != nil {
		return err
	}
	// The file holds bearer tokens, so only its owner reads it.
	if err := os.WriteFile(*out, indented(file), 0o600); err != nil {
		return err
	}
	fmt.Printf("%d tokens in %s, the first expiring %s\n", len(everyone), *out, file.Expires.UTC().Format(time.RFC3339))
	return nil
}

// measurementSigners are the accounts of a token file, without tokens: the
// first customers load accounts other than load-1000, and load-1000.
func measurementSigners(customers int) tokenFile {
	var file tokenFile
	for n := 1; len(file.Customers) < customers; n++ {
		if n == limited {
			continue
		}
		file.Customers = append(file.Customers, signer{ID: fmt.Sprintf("load-%04d", n), email: fmt.Sprintf("load%04d@fetch.test", n)})
	}
	file.Limited = signer{ID: fmt.Sprintf("load-%04d", limited), email: fmt.Sprintf("load%04d@fetch.test", limited)}
	for _, user := range services.Users() {
		// MER-005 and MER-006 count their stock; the mixes read only theirs.
		if user.Merchant != nil && (*user.Merchant == "MER-005" || *user.Merchant == "MER-006") {
			file.Merchants = append(file.Merchants, signer{ID: user.ID, Merchant: *user.Merchant, email: user.Email})
		}
	}
	return file
}

// signAll signs every account in with eight sign-ins at a time, the n-th
// named as visitor 198.18.0.0 + n (the benchmarking range of RFC 2544), and
// returns the earliest expiry. A refused sign-in fails the whole file and
// stops the sign-ins not yet sent.
func signAll(client *http.Client, origin string, everyone []*signer) (time.Time, error) {
	var (
		mutex    sync.Mutex
		earliest time.Time
		failed   error
		group    sync.WaitGroup
	)
	work := make(chan int)
	// Eight at a time: Accounts hashes each password with Argon2id, so more only queue there.
	for range 8 {
		group.Go(func() {
			for n := range work {
				visitor := netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)}).String()
				token, expires, err := loginWithClient(client, origin, everyone[n].email, visitor)
				mutex.Lock()
				if err != nil {
					failed = errors.Join(failed, fmt.Errorf("%s: %w", everyone[n].ID, err))
				}
				everyone[n].Token = token
				if earliest.IsZero() || expires.Before(earliest) {
					earliest = expires
				}
				mutex.Unlock()
			}
		})
	}
	for n := range everyone {
		mutex.Lock()
		stop := failed != nil
		mutex.Unlock()
		// One refused sign-in already fails the file; the rest are not sent.
		if stop {
			break
		}
		work <- n
	}
	close(work)
	group.Wait()
	return earliest, failed
}

// tokenClient connects from 127.0.0.1 with the gateway's client certificate
// in folder and accepts only a server certificate the folder's CA issued.
func tokenClient(folder string) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(folder, clientCertFile), filepath.Join(folder, clientKeyFile))
	if err != nil {
		return nil, err
	}
	authority, err := os.ReadFile(filepath.Join(folder, caFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority) {
		return nil, fmt.Errorf("%s holds no certificate", filepath.Join(folder, caFile))
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
		// Fetch's certificate names the address demo certs was given, while a
		// measured host may serve it on another one: the chain is checked, the name is not.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
			return err
		},
	}
	// From loopback, so the APIs trust the visitor address it names.
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: config, MaxIdleConnsPerHost: 8}
	// Thirty seconds a sign-in: Argon2id under eight parallel sign-ins can take seconds on a small host.
	return &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: refuseRedirect}, nil
}
