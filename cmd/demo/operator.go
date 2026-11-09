// Operator commands of the demo tool: Fetch sign-ins, bounded attack traffic,
// policy export and staging, and whole-file writes.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func accountLogin(origin, email string) (string, time.Time, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: refuseRedirect}
	defer client.CloseIdleConnections()
	return loginWithClient(client, origin, email)
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func loginWithClient(client *http.Client, origin, email string) (string, time.Time, error) {
	request, err := http.NewRequest("POST", origin+"/accounts/login", bytes.NewReader(marshal(map[string]string{"email": email, "password": "FetchDemo2026!"})))
	if err != nil {
		return "", time.Time{}, err
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("Accounts did not answer: %w", err)
	}
	defer response.Body.Close()
	var reply struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&reply) != nil || reply.Token == "" || reply.Expires.IsZero() {
		return "", time.Time{}, fmt.Errorf("Accounts sign-in failed (status %d)", response.StatusCode)
	}
	return reply.Token, reply.Expires, nil
}

// attack sends one scenario's requests to the demonstration's gateway from
// another loopback source address, or with -target to a gateway on another
// host from this machine's own address, and prints the answers by status.
func attack(args []string) error {
	set := flag.NewFlagSet("attack", flag.ContinueOnError)
	scenario := set.String("scenario", "", "flood-search, flood-login or flood-orders")
	from := set.String("from", "127.0.0.50", "source IPv4 loopback address, on the demonstration's machine")
	dir := set.String("dir", "", "demonstration directory, on the demonstration's machine")
	target := set.String("target", "", "a gateway on another host: its shop origin, such as https://203.0.113.10:9480")
	ca := set.String("ca", "", "with -target: CA certificate (PEM) the gateway's certificate is checked against (default: the system's)")
	count := set.Int("count", 100, "number of requests (1 to 10000)")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("attack takes no arguments\n" + usage)
	}
	if *scenario != "flood-search" && *scenario != "flood-login" && *scenario != "flood-orders" {
		return errors.New("choose flood-search, flood-login or flood-orders")
	}
	if *count < 1 || *count > 10000 {
		return errors.New("use a count from 1 to 10000")
	}
	var client *http.Client
	var origin, source string
	var err error
	if *target != "" {
		if err := onlyFlags(set, "scenario", "count", "target", "ca"); err != nil {
			return err
		}
		origin, client, err = remoteClient(*target, *ca)
		source = "target=" + origin
	} else {
		if err := onlyFlags(set, "scenario", "count", "from", "dir"); err != nil {
			return err
		}
		origin, source = "http://"+dataListen, "from="+*from
		client, err = localClient(*from, *dir)
	}
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	token := ""
	if *scenario == "flood-orders" {
		// This limit is per account: a different source address alone would
		// still consume Customer 1's checkout budget.
		token, _, err = loginWithClient(client, origin, "customer2@fetch.test")
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	counts := map[int]int{}
	start := time.Now()
	for range *count {
		method, path, body := "GET", "/inventory/search?q=rice", []byte(nil)
		switch *scenario {
		case "flood-login":
			method, path, body = "POST", "/accounts/login", marshal(map[string]string{"email": "nobody@fetch.test", "password": "wrong-password"})
		case "flood-orders":
			method, path, body = "POST", "/orders", marshal(map[string]any{"merchant": "MER-001", "items": []map[string]any{{"item": "ITM-001", "quantity": 1}}, "address": map[string]string{"line1": "12 Jalan Telawi 3", "postcode": "59100", "city": "Kuala Lumpur", "state": "Wilayah Persekutuan Kuala Lumpur"}, "payment": "cash"})
		}
		request, _ := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
		request.GetBody = nil // A write without an answer is never retried by the transport.
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Idempotency-Key", newKey())
		}
		response, err := client.Do(request)
		if err != nil {
			fmt.Printf("scenario=%s %s responses=%v elapsed=%s; stopped with an unknown request outcome\n", *scenario, source, counts, time.Since(start).Round(time.Millisecond))
			return err
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			return readErr
		}
		counts[response.StatusCode]++
	}
	fmt.Printf("scenario=%s %s requests=%d responses=%v elapsed=%s\n", *scenario, source, *count, counts, time.Since(start).Round(time.Millisecond))
	return nil
}

// localClient sends from the IPv4 loopback address from, on the machine of
// the demonstration in dir.
func localClient(from, dir string) (*http.Client, error) {
	address, err := netip.ParseAddr(from)
	if err != nil || !address.Is4() || !address.IsLoopback() {
		return nil, errors.New("use an IPv4 loopback source")
	}
	if dir == "" {
		return nil, errors.New("-dir is required without -target\n" + usage)
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, err
	}
	if err := checkDemo(dir); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(address.AsSlice())}, Timeout: 2 * time.Second}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext}, CheckRedirect: refuseRedirect}, nil
}

// remoteClient checks target, a gateway's https origin, and returns it
// without a trailing slash with a client that checks the gateway's
// certificate against the CA file at ca, or the system's roots.
func remoteClient(target, ca string) (string, *http.Client, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", nil, errors.New("-target is a gateway's https origin, such as https://203.0.113.10:9480")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		data, err := os.ReadFile(ca)
		if err != nil {
			return "", nil, err
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(data) {
			return "", nil, fmt.Errorf("%s holds no CA certificate", ca)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: config}, CheckRedirect: refuseRedirect}
	return "https://" + parsed.Host, client, nil
}

func operatorSession(dir string) (*adminClient, error) {
	if err := checkDemo(dir); err != nil {
		return nil, err
	}
	password, err := readSecretLine("Password of Dashboard administrator " + upAdmin + " (not shown): ")
	if err != nil {
		return nil, err
	}
	admin := newAdminClient()
	if err = admin.signIn(password); err != nil {
		admin.client.CloseIdleConnections()
		return nil, err
	}
	return admin, nil
}

func policy(args []string) error {
	if len(args) == 0 || args[0] != "export" && args[0] != "stage" {
		return errors.New("choose policy export or policy stage")
	}
	set := flag.NewFlagSet("policy "+args[0], flag.ContinueOnError)
	var path *string
	if args[0] == "export" {
		path = set.String("out", "", "new output file")
	} else {
		path = set.String("file", "", "complete policy file")
	}
	dir, err := parse(set, args[1:])
	if err != nil {
		return err
	}
	if *path == "" {
		return errors.New("an output or input file is required")
	}
	var document []byte
	if args[0] == "stage" {
		document, err = compactFile(*path)
		if err != nil {
			return err
		}
		if len(document) > 1<<20 {
			return errors.New("policy file is too large")
		}
	}
	admin, err := operatorSession(dir)
	if err != nil {
		return err
	}
	defer admin.signOut()
	response, body, err := admin.send("GET", "/admin/policy", nil, nil, 200)
	if err != nil {
		return err
	}
	if args[0] == "export" {
		var revision struct {
			Document json.RawMessage `json:"document"`
		}
		if json.Unmarshal(body, &revision) != nil || len(revision.Document) == 0 {
			return errors.New("policy response has no document")
		}
		if err := writeNewFile(*path, append(revision.Document, '\n')); err != nil {
			return err
		}
		fmt.Println("confirmed policy exported to", *path)
		return nil
	}
	candidate, err := admin.stage(document, response.Header.Get("ETag"))
	if err != nil {
		return err
	}
	fmt.Printf("candidate %d staged; checksum %s; policy is not activated\n", candidate.ID, candidate.Checksum)
	return nil
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

// Operator updates replace a whole regular file. The temporary file is owned
// by this invocation; a failed write cannot leave a partially parsed key set.
func replaceOperatorFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return errors.New("operator target must be an existing regular file")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".fetch-operator-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
