// The standalone mode of demo up: the shop, the four APIs and Accounts with
// no gateway. The demo process takes the data-plane address, forwards each
// API path to its service and serves the shop itself. Nothing is checked:
// this is the application before it is protected, never a security mode.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// standaloneWarning is printed whenever the unprotected mode runs.
const standaloneWarning = `STANDALONE: no gateway. Every request reaches the services unchecked, and any
signed-in identity is believed without checking its token. Never use this
mode to protect anything; run demo up without -standalone for that.`

// identityHeaders are the headers the services read the caller from. In this
// mode they come only from the token's unverified claims, never the client.
var identityHeaders = []string{"X-Gateway-Subject", "X-Gateway-Roles", "X-Gateway-Generation"}

// runStandalone starts the services and Accounts with the files in dir,
// serves the shop in shop and the API paths on the data-plane address, and
// stops everything when ctx ends.
func runStandalone(ctx context.Context, dir string, shop fs.FS, serviceBinary, accountsBinary string) (runErr error) {
	if err := checkPortsFree(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", dataListen)
	if err != nil {
		return fmt.Errorf("the shop address: %w", err)
	}
	server := &http.Server{Handler: standaloneHandler(shop), ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	// The server stops last, after every child, mirroring demo run.
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, server.Shutdown(shutdown))
	}()

	running := newChildren(dir, len(fetchServices))
	defer func() { runErr = errors.Join(runErr, running.stop()) }()
	addresses, err := running.startServices(dir, serviceBinary, accountsBinary)
	if err != nil {
		return err
	}
	if err := running.awaitListening(ctx, addresses, time.Now().Add(30*time.Second)); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}
	fmt.Println(standaloneWarning)
	running.printProcesses()
	fmt.Printf("\nShop: http://%s/  (unprotected)\nPress Ctrl+C to stop.\n", dataListen)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("stopping")
			return nil
		case err := <-served:
			return fmt.Errorf("the shop server stopped (%v)", err)
		case result := <-running.exited:
			running.received()
			fmt.Printf("service %s stopped (%v); its requests now fail\n", result.name, result.err)
		}
	}
}

// standaloneHandler sends the API paths the shop calls to their services,
// with the same split as the shop's development proxy, and serves the shop
// for every other path.
func standaloneHandler(shop fs.FS) http.Handler {
	site := website(shop)
	proxies := map[string]http.Handler{}
	for _, service := range fetchServices {
		target := &url.URL{Scheme: "http", Host: service.listen}
		proxies[service.name] = &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			copyIdentity(r.Out)
		}}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy, ok := proxies[apiOf(r.URL.Path)]; ok {
			proxy.ServeHTTP(w, r)
			return
		}
		site.ServeHTTP(w, r)
	})
}

// apiOf names the service a path belongs to, or "" for the shop: /support
// alone is the shop's support page, while /orders alone is an API call.
func apiOf(path string) string {
	name, _, nested := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	switch name {
	case "inventory", "orders", "reports", "accounts":
		return name
	case "support":
		if nested {
			return name
		}
	}
	return ""
}

// copyIdentity replaces the identity headers with the bearer token's sub and
// roles claims, read WITHOUT verifying the token: whatever a token claims is
// believed. A request without a readable token carries no identity.
func copyIdentity(r *http.Request) {
	for _, name := range identityHeaders {
		r.Header.Del(name)
	}
	value, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		return
	}
	token, err := jwt.ParseSigned(value, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return
	}
	var claims struct {
		Subject string   `json:"sub"`
		Roles   []string `json:"roles"`
	}
	if token.UnsafeClaimsWithoutVerification(&claims) != nil || claims.Subject == "" {
		return
	}
	r.Header.Set("X-Gateway-Subject", claims.Subject)
	r.Header.Set("X-Gateway-Roles", strings.Join(claims.Roles, ","))
}

// upStandalone is demo up -standalone: it builds the services, Accounts and
// the shop from this repository, makes a new standalone directory in home
// and runs everything until interrupted. APIWard is neither needed nor built.
func upStandalone(home string, stdin bool) error {
	if err := checkPortsFree(); err != nil {
		return err
	}
	fetch, err := fetchRepository()
	if err != nil {
		return err
	}
	bin, shop := filepath.Join(home, "bin"), filepath.Join(home, "web", "demo")
	services, accounts, err := buildServices(fetch, bin)
	if err != nil {
		return err
	}
	if err := buildWebsite(filepath.Join(fetch, "client"), shop); err != nil {
		return err
	}
	dir := filepath.Join(home, "standalone")
	if err := prepareStandalone(dir); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if stdin {
		go func() {
			io.Copy(io.Discard, stdinLines)
			stop()
		}()
	}
	return runStandalone(ctx, dir, os.DirFS(shop), services, accounts)
}

// prepareStandalone makes a new private directory for one standalone run,
// replacing the previous run's: the service secret and a new signing key.
func prepareStandalone(dir string) error {
	// Only a folder this mode made, which holds its secret and signing
	// settings, is replaced; anything else in its place is left alone.
	if _, err := os.Stat(dir); err == nil {
		for _, name := range []string{secretFile, signingFile} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("not replacing %s: it is not a standalone demonstration folder", dir)
			}
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := privateDirectory(dir); err != nil {
		return fmt.Errorf("creating the standalone directory: %w", err)
	}
	files, err := serviceFiles(dir)
	if err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}
	return nil
}
