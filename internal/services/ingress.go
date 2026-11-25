// The listener of a Fetch API, Accounts or the shop: plain HTTP on a loopback
// address, or TLS that admits only clients holding a certificate issued by one
// CA (the gateway's), which any other address requires.

package services

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Ingress names an API listener's TLS files: its certificate chain, its key
// and the CA that issued the only client certificates it admits. All empty
// means plain HTTP, which only a loopback address may serve.
type Ingress struct {
	Certificate, Key, ClientCA string
}

// Listen opens address, one interface's literal IP address and port, for an
// API. Without TLS files only a loopback address is accepted. With all three,
// every connection must complete a TLS 1.2 or later handshake that presents a
// client certificate issued by ClientCA; nothing relaxes that requirement.
func Listen(address string, ingress Ingress) (net.Listener, error) {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || parsed.Addr().IsUnspecified() {
		return nil, fmt.Errorf("%q: an API listens on one interface's literal IP address and a port", address)
	}
	given := 0
	for _, file := range []string{ingress.Certificate, ingress.Key, ingress.ClientCA} {
		if file != "" {
			given++
		}
	}
	switch {
	case given == 0 && parsed.Addr().IsLoopback():
		return net.Listen("tcp", address)
	case given == 0:
		return nil, fmt.Errorf("%s is not a loopback address: set -tls-cert, -tls-key and -client-ca so only the gateway can connect", address)
	case given < 3:
		return nil, errors.New("-tls-cert, -tls-key and -client-ca are set together")
	}
	config, err := ingress.config()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

type ingressState struct {
	cfg           *tls.Config
	cert, key, ca stamp
}

type ingressReloader struct {
	ingress Ingress
	held    atomic.Pointer[ingressState]
	checked atomic.Int64 // Unix ns of the last stat check
	mu      sync.Mutex
}

// config is the server TLS configuration of a complete Ingress. The gateway
// speaks HTTP/1.1 to its upstreams, so no other protocol is offered.
func (i Ingress) config() (*tls.Config, error) {
	state, err := loadIngressState(i)
	if err != nil {
		return nil, err
	}
	r := &ingressReloader{ingress: i}
	r.held.Store(state)
	r.checked.Store(time.Now().UnixNano())
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		GetConfigForClient: r.configForClient,
	}, nil
}

func (r *ingressReloader) configForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	held := r.held.Load()
	now := time.Now().UnixNano()
	if now-r.checked.Load() < int64(time.Second) {
		return held.cfg, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	held = r.held.Load()
	if now-r.checked.Load() < int64(time.Second) {
		return held.cfg, nil
	}
	r.checked.Store(now)
	cs, err1 := stampOf(r.ingress.Certificate)
	ks, err2 := stampOf(r.ingress.Key)
	cas, err3 := stampOf(r.ingress.ClientCA)
	if err := errors.Join(err1, err2, err3); err != nil {
		slog.Error("reloading API TLS files", "error", err)
		return held.cfg, nil
	}
	if cs == held.cert && ks == held.key && cas == held.ca {
		return held.cfg, nil
	}
	next, err := loadIngressState(r.ingress)
	if err != nil {
		slog.Error("reloading API TLS files", "error", err)
		return held.cfg, nil
	}
	r.held.Store(next)
	return next.cfg, nil
}

func loadIngressState(i Ingress) (*ingressState, error) {
	// The key must be the service user's alone, and the certificate and CA
	// not rewritable by another account, which could let it impersonate the
	// API or admit its own clients.
	if err := errors.Join(checkFile(i.Key, private), checkFile(i.Certificate, trusted), checkFile(i.ClientCA, trusted)); err != nil {
		return nil, err
	}
	cs, err1 := stampOf(i.Certificate)
	ks, err2 := stampOf(i.Key)
	cas, err3 := stampOf(i.ClientCA)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
	if err != nil {
		return nil, fmt.Errorf("the API certificate: %w", err)
	}
	// Read whole, so every certificate in the operator's CA file joins the pool.
	data, err := os.ReadFile(i.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("the client CA: %w", err)
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no CA certificate", i.ClientCA)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		NextProtos:   []string{"http/1.1"},
	}
	return &ingressState{cfg: cfg, cert: cs, key: ks, ca: cas}, nil
}
