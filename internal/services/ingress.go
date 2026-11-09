// The listener of a Fetch API, Accounts or the shop: plain HTTP on a loopback
// address, or TLS that admits only clients holding a certificate issued by one
// CA (the gateway's), which any other address requires.

package services

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
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

// config is the server TLS configuration of a complete Ingress. The gateway
// speaks HTTP/1.1 to its upstreams, so no other protocol is offered.
func (i Ingress) config() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(i.Certificate, i.Key)
	if err != nil {
		return nil, fmt.Errorf("the API certificate: %w", err)
	}
	data, err := os.ReadFile(i.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("the client CA: %w", err)
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no CA certificate", i.ClientCA)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		NextProtos:   []string{"http/1.1"},
	}, nil
}
