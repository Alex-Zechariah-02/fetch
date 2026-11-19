// The lifecycle of a Fetch service: its API, control and loopback internal
// listeners, served until the context ends, then shut down together.

package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// InternalHost is where the services call each other in plain HTTP, at
// their APIs' ports.
var InternalHost = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// internal serves only the /internal/ endpoints, each still requiring the
// caller's key; every other path is not found.
func (s *Service) internal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/internal/") {
			w.Header().Set("X-Service", s.name)
			writeJSON(w, notFound())
			return
		}
		s.ServeHTTP(w, r)
	})
}

// external serves next except the /internal/ paths, which are not found.
func (s *Service) external(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			w.Header().Set("X-Service", s.name)
			writeJSON(w, notFound())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Run serves the API on listen (see Listen for ingress) and the control
// endpoints on the loopback address control until ctx ends. When the API takes
// only the gateway's certificate, a callee of the other services also serves
// /internal/ alone on 127.0.0.1 at the API's port, where those calls arrive.
func Run(ctx context.Context, s *Service, listen, control string, secret []byte, ingress Ingress) error {
	if closer, ok := s.data.(interface{ close() }); ok {
		defer closer.close()
	}
	if s.guard != nil {
		defer s.guard.Close()
	}
	if len(secret) < 32 || len(secret) > 4096 {
		return errors.New("control secret must contain 32 to 4096 bytes")
	}
	if address, err := netip.ParseAddrPort(control); err != nil || !address.Addr().IsLoopback() {
		return errors.New("the control listener must be a literal loopback address")
	}
	// On InternalHost the services call each other in plain HTTP at the API's
	// port, which a TLS listener there would already hold.
	if address, err := netip.ParseAddrPort(listen); err == nil && address.Addr().Unmap() == InternalHost && ingress != (Ingress{}) {
		return errors.New("TLS takes another address than 127.0.0.1, where the services call each other")
	}
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	listener, err := Listen(listen, ingress)
	if err != nil {
		return err
	}
	listeners = append(listeners, listener)
	api := s.api()
	if ingress != (Ingress{}) {
		// The gateway-facing TLS listener serves no /internal/ path: those
		// calls arrive only on the loopback listener below.
		api = s.external(api)
	}
	handlers := []http.Handler{api, s.Control(secret)}
	addresses := []string{control}
	if ingress != (Ingress{}) && called(s.name) {
		port := listener.Addr().(*net.TCPAddr).Port
		handlers = append(handlers, s.internal())
		addresses = append(addresses, netip.AddrPortFrom(InternalHost, uint16(port)).String()) // #nosec G115 -- a TCP port fits 16 bits
	}
	for _, address := range addresses {
		listener, err := Listen(address, Ingress{})
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}
	// A gateway reuses its connections to the APIs and must close them
	// before the API does; without IdleTimeout, net/http would close idle
	// connections after the 10 s ReadTimeout.
	const idleTimeout = 2 * time.Minute
	// 10 s reads a maxBody body on a slow link and outlasts the slowest
	// answer, a report that waits at most 4 s for Orders; every list is paged,
	// so no answer is large. 64 KiB of headers holds a token and the
	// gateway's assertion many times over, where Go's default is 1 MiB.
	const maxHeaderBytes = 64 << 10
	var servers []*http.Server
	for _, handler := range handlers {
		servers = append(servers, &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes})
	}
	errs := make(chan error, len(servers))
	for i, server := range servers {
		go func() { errs <- server.Serve(listeners[i]) }()
	}
	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}
	// Five seconds for open connections to drain before Close ends them.
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(stop); err != nil {
			result = errors.Join(result, err, server.Close())
		}
	}
	if errors.Is(result, http.ErrServerClosed) {
		return nil
	}
	return result
}
