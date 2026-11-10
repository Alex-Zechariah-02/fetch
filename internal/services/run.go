// The lifecycle of a Fetch service: its API, control and loopback internal
// listeners, served until the context ends, then shut down together.

package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// internal serves only the /internal/ endpoints, each still requiring the
// service key; every other path is not found.
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

// internalCallees are the services another one calls under /internal/ (Orders
// calls Inventory, Reports calls Orders), always over loopback.
var internalCallees = []string{"inventory", "orders"}

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
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	api, err := Listen(listen, ingress)
	if err != nil {
		return err
	}
	listeners = append(listeners, api)
	handlers := []http.Handler{s.api(), s.Control(secret)}
	addresses := []string{control}
	if ingress != (Ingress{}) && slices.Contains(internalCallees, s.name) {
		port := api.Addr().(*net.TCPAddr).Port
		handlers = append(handlers, s.internal())
		addresses = append(addresses, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	for _, address := range addresses {
		listener, err := Listen(address, Ingress{})
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}
	var servers []*http.Server
	for _, handler := range handlers {
		servers = append(servers, &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second})
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
