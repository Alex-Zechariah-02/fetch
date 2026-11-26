// Service security settings pinned at their bounds: Argon2id memory cost,
// caller key lengths, internal client response-header timeout, receipt
// Authorization flag, signing key cache and kid checks, and single-file TLS
// certificate and client CA reloads.

package services

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestServiceSecuritySettings(t *testing.T) {
	t.Run("argon2_cost", func(t *testing.T) {
		salt := []byte("0123456789abcdef")
		want := argon2.IDKey([]byte("FetchDemo2026!"), salt, 2, 64*1024, 2, 32)
		if !bytes.Equal(passwordKey("FetchDemo2026!", salt), want) {
			t.Fatal("passwordKey does not match Argon2id 64 MiB cost")
		}
	})

	t.Run("caller_key_length", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			size int
			ok   bool
		}{
			{"31 bytes", 31, false},
			{"32 bytes", 32, true},
			{"4096 bytes", 4096, true},
			{"4097 bytes", 4097, false},
		} {
			_, err := New(Config{
				Name:      "reports",
				Keys:      map[string][]byte{"reports": bytes.Repeat([]byte("k"), tc.size)},
				OrdersURL: unusedOrders,
			})
			if (err == nil) != tc.ok {
				t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
			}
		}
	})

	t.Run("internal_client_timeout", func(t *testing.T) {
		client, err := newServiceClient("http://127.0.0.1:9101", testSecret)
		if err != nil {
			t.Fatal(err)
		}
		defer client.close()
		tr, ok := client.http.Transport.(*http.Transport)
		if !ok || tr.ResponseHeaderTimeout != 2*time.Second {
			t.Fatalf("ResponseHeaderTimeout = %v, want 2s", tr.ResponseHeaderTimeout)
		}
	})

	t.Run("receipt_authorization_flag", func(t *testing.T) {
		s := newService(t, Config{Name: "inventory", Keys: testKeys("inventory")})
		r1 := httptest.NewRequest(http.MethodGet, "/inventory/categories", nil)
		s.ServeHTTP(httptest.NewRecorder(), r1)
		r2 := httptest.NewRequest(http.MethodGet, "/inventory/categories", nil)
		r2.Header.Set("Authorization", "Bearer tok")
		s.ServeHTTP(httptest.NewRecorder(), r2)
		if len(s.recent.receipts) != 2 {
			t.Fatalf("got %d receipts, want 2", len(s.recent.receipts))
		}
		if s.recent.receipts[0].Authorization {
			t.Fatal("request without Authorization recorded Authorization=true")
		}
		if !s.recent.receipts[1].Authorization {
			t.Fatal("request with Authorization recorded Authorization=false")
		}
	})

	t.Run("signing_cache_and_kid", func(t *testing.T) {
		_, _, settings := accountService(t)
		var cache signerCache
		first, err := cache.current(settings)
		if err != nil {
			t.Fatal(err)
		}
		second, err := cache.current(settings)
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatal("unchanged signing settings and key reloaded instead of reusing cache")
		}
		for _, tc := range []struct {
			kid string
			ok  bool
		}{
			{"", false},
			{"A", true},
			{"Z", true},
			{"@", false},
			{strings.Repeat("a", 64), true},
			{strings.Repeat("a", 65), false},
		} {
			if got := validKid(tc.kid); got != tc.ok {
				t.Errorf("validKid(%q) = %v, want %v", tc.kid, got, tc.ok)
			}
		}
	})
}

func TestIngressSingleFileReloads(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt.pem")
	keyPath := filepath.Join(dir, "server.key.pem")
	caPath := filepath.Join(dir, "client-ca.pem")

	newCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	issueFor := func(caCert *x509.Certificate, caKey, leafKey *ecdsa.PrivateKey, cn string, serial int64, usage x509.ExtKeyUsage) []byte {
		now := time.Now().UTC()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyPEM := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	ca1Cert, ca1Key, ca1PEM := newCA("ca1")
	ca2Cert, ca2Key, ca2PEM := newCA("ca2")
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cli1Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cli2Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	srvCert1 := issueFor(ca1Cert, ca1Key, srvKey, "srv-v1", 2, x509.ExtKeyUsageServerAuth)
	srvCert2 := issueFor(ca1Cert, ca1Key, srvKey, "srv-v2", 3, x509.ExtKeyUsageServerAuth)
	cli1Cert := issueFor(ca1Cert, ca1Key, cli1Key, "cli1", 4, x509.ExtKeyUsageClientAuth)
	cli2Cert := issueFor(ca2Cert, ca2Key, cli2Key, "cli2", 5, x509.ExtKeyUsageClientAuth)

	for p, b := range map[string][]byte{certPath: srvCert1, keyPath: keyPEM(srvKey), caPath: ca1PEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := Listen("127.0.0.1:0", Ingress{Certificate: certPath, Key: keyPath, ClientCA: caPath})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if err := conn.(*tls.Conn).Handshake(); err == nil {
					_, _ = conn.Write([]byte("ok"))
				}
			}(c)
		}
	}()

	dial := func(cliCert, cliKey []byte) (string, error) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca1PEM)
		cert, err := tls.X509KeyPair(cliCert, cliKey)
		if err != nil {
			return "", err
		}
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
		})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		var reply [2]byte
		if _, err := conn.Read(reply[:]); err != nil {
			return "", err
		}
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
	}

	// Replace only the server certificate (key and CA unchanged).
	if cn, err := dial(cli1Cert, keyPEM(cli1Key)); err != nil || cn != "srv-v1" {
		t.Fatalf("initial: cn=%q err=%v", cn, err)
	}
	if err := os.WriteFile(certPath, srvCert2, 0o600); err != nil {
		t.Fatal(err)
	}
	t1 := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, t1, t1)
	time.Sleep(1100 * time.Millisecond)
	if cn, err := dial(cli1Cert, keyPEM(cli1Key)); err != nil || cn != "srv-v2" {
		t.Fatalf("cert-only reload: cn=%q err=%v, want srv-v2", cn, err)
	}

	// Replace only the client CA (server cert and key unchanged).
	if err := os.WriteFile(caPath, ca2PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t2 := time.Now().Add(4 * time.Second)
	_ = os.Chtimes(caPath, t2, t2)
	time.Sleep(1100 * time.Millisecond)
	if cn, err := dial(cli2Cert, keyPEM(cli2Key)); err != nil || cn != "srv-v2" {
		t.Fatalf("ca-only reload with new client: cn=%q err=%v, want srv-v2", cn, err)
	}
	if _, err := dial(cli1Cert, keyPEM(cli1Key)); err == nil {
		t.Fatal("ca-only reload still accepted old client cert")
	}
}
