// Fetch API TLS certificate, key and client CA hot-reload tests.

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestCAAndPair(t *testing.T, cn string) (caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	issue := func(name string, serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kDER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kDER})
	}
	serverCertPEM, serverKeyPEM = issue(cn+"-server", 2, x509.ExtKeyUsageServerAuth)
	clientCertPEM, clientKeyPEM = issue(cn+"-client", 3, x509.ExtKeyUsageClientAuth)
	return
}

func TestIngressCertificateReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt.pem")
	keyPath := filepath.Join(dir, "server.key.pem")
	caPath := filepath.Join(dir, "client-ca.pem")

	ca1, srvCert1, srvKey1, cliCert1, cliKey1 := makeTestCAAndPair(t, "gen1")
	ca2, srvCert2, srvKey2, cliCert2, cliKey2 := makeTestCAAndPair(t, "gen2")

	writeFiles := func(cert, key, ca []byte) {
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(caPath, ca, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFiles(srvCert1, srvKey1, ca1)

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
				_ = conn.(*tls.Conn).Handshake()
			}(c)
		}
	}()

	dial := func(caPEM, cliCertPEM, cliKeyPEM []byte) (string, error) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		cert, err := tls.X509KeyPair(cliCertPEM, cliKeyPEM)
		if err != nil {
			return "", err
		}
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
	}

	if cn, err := dial(ca1, cliCert1, cliKey1); err != nil || cn != "gen1-server" {
		t.Fatalf("initial handshake: cn=%q err=%v, want gen1-server", cn, err)
	}

	writeFiles(srvCert2, srvKey2, ca2)
	future := time.Now().Add(2 * time.Second)
	for _, p := range []string{certPath, keyPath, caPath} {
		_ = os.Chtimes(p, future, future)
	}
	time.Sleep(1100 * time.Millisecond)

	if cn, err := dial(ca2, cliCert2, cliKey2); err != nil || cn != "gen2-server" {
		t.Fatalf("reloaded handshake: cn=%q err=%v, want gen2-server", cn, err)
	}
	if _, err := dial(ca1, cliCert1, cliKey1); err == nil {
		t.Fatal("old gen1 client cert still accepted after reload")
	}

	if err := os.WriteFile(certPath, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if cn, err := dial(ca2, cliCert2, cliKey2); err != nil || cn != "gen2-server" {
		t.Fatalf("gen2 lost after bad reload: cn=%q err=%v", cn, err)
	}
}

func TestListenRefusesMappedWildcard(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key, _, _ := makeTestCAAndPair(t, "wild")
	certPath := filepath.Join(dir, "srv.pem")
	keyPath := filepath.Join(dir, "srv.key")
	caPath := filepath.Join(dir, "ca.pem")
	for p, b := range map[string][]byte{certPath: cert, keyPath: key, caPath: ca} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ing := Ingress{Certificate: certPath, Key: keyPath, ClientCA: caPath}
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"} {
		ln, err := Listen(addr, ing)
		if err == nil {
			got := ln.Addr().String()
			ln.Close()
			t.Fatalf("Listen(%q) succeeded (%s), want unspecified address refused", addr, got)
		}
	}
}
