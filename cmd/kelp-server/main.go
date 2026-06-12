// kelp-server: MVP Kelp exit/front. Terminates real TLS on a single port and
// peeks the first bytes to route: a valid Kelp 0-RTT opening becomes a
// multiplexed tunnel; anything else (browsers, probers) is reverse-proxied to a
// real decoy origin, so the server is indistinguishable from a benign site.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ca110us/kelp/core"
	"github.com/ca110us/kelp/mux"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	addr := flag.String("listen", "0.0.0.0:443", "TLS listen address")
	pskStr := flag.String("psk", "", "shared secret (required); use a long random string")
	keyFile := flag.String("key", "kelp_server.key", "file to persist the server static keypair")
	domain := flag.String("domain", "", "real domain for an automatic Let's Encrypt cert (recommended)")
	certDir := flag.String("certdir", "kelp-certs", "ACME certificate cache directory")
	sni := flag.String("sni", "cdn.example.com", "self-signed cert CN (only when -domain is empty)")
	decoy := flag.String("decoy", "https://example.com", "decoy origin for non-Kelp traffic")
	modelFile := flag.String("model", "", "measured shaping model JSON (optional)")
	flag.Parse()
	if *pskStr == "" {
		log.Fatalf("-psk is required (a long random shared secret)")
	}
	if *modelFile != "" {
		m, err := core.LoadModel(*modelFile)
		if err != nil {
			log.Fatalf("load model: %v", err)
		}
		core.SetModel(m)
		log.Printf("loaded shaping model %s (sizes %v)", *modelFile, m.Sizes)
	}

	decoyURL, err := url.Parse(*decoy)
	if err != nil {
		log.Fatalf("decoy url: %v", err)
	}

	priv, pub, err := loadOrCreateKey(*keyFile)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	psk := core.PSKFromString(*pskStr)
	replay := core.NewReplayCache()

	var tlsCfg *tls.Config
	if *domain != "" {
		// Real, browser-trusted cert via Let's Encrypt (TLS-ALPN-01); the TLS
		// handshake becomes indistinguishable from a normal HTTPS site. Must be
		// reachable on :443 from the internet for issuance.
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(*certDir),
		}
		tlsCfg = m.TLSConfig()
		tlsCfg.NextProtos = append([]string{"http/1.1"}, tlsCfg.NextProtos...) // keep acme-tls/1
	} else {
		cert, err := selfSignedCert(*sni)
		if err != nil {
			log.Fatalf("cert: %v", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		}
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("kelp-server listening on %s", *addr)
	log.Printf("server static pubkey: %s", pubB64)
	if *domain != "" {
		log.Printf("client: kelp-client -server %s:%s -psk <same-psk> -pubkey %s -domain %s",
			*domain, portOf(*addr), pubB64, *domain)
	} else {
		log.Printf("client: kelp-client -server <this-host>:%s -psk <same-psk> -pubkey %s -sni %s",
			portOf(*addr), pubB64, *sni)
	}

	s := &server{psk: psk, priv: priv, replay: replay, decoy: decoyURL, tlsCfg: tlsCfg}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(c)
	}
}

type server struct {
	psk    []byte
	priv   []byte
	replay *core.ReplayCache
	decoy  *url.URL
	tlsCfg *tls.Config
}

func (s *server) handle(raw net.Conn) {
	conn := tls.Server(raw, s.tlsCfg)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return
	}
	if conn.ConnectionState().NegotiatedProtocol == "acme-tls/1" {
		conn.Close() // Let's Encrypt TLS-ALPN-01 challenge, handled by autocert
		return
	}

	// Peek the clear preamble to decide tunnel vs decoy.
	pre := make([]byte, core.PreambleLen)
	if _, err := io.ReadFull(conn, pre); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // clear; tunnels are long-lived

	sess, err := core.AcceptWithPreamble(conn, pre, s.psk, s.priv, s.replay)
	if err != nil {
		// Not a valid Kelp client → behave like a real website.
		s.serveDecoy(conn, pre)
		return
	}
	defer sess.Close()

	mx := mux.New(sess, false)
	defer mx.Close()
	for {
		st, err := mx.Accept()
		if err != nil {
			return
		}
		go serveStream(st)
	}
}

func serveStream(st *mux.Stream) {
	defer st.Close()
	out, err := net.DialTimeout("tcp", st.Target(), 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", st.Target(), err)
		return
	}
	defer out.Close()
	log.Printf("stream -> %s", st.Target())
	done := make(chan struct{}, 2)
	go func() { io.Copy(out, st); done <- struct{}{} }()
	go func() { io.Copy(st, out); done <- struct{}{} }()
	<-done
}

var decoyClient = &http.Client{
	Transport: &http.Transport{},
	Timeout:   15 * time.Second,
}

// serveDecoy reverse-proxies the (already TLS-decrypted) HTTP/1.1 request to the
// decoy origin. The peeked preamble bytes are replayed first so the request is
// intact. Behaviorally identical to a benign reverse-proxying website.
func (s *server) serveDecoy(conn net.Conn, pre []byte) {
	defer conn.Close()
	br := bufio.NewReader(&prefixConn{Conn: conn, pre: pre})
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = s.decoy.Host
	req.Host = s.decoy.Host
	req.RequestURI = ""
	resp, err := decoyClient.Do(req)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}

// prefixConn replays already-read bytes before the underlying connection.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// loadOrCreateKey persists the server's X25519 static keypair so the public key
// (which clients pin) stays stable across restarts.
func loadOrCreateKey(path string) (priv, pub []byte, err error) {
	if data, e := os.ReadFile(path); e == nil {
		if p, e2 := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); e2 == nil && len(p) == 32 {
			pub, err = core.PubFromPriv(p)
			return p, pub, err
		}
	}
	priv, pub, err = core.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	if e := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); e != nil {
		return nil, nil, e
	}
	return priv, pub, nil
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}

func selfSignedCert(cn string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
