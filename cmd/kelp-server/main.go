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
	"time"

	"github.com/ca110us/kelp/internal/core"
	"github.com/ca110us/kelp/internal/mux"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8443", "TLS listen address")
	pskStr := flag.String("psk", "dev", "shared PSK passphrase (MVP)")
	pubFile := flag.String("pubfile", "/tmp/kelp_server.pub", "where to write the server static pubkey")
	decoy := flag.String("decoy", "https://example.com", "decoy origin for non-Kelp traffic")
	modelFile := flag.String("model", "", "measured shaping model JSON (optional)")
	flag.Parse()
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

	priv, pub, err := core.GenerateKeypair()
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(*pubFile, []byte(pubB64), 0o644); err != nil {
		log.Fatalf("write pubfile: %v", err)
	}
	psk := core.PSKFromString(*pskStr)
	replay := core.NewReplayCache()

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"}, // probers speak HTTP/1.1 → decoy
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("kelp-server listening on %s", *addr)
	log.Printf("server static pubkey: %s", pubB64)

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

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cdn.example.com"},
		DNSNames:     []string{"cdn.example.com"},
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
