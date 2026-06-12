// kelp-client: MVP Kelp client. Exposes a local SOCKS5 proxy; all accepted
// connections are multiplexed over a single Kelp carrier (a real TLS connection
// to the front, carrying the 0-RTT-authenticated, shaped, muxed session).
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/ca110us/kelp/internal/core"
	"github.com/ca110us/kelp/internal/mux"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	server := flag.String("server", "127.0.0.1:8443", "kelp-server address")
	pskStr := flag.String("psk", "dev", "shared PSK passphrase (MVP)")
	pubFile := flag.String("pubfile", "/tmp/kelp_server.pub", "file with the server static pubkey (base64)")
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

	pubB64, err := os.ReadFile(*pubFile)
	if err != nil {
		log.Fatalf("read pubfile: %v", err)
	}
	serverPub, err := base64.StdEncoding.DecodeString(string(pubB64))
	if err != nil {
		log.Fatalf("decode pubkey: %v", err)
	}

	mgr := &carrier{
		server:    *server,
		psk:       core.PSKFromString(*pskStr),
		serverPub: serverPub,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("kelp-client SOCKS5 on %s -> %s (muxed)", *listen, *server)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c, mgr)
	}
}

// carrier lazily establishes and reuses one muxed Kelp carrier, redialing when
// the current one dies.
type carrier struct {
	server    string
	psk       []byte
	serverPub []byte

	mu  sync.Mutex
	mux *mux.Mux
}

func (c *carrier) open(target string) (*mux.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mux != nil {
		if st, err := c.mux.Open(target); err == nil {
			return st, nil
		}
		c.mux = nil // dead carrier; redial below
	}
	m, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.mux = m
	return c.mux.Open(target)
}

func (c *carrier) dial() (*mux.Mux, error) {
	opening, keys, err := core.PrepareClient(c.psk, c.serverPub)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", c.server, &tls.Config{
		InsecureSkipVerify: true, // MVP: self-signed front
		ServerName:         "cdn.example.com",
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(opening); err != nil {
		conn.Close()
		return nil, err
	}
	sess, err := core.BindClient(conn, keys)
	if err != nil {
		conn.Close()
		return nil, err
	}
	log.Printf("carrier established")
	return mux.New(sess, true), nil
}

func handle(c net.Conn, mgr *carrier) {
	defer c.Close()
	target, err := socks5Handshake(c)
	if err != nil {
		return
	}
	st, err := mgr.open(target)
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	defer st.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(st, c); done <- struct{}{} }()
	go func() { io.Copy(c, st); done <- struct{}{} }()
	<-done
}

// socks5Handshake performs a minimal SOCKS5 no-auth handshake and returns the
// requested target as "host:port".
func socks5Handshake(c net.Conn) (string, error) {
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}
	nm := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nm]); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	if buf[1] != 0x01 {
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported cmd %d", buf[1])
	}
	var host string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return "", err
		}
		host = string(buf[:l])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", fmt.Errorf("bad atyp")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}
