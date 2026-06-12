// Package proxy is the reusable client/server plumbing on top of the Kelp
// core+mux: a local SOCKS5 server (TCP CONNECT + UDP ASSOCIATE) on the client
// side, and per-stream TCP/UDP relaying on the server side. It is shared by the
// standalone binaries and the embedded TakoMesh client.
package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ca110us/kelp/core"
	"github.com/ca110us/kelp/mux"
)

// udpTarget is the mux SYN target marking a stream as a UDP relay (TCP targets
// are always "host:port" with a colon, so this never collides).
const udpTarget = "udp"

// --- Client carrier ---------------------------------------------------------

// Carrier lazily establishes and reuses one muxed Kelp carrier to the server.
type Carrier struct {
	Server    string
	PSK       []byte
	ServerPub []byte
	SNI       string
	Insecure  bool

	mu  sync.Mutex
	mux *mux.Mux
}

// NewCarrier builds a Carrier from string config (decoding the base64 pubkey).
func NewCarrier(server, psk, pubkeyB64, sni, domain string) (*Carrier, error) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubkeyB64))
	if err != nil || len(pub) != 32 {
		return nil, fmt.Errorf("bad server pubkey")
	}
	c := &Carrier{Server: server, PSK: core.PSKFromString(psk), ServerPub: pub, SNI: sni, Insecure: true}
	if domain != "" {
		c.SNI, c.Insecure = domain, false
	}
	return c, nil
}

func (c *Carrier) open(target string) (*mux.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mux != nil {
		if st, err := c.mux.Open(target); err == nil {
			return st, nil
		}
		c.mux = nil
	}
	m, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.mux = m
	return c.mux.Open(target)
}

func (c *Carrier) dial() (*mux.Mux, error) {
	opening, keys, err := core.PrepareClient(c.PSK, c.ServerPub)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", c.Server, &tls.Config{
		InsecureSkipVerify: c.Insecure,
		ServerName:         c.SNI,
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
	return mux.New(sess, true), nil
}

// --- Client SOCKS5 server ---------------------------------------------------

// Serve accepts SOCKS5 connections on ln and tunnels them through the carrier.
func Serve(ln net.Listener, c *Carrier) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(conn, c)
	}
}

func handleSOCKS(c net.Conn, carrier *Carrier) {
	defer c.Close()
	cmd, target, err := socks5Begin(c)
	if err != nil {
		return
	}
	switch cmd {
	case 0x01: // CONNECT (TCP)
		socks5Reply(c, 0x00, net.IPv4(0, 0, 0, 0), 0)
		st, err := carrier.open(target)
		if err != nil {
			log.Printf("kelp: open %s: %v", target, err)
			return
		}
		defer st.Close()
		pipe(c, st)
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(c, carrier)
	default:
		socks5Reply(c, 0x07, net.IPv4(0, 0, 0, 0), 0)
	}
}

func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// --- Server side relay ------------------------------------------------------

// ServeStream relays one inbound mux stream to its target: a TCP dial, or a UDP
// relay if the target is the UDP sentinel.
func ServeStream(st *mux.Stream) {
	defer st.Close()
	if st.Target() == udpTarget {
		serveUDP(st)
		return
	}
	out, err := net.DialTimeout("tcp", st.Target(), 10*time.Second)
	if err != nil {
		log.Printf("kelp: dial %s: %v", st.Target(), err)
		return
	}
	defer out.Close()
	pipe(st, out)
}

// serveUDP is a NAT-style relay: one ephemeral UDP socket sends to all targets
// for this association and receives their replies, framed back with the source.
func serveUDP(st *mux.Stream) {
	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer uc.Close()

	// Stream -> world.
	go func() {
		for {
			addr, data, err := readDatagram(st)
			if err != nil {
				uc.Close()
				return
			}
			dst, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				continue
			}
			uc.SetWriteDeadline(time.Now().Add(30 * time.Second))
			uc.WriteToUDP(data, dst)
		}
	}()

	// World -> stream.
	buf := make([]byte, 64*1024)
	for {
		uc.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if err := writeDatagram(st, src.String(), buf[:n]); err != nil {
			return
		}
	}
}

// --- UDP framing inside a stream --------------------------------------------
//
//	[2-byte frame len][1 atyp][addr][2 port][payload]
//
// frame len covers atyp..payload. atyp: 1=IPv4(4) 3=domain(1+n) 4=IPv6(16).

func writeDatagram(w io.Writer, addr string, payload []byte) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)
	var ab []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ab = append([]byte{0x01}, v4...)
		} else {
			ab = append([]byte{0x04}, ip.To16()...)
		}
	} else {
		ab = append([]byte{0x03, byte(len(host))}, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	body := append(append(ab, pb[:]...), payload...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(body)))
	if _, err := w.Write(lb[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readDatagram(r io.Reader) (addr string, payload []byte, err error) {
	var lb [2]byte
	if _, err = io.ReadFull(r, lb[:]); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err = io.ReadFull(r, body); err != nil {
		return
	}
	host, rest, err := parseAddr(body)
	if err != nil {
		return "", nil, err
	}
	if len(rest) < 2 {
		return "", nil, fmt.Errorf("short datagram")
	}
	port := binary.BigEndian.Uint16(rest[:2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), rest[2:], nil
}

// parseAddr decodes a SOCKS5-style address prefix and returns host + remainder.
func parseAddr(b []byte) (host string, rest []byte, err error) {
	if len(b) < 1 {
		return "", nil, fmt.Errorf("empty addr")
	}
	switch b[0] {
	case 0x01:
		if len(b) < 5 {
			return "", nil, fmt.Errorf("short v4")
		}
		return net.IP(b[1:5]).String(), b[5:], nil
	case 0x04:
		if len(b) < 17 {
			return "", nil, fmt.Errorf("short v6")
		}
		return net.IP(b[1:17]).String(), b[17:], nil
	case 0x03:
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return "", nil, fmt.Errorf("short domain")
		}
		n := int(b[1])
		return string(b[2 : 2+n]), b[2+n:], nil
	}
	return "", nil, fmt.Errorf("bad atyp %d", b[0])
}
