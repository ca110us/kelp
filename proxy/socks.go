package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// socks5Begin runs the SOCKS5 greeting + request, returning the command and,
// for CONNECT, the target "host:port".
func socks5Begin(c net.Conn) (cmd byte, target string, err error) {
	buf := make([]byte, 262)
	if _, err = io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return 0, "", fmt.Errorf("not socks5")
	}
	nm := int(buf[1])
	if _, err = io.ReadFull(c, buf[:nm]); err != nil {
		return
	}
	if _, err = c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	if _, err = io.ReadFull(c, buf[:4]); err != nil { // VER CMD RSV ATYP
		return
	}
	cmd = buf[1]
	host, err := readSocksHost(c, buf[3], buf)
	if err != nil {
		return
	}
	if _, err = io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	return cmd, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readSocksHost(c net.Conn, atyp byte, buf []byte) (string, error) {
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		return net.IP(buf[:4]).String(), nil
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return "", err
		}
		return string(buf[:l]), nil
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		return net.IP(buf[:16]).String(), nil
	}
	return "", fmt.Errorf("bad atyp")
}

// socks5Reply writes a SOCKS5 reply with the given code and bound address/port.
func socks5Reply(c net.Conn, rep byte, bnd net.IP, port int) {
	out := []byte{0x05, rep, 0x00}
	if v4 := bnd.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else {
		out = append(out, 0x04)
		out = append(out, bnd.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	out = append(out, pb[:]...)
	c.Write(out)
}

// handleUDPAssociate sets up a UDP relay: a local UDP socket the app sends to,
// bridged to a Kelp "udp" stream. The TCP control connection stays open for the
// association's lifetime.
func handleUDPAssociate(ctrl net.Conn, carrier *Carrier) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		socks5Reply(ctrl, 0x01, net.IPv4(0, 0, 0, 0), 0)
		return
	}
	defer uc.Close()
	local := uc.LocalAddr().(*net.UDPAddr)
	socks5Reply(ctrl, 0x00, net.IPv4(127, 0, 0, 1), local.Port)

	st, err := carrier.open(udpTarget)
	if err != nil {
		return
	}
	defer st.Close()

	var appAddr *net.UDPAddr // where the app sends from (reply destination)

	// app -> stream
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				st.Close()
				return
			}
			appAddr = src
			// SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP ADDR PORT DATA
			host, rest, perr := parseAddr(buf[3:n])
			if perr != nil || len(rest) < 2 {
				continue
			}
			port := binary.BigEndian.Uint16(rest[:2])
			target := net.JoinHostPort(host, strconv.Itoa(int(port)))
			if writeDatagram(st, target, rest[2:]) != nil {
				return
			}
		}
	}()

	// stream -> app
	go func() {
		for {
			addr, data, err := readDatagram(st)
			if err != nil {
				uc.Close()
				return
			}
			if appAddr == nil {
				continue
			}
			// Wrap in a SOCKS5 UDP reply header.
			hdr := buildSocksUDPHeader(addr)
			uc.WriteToUDP(append(hdr, data...), appAddr)
		}
	}()

	// Block until the TCP control connection closes (association ends).
	io.Copy(io.Discard, ctrl)
}

func buildSocksUDPHeader(addr string) []byte {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	out := []byte{0, 0, 0} // RSV RSV FRAG
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 0x01)
			out = append(out, v4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	return append(out, pb[:]...)
}
