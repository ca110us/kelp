// kelp-tun is a self-contained global proxy for macOS: it runs the Kelp SOCKS5
// client internally and a userspace TUN (tun2socks) that routes all TCP+UDP
// through it. Requires root (creates a utun and sets routes). Restores routing
// on exit.
//
// NOTE: this manipulates system routing and must be run with sudo. It has not
// been exercised in CI; review the route setup for your environment first.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ca110us/kelp/core"
	"github.com/ca110us/kelp/proxy"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func main() {
	server := flag.String("server", "", "kelp-server host:port (required)")
	pskStr := flag.String("psk", "", "shared secret (required)")
	pubKey := flag.String("pubkey", "", "server static pubkey base64 (required)")
	domain := flag.String("domain", "", "server real domain (verifies cert)")
	sni := flag.String("sni", "cdn.example.com", "TLS SNI for self-signed server")
	socks := flag.String("socks", "127.0.0.1:1080", "internal SOCKS5 address")
	tunName := flag.String("tun", "utun123", "utun device name")
	tunAddr := flag.String("tun-addr", "198.18.0.1", "address assigned to the tun device")
	modelFile := flag.String("model", "", "measured shaping model JSON (optional)")
	flag.Parse()
	if *server == "" || *pskStr == "" || *pubKey == "" {
		log.Fatalf("-server, -psk and -pubkey are required")
	}
	if os.Geteuid() != 0 {
		log.Fatalf("must run as root (sudo): creates a utun and edits routes")
	}
	if *modelFile != "" {
		if m, err := core.LoadModel(*modelFile); err == nil {
			core.SetModel(m)
		}
	}

	serverIP, err := resolveHostIP(*server)
	if err != nil {
		log.Fatalf("resolve server: %v", err)
	}
	gw, iface, err := defaultRoute()
	if err != nil {
		log.Fatalf("detect default route: %v", err)
	}
	log.Printf("default gateway %s via %s; server %s pinned to it", gw, iface, serverIP)

	// 1. Kelp SOCKS5 client.
	carrier, err := proxy.NewCarrier(*server, *pskStr, *pubKey, *sni, *domain)
	if err != nil {
		log.Fatalf("%v", err)
	}
	ln, err := net.Listen("tcp", *socks)
	if err != nil {
		log.Fatalf("socks listen: %v", err)
	}
	go proxy.Serve(ln, carrier)

	// 2. TUN -> SOCKS5. Bind tun2socks's own dialer to the physical interface so
	// proxied flows leave via it, not back through the tun.
	engine.Insert(&engine.Key{
		Device:    "tun://" + *tunName,
		Proxy:     "socks5://" + *socks,
		Interface: iface,
		LogLevel:  "warning",
	})
	engine.Start()
	defer engine.Stop()

	// 3. Routing: tun address, host route for the server via the real gateway
	// (avoids a loop), and a split default route through the tun.
	run("ifconfig", *tunName, *tunAddr, *tunAddr, "up")
	run("route", "-n", "add", "-host", serverIP, gw)
	run("route", "-n", "add", "-net", "0.0.0.0/1", *tunAddr)
	run("route", "-n", "add", "-net", "128.0.0.0/1", *tunAddr)
	log.Printf("global proxy active via %s — all TCP+UDP tunneled through Kelp", *tunName)

	cleanup := func() {
		run("route", "-n", "delete", "-net", "0.0.0.0/1", *tunAddr)
		run("route", "-n", "delete", "-net", "128.0.0.0/1", *tunAddr)
		run("route", "-n", "delete", "-host", serverIP, gw)
	}
	defer cleanup()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down, restoring routes")
}

func run(args ...string) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		log.Printf("%s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func resolveHostIP(hostport string) (string, error) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if net.ParseIP(host) != nil {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("no IP for %s", host)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return ips[0].String(), nil
}

// defaultRoute parses `route -n get default` for the gateway and interface.
func defaultRoute() (gw, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			switch f[0] {
			case "gateway:":
				gw = f[1]
			case "interface:":
				iface = f[1]
			}
		}
	}
	if gw == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default route")
	}
	return gw, iface, nil
}
