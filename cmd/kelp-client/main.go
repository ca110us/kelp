// kelp-client: exposes a local SOCKS5 proxy (TCP CONNECT + UDP ASSOCIATE);
// all connections are multiplexed over a single Kelp carrier to the server.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/ca110us/kelp/core"
	"github.com/ca110us/kelp/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	server := flag.String("server", "", "kelp-server address host:port (required)")
	pskStr := flag.String("psk", "", "shared secret (required, same as server)")
	pubKey := flag.String("pubkey", "", "server static pubkey base64 (from server log)")
	pubFile := flag.String("pubfile", "", "file with the server static pubkey (alternative to -pubkey)")
	domain := flag.String("domain", "", "server's real domain — verifies its Let's Encrypt cert (recommended)")
	sni := flag.String("sni", "cdn.example.com", "TLS SNI for a self-signed server (when -domain is empty)")
	modelFile := flag.String("model", "", "measured shaping model JSON (optional)")
	flag.Parse()
	if *server == "" || *pskStr == "" {
		log.Fatalf("-server and -psk are required")
	}
	if *modelFile != "" {
		m, err := core.LoadModel(*modelFile)
		if err != nil {
			log.Fatalf("load model: %v", err)
		}
		core.SetModel(m)
		log.Printf("loaded shaping model %s (sizes %v)", *modelFile, m.Sizes)
	}

	pkB64 := *pubKey
	if pkB64 == "" {
		if *pubFile == "" {
			log.Fatalf("provide the server pubkey via -pubkey or -pubfile")
		}
		data, err := os.ReadFile(*pubFile)
		if err != nil {
			log.Fatalf("read pubfile: %v", err)
		}
		pkB64 = strings.TrimSpace(string(data))
	}

	carrier, err := proxy.NewCarrier(*server, *pskStr, pkB64, *sni, *domain)
	if err != nil {
		log.Fatalf("%v", err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("kelp-client SOCKS5 on %s -> %s (muxed, TCP+UDP)", *listen, *server)
	proxy.Serve(ln, carrier)
}
