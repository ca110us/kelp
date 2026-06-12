// kelp-measure observes the real TLS application-data record-size sequence to a
// live host and emits a Kelp shaping model (JSON). TLS record lengths are
// cleartext in the 5-byte record header even though payloads are encrypted, so
// we can learn the on-wire size distribution of a real H2/TLS session without
// decrypting anything.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/ca110us/kelp/internal/core"
)

func main() {
	host := flag.String("host", "www.cloudflare.com:443", "host:port to measure")
	path := flag.String("path", "/", "HTTP path to GET (use a large resource for bulk shape)")
	out := flag.String("out", "model.json", "output model file")
	buckets := flag.Int("buckets", 5, "number of size buckets")
	flag.Parse()

	hostname, _, err := net.SplitHostPort(*host)
	if err != nil {
		log.Fatalf("host: %v", err)
	}

	raw, err := net.Dial("tcp", *host)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	obs := &observer{Conn: raw}
	conn := tls.Client(obs, &tls.Config{ServerName: hostname, NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.Handshake(); err != nil {
		log.Fatalf("handshake: %v", err)
	}

	// Generate a realistic application-data exchange.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", *path, hostname)
	conn.Write([]byte(req))
	io.Copy(io.Discard, conn) // read the whole response
	conn.Close()

	// obs.recv holds the server->client application-data record lengths in order.
	sizes := obs.recvAppData
	if len(sizes) < 20 {
		log.Fatalf("too few records observed (%d); try a larger -path", len(sizes))
	}
	log.Printf("observed %d application-data records (server->client)", len(sizes))

	model := buildModel(sizes, *buckets)
	data, _ := json.MarshalIndent(model, "", "  ")
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("wrote %s", *out)
	log.Printf("buckets (sizes): %v", model.Sizes)
	log.Printf("handshake template: %v", model.HS)
}

// observer taps the raw TCP stream and parses TLS record headers to record the
// length of each application-data (type 23) record in the server->client
// direction (the bytes we Read from the underlying conn).
type observer struct {
	net.Conn
	recvBuf     []byte
	recvAppData []int
}

func (o *observer) Read(p []byte) (int, error) {
	n, err := o.Conn.Read(p)
	if n > 0 {
		o.recvBuf = append(o.recvBuf, p[:n]...)
		o.parse()
	}
	return n, err
}

func (o *observer) parse() {
	for len(o.recvBuf) >= 5 {
		typ := o.recvBuf[0]
		length := int(o.recvBuf[3])<<8 | int(o.recvBuf[4])
		if len(o.recvBuf) < 5+length {
			break
		}
		if typ == 23 { // application_data
			o.recvAppData = append(o.recvAppData, length)
		}
		o.recvBuf = o.recvBuf[5+length:]
	}
}

// buildModel turns an observed size sequence into a Markov model: 1-D k-means
// to find representative bucket sizes, then transition counts between buckets.
func buildModel(sizes []int, k int) *core.Model {
	if k > len(sizes) {
		k = len(sizes)
	}
	centroids := kmeans1d(sizes, k)
	assign := func(s int) int {
		best, bd := 0, 1<<62
		for i, c := range centroids {
			d := (s - c) * (s - c)
			if d < bd {
				bd, best = d, i
			}
		}
		return best
	}

	// Transition counts.
	trans := make([][]float64, k)
	for i := range trans {
		trans[i] = make([]float64, k)
	}
	prev := assign(sizes[0])
	for _, s := range sizes[1:] {
		cur := assign(s)
		trans[prev][cur]++
		prev = cur
	}
	for i := range trans {
		sum := 0.0
		for _, v := range trans[i] {
			sum += v
		}
		if sum == 0 {
			for j := range trans[i] {
				trans[i][j] = 1.0 / float64(k) // unseen state: uniform
			}
			continue
		}
		for j := range trans[i] {
			trans[i][j] /= sum
		}
	}

	// Handshake template = the first few observed records (the real opening).
	hsN := 6
	if hsN > len(sizes) {
		hsN = len(sizes)
	}
	hs := append([]int{}, sizes[:hsN]...)

	return &core.Model{Sizes: centroids, Trans: trans, HS: hs, Beta: 0.10}
}

// kmeans1d returns k cluster centers over the values (a few Lloyd iterations).
func kmeans1d(vals []int, k int) []int {
	// Init centers at evenly spaced order statistics.
	sorted := append([]int{}, vals...)
	insertionSort(sorted)
	centers := make([]int, k)
	for i := range centers {
		centers[i] = sorted[(i*len(sorted))/k+len(sorted)/(2*k)]
	}
	for iter := 0; iter < 12; iter++ {
		sum := make([]int, k)
		cnt := make([]int, k)
		for _, v := range vals {
			best, bd := 0, 1<<62
			for i, c := range centers {
				d := (v - c) * (v - c)
				if d < bd {
					bd, best = d, i
				}
			}
			sum[best] += v
			cnt[best]++
		}
		for i := range centers {
			if cnt[i] > 0 {
				centers[i] = sum[i] / cnt[i]
			}
		}
	}
	insertionSort(centers)
	return centers
}

func insertionSort(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

