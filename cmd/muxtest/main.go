package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ca110us/kelp/mux"
)

func main() {
	a, b := net.Pipe()
	cm := mux.New(a, true)  // client
	sm := mux.New(b, false) // server

	// server: echo each stream
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			go func(s *mux.Stream) { io.Copy(s, s); s.Close() }(st)
		}
	}()

	// client: 2 concurrent streams, each writes 8KB and reads it back
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			st, err := cm.Open(fmt.Sprintf("echo-%d", id))
			if err != nil {
				fmt.Printf("stream %d open err: %v\n", id, err)
				return
			}
			payload := bytes.Repeat([]byte{byte('A' + id)}, 8192)
			go func() { st.Write(payload); /* keep open */ }()
			got := make([]byte, 0, 8192)
			buf := make([]byte, 4096)
			for len(got) < 8192 {
				n, err := st.Read(buf)
				if n > 0 {
					got = append(got, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			if bytes.Equal(got, payload) {
				fmt.Printf("stream %d: OK echoed %d bytes\n", id, len(got))
			} else {
				fmt.Printf("stream %d: MISMATCH got %d/%d\n", id, len(got), len(payload))
			}
			st.Close()
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		fmt.Println("ALL DONE")
	case <-time.After(5 * time.Second):
		fmt.Println("DEADLOCK (timeout)")
	}
}
