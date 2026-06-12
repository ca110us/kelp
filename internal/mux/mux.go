// Package mux multiplexes many logical streams over one Kelp carrier session.
// Concurrent streams blend new inner handshakes into ongoing traffic, and one
// carrier amortizes the handshake/opening cost across all streams.
//
// Wire frame (carried inside the shaped, encrypted Kelp session):
//
//	[1-byte type][4-byte stream id][2-byte length][payload (length)]
//
// Only the client opens streams; SYN carries the target "host:port".
package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

type frameType byte

const (
	synFrame  frameType = 1 // open a stream; payload = target
	dataFrame frameType = 2 // stream data
	finFrame  frameType = 3 // half/close

	headerLen   = 1 + 4 + 2
	maxPayload  = 65535
)

// Mux multiplexes streams over a single carrier.
type Mux struct {
	conn io.ReadWriteCloser

	wmu sync.Mutex // serializes writes to conn

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	closed  bool

	accept chan *Stream // server side: inbound streams
}

// New wraps a carrier. isClient selects odd stream-id allocation; the server
// only accepts. The read loop starts immediately.
func New(conn io.ReadWriteCloser, isClient bool) *Mux {
	m := &Mux{
		conn:    conn,
		streams: map[uint32]*Stream{},
		accept:  make(chan *Stream, 16),
	}
	if isClient {
		m.nextID = 1 // odd ids
	}
	go m.readLoop()
	return m
}

// Open creates a new stream to target (client side).
func (m *Mux) Open(target string) (*Stream, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("mux: closed")
	}
	id := m.nextID
	m.nextID += 2
	st := newStream(m, id, target)
	m.streams[id] = st
	m.mu.Unlock()

	if err := m.writeFrame(synFrame, id, []byte(target)); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept returns the next inbound stream (server side).
func (m *Mux) Accept() (*Stream, error) {
	st, ok := <-m.accept
	if !ok {
		return nil, io.EOF
	}
	return st, nil
}

func (m *Mux) Close() error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.accept)
	}
	m.mu.Unlock()
	return m.conn.Close()
}

func (m *Mux) writeFrame(t frameType, id uint32, payload []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	var hdr [headerLen]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], id)
	binary.BigEndian.PutUint16(hdr[5:], uint16(len(payload)))
	if _, err := m.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := m.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mux) readLoop() {
	defer m.Close()
	var hdr [headerLen]byte
	for {
		if _, err := io.ReadFull(m.conn, hdr[:]); err != nil {
			return
		}
		t := frameType(hdr[0])
		id := binary.BigEndian.Uint32(hdr[1:])
		n := binary.BigEndian.Uint16(hdr[5:])
		var payload []byte
		if n > 0 {
			payload = make([]byte, n)
			if _, err := io.ReadFull(m.conn, payload); err != nil {
				return
			}
		}
		switch t {
		case synFrame:
			st := newStream(m, id, string(payload))
			m.mu.Lock()
			m.streams[id] = st
			closed := m.closed
			m.mu.Unlock()
			if !closed {
				m.accept <- st
			}
		case dataFrame:
			m.mu.Lock()
			st := m.streams[id]
			m.mu.Unlock()
			if st != nil {
				st.push(payload)
			}
		case finFrame:
			m.mu.Lock()
			st := m.streams[id]
			delete(m.streams, id)
			m.mu.Unlock()
			if st != nil {
				st.closeInbound()
			}
		}
	}
}

// Stream is one logical connection, an io.ReadWriteCloser. Inbound data is
// queued without ever blocking the mux read loop (push only appends), which
// avoids head-of-line deadlock across streams. The queue is unbounded in the
// MVP; production adds per-stream receive windows.
type Stream struct {
	m      *Mux
	id     uint32
	target string

	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	inBuf  []byte
	inDone bool // FIN received

	closeOnce sync.Once
}

func newStream(m *Mux, id uint32, target string) *Stream {
	s := &Stream{m: m, id: id, target: target}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Target is the requested destination (set on SYN).
func (s *Stream) Target() string { return s.target }

func (s *Stream) push(p []byte) {
	s.mu.Lock()
	if !s.inDone {
		s.queue = append(s.queue, p)
		s.cond.Signal()
	}
	s.mu.Unlock()
}

func (s *Stream) closeInbound() {
	s.mu.Lock()
	s.inDone = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.inBuf) == 0 {
		if len(s.queue) > 0 {
			s.inBuf = s.queue[0]
			s.queue = s.queue[1:]
			break
		}
		if s.inDone {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	n := copy(p, s.inBuf)
	s.inBuf = s.inBuf[n:]
	s.mu.Unlock()
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		if err := s.m.writeFrame(dataFrame, s.id, chunk); err != nil {
			return total - len(p), err
		}
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.m.writeFrame(finFrame, s.id, nil)
		s.m.mu.Lock()
		delete(s.m.streams, s.id)
		s.m.mu.Unlock()
	})
	return nil
}
