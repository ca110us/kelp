package core

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Session is a framed AEAD record stream over an arbitrary carrier
// io.ReadWriteCloser (in the MVP, an HTTP/2 CONNECT stream). It implements
// io.ReadWriteCloser so traffic can be io.Copy'd through it.
type Session struct {
	carrier io.ReadWriteCloser

	sendMu  sync.Mutex
	send    cipher.AEAD
	sendCtr uint64

	recvMu  sync.Mutex
	recv    cipher.AEAD
	recvCtr uint64
	readBuf []byte // leftover decrypted payload not yet consumed by Read

	// send-path shaping state (single writer: io.Copy)
	model       *Model
	modelState  int
	hsRemaining int
	totalReal   uint64
	totalPad    uint64
}

func newSession(carrier io.ReadWriteCloser, sendKey, recvKey []byte, sendCtr, recvCtr uint64) (*Session, error) {
	s, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	m := activeModel
	return &Session{
		carrier: carrier, send: s, recv: r, sendCtr: sendCtr, recvCtr: recvCtr,
		model: m, hsRemaining: len(m.HS),
	}, nil
}

// writeRecord seals one plaintext chunk into a length-prefixed AEAD record.
func (s *Session) writeRecord(p []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	ct := s.send.Seal(nil, nonce(s.sendCtr), p, nil)
	s.sendCtr++
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
	if _, err := s.carrier.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.carrier.Write(ct)
	return err
}

// readRecord reads and opens one length-prefixed AEAD record.
func (s *Session) readRecord() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(s.carrier, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	ct := make([]byte, n)
	if _, err := io.ReadFull(s.carrier, ct); err != nil {
		return nil, err
	}
	pt, err := s.recv.Open(nil, nonce(s.recvCtr), ct, nil)
	if err != nil {
		return nil, wantErr("decrypt record", err)
	}
	s.recvCtr++
	return pt, nil
}

// Read returns the de-framed real payload, skipping any pure-pad cover records.
func (s *Session) Read(p []byte) (int, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	for len(s.readBuf) == 0 {
		pt, err := s.readRecord()
		if err != nil {
			return 0, err
		}
		if len(pt) < realLenSize {
			return 0, wantErr("short frame", io.ErrUnexpectedEOF)
		}
		rl := int(binary.BigEndian.Uint16(pt[:realLenSize]))
		if rl > len(pt)-realLenSize {
			return 0, wantErr("bad frame length", io.ErrUnexpectedEOF)
		}
		s.readBuf = pt[realLenSize : realLenSize+rl] // rl==0 → loop (cover record)
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

// Write re-chunks the byte stream into records whose on-wire sizes follow the
// shaping model, smears the first records into a benign-opening template, and
// pads within the budget. Single writer (io.Copy) — no extra locking.
func (s *Session) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		ctSize, handshake := s.nextSize()
		if ctSize < minCTSize {
			ctSize = minCTSize
		}
		capacity := ctSize - tagSize - realLenSize
		take := len(p)
		if take > capacity {
			take = capacity
		}
		pad := capacity - take
		if pad > 0 && !handshake {
			// shrink instead of pad once the padding budget is exhausted
			if float64(s.totalPad+uint64(pad)) > s.model.Beta*float64(s.totalReal+uint64(take)) {
				pad = 0
			}
		}
		plain := make([]byte, realLenSize+take+pad)
		binary.BigEndian.PutUint16(plain[:realLenSize], uint16(take))
		copy(plain[realLenSize:], p[:take])
		if err := s.writeRecord(plain); err != nil {
			return total - len(p), err
		}
		s.totalReal += uint64(take)
		s.totalPad += uint64(pad)
		p = p[take:]
	}
	return total, nil
}

func (s *Session) Close() error { return s.carrier.Close() }

// --- Client side: Dial -------------------------------------------------------

// ClientKeys holds the per-connection directional keys produced by
// PrepareClient, to be bound to a carrier once it is ready.
type ClientKeys struct{ c2s, s2c []byte }

// kelpVersion is the first encrypted byte; it confirms key agreement without
// revealing anything. Per-stream targets travel in the mux layer, not here.
const kelpVersion = 0x00

// PrepareClient computes the 0-RTT opening as the client and returns the raw
// opening bytes (clear preamble + a first encrypted hello record) plus the
// directional keys. The caller streams the opening over the carrier *before*
// the response arrives, so the server can authenticate before deciding whether
// to carry the mux or serve a decoy.
func PrepareClient(psk, serverPub []byte) ([]byte, ClientKeys, error) {
	ePriv, ePub, err := GenerateKeypair()
	if err != nil {
		return nil, ClientKeys{}, err
	}
	clientRand := make([]byte, randLen)
	if _, err := rand.Read(clientRand); err != nil {
		return nil, ClientKeys{}, err
	}
	ident := computeIdent(psk, time.Now().Unix()/EpochSeconds)

	es, err := curve25519.X25519(ePriv, serverPub)
	if err != nil {
		return nil, ClientKeys{}, wantErr("x25519", err)
	}
	c2s, s2c := deriveKeys(es, psk, ident, clientRand)

	aead, err := chacha20poly1305.New(c2s)
	if err != nil {
		return nil, ClientKeys{}, err
	}
	firstCT := aead.Seal(nil, nonce(0), []byte{kelpVersion}, nil)

	out := make([]byte, 0, preamble+2+len(firstCT))
	out = append(out, ePub...)
	out = append(out, clientRand...)
	out = append(out, ident...)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(firstCT)))
	out = append(out, hdr[:]...)
	out = append(out, firstCT...)
	return out, ClientKeys{c2s: c2s, s2c: s2c}, nil
}

// BindClient wraps a carrier (whose write side already carried the opening)
// into a Session ready for bidirectional traffic. Send counter starts at 1
// because the opening's first record already consumed counter 0.
func BindClient(carrier io.ReadWriteCloser, k ClientKeys) (*Session, error) {
	return newSession(carrier, k.c2s, k.s2c, 1, 0)
}

// --- Server side: Accept -----------------------------------------------------

// ReplayCache rejects repeated (ident, client_rand) openings within the epoch
// window. Bounded and periodically swept.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewReplayCache() *ReplayCache { return &ReplayCache{seen: map[string]time.Time{}} }

func (c *ReplayCache) checkAndAdd(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if len(c.seen) > 100000 { // sweep
		for k, t := range c.seen {
			if now.Sub(t) > 2*EpochSeconds*time.Second {
				delete(c.seen, k)
			}
		}
	}
	if _, dup := c.seen[key]; dup {
		return false
	}
	c.seen[key] = now
	return true
}

// ErrAuth means the opening did not authenticate (unknown ident or replay).
// The caller should fall through to decoy behavior, never signal the error.
var ErrAuth = errors.New("kelp: authentication failed")

// Accept performs the server side of the 0-RTT opening. It authenticates the
// client against the single PSK (MVP) across the current and previous epoch,
// rejects replays, and returns an authenticated Session. Per-stream targets are
// handled by the mux layer above.
func Accept(carrier io.ReadWriteCloser, psk, serverPriv []byte, replay *ReplayCache) (*Session, error) {
	pre := make([]byte, preamble)
	if _, err := io.ReadFull(carrier, pre); err != nil {
		return nil, err
	}
	return AcceptWithPreamble(carrier, pre, psk, serverPriv, replay)
}

// PreambleLen is the number of clear bytes to read before routing a connection
// (Kelp tunnel vs decoy) on a shared port.
const PreambleLen = preamble

// AcceptWithPreamble is Accept when the caller already read the clear preamble
// (to peek-and-route). On ErrAuth it has consumed only the preamble, so those
// bytes can be replayed to a decoy.
func AcceptWithPreamble(carrier io.ReadWriteCloser, pre, psk, serverPriv []byte, replay *ReplayCache) (*Session, error) {
	if len(pre) != preamble {
		return nil, ErrAuth
	}
	ePub := pre[:pubLen]
	clientRand := pre[pubLen : pubLen+randLen]
	ident := pre[pubLen+randLen:]

	// Match ident against current and previous epoch.
	epoch := time.Now().Unix() / EpochSeconds
	matched := false
	for _, e := range []int64{epoch, epoch - 1} {
		if hmac.Equal(ident, computeIdent(psk, e)) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrAuth
	}
	if !replay.checkAndAdd(string(ident) + string(clientRand)) {
		return nil, ErrAuth
	}

	es, err := curve25519.X25519(serverPriv, ePub)
	if err != nil {
		return nil, ErrAuth
	}
	c2s, s2c := deriveKeys(es, psk, ident, clientRand)

	// Server receives on c2s, sends on s2c.
	sess, err := newSession(carrier, s2c, c2s, 0, 0)
	if err != nil {
		return nil, err
	}
	first, err := sess.readRecord()
	if err != nil || len(first) < 1 || first[0] != kelpVersion {
		return nil, ErrAuth
	}
	return sess, nil
}
