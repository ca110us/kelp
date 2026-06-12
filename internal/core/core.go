// Package core implements the stable Kelp cryptographic core: the 0-RTT
// authenticated opening (X25519 + PSK + HKDF) and a framed AEAD record stream.
// This is the part of the protocol that must never change at runtime.
package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// EpochSeconds is the coarse time window used to derive the rotating
	// connection identifier. The server accepts the current and previous epoch.
	EpochSeconds = 600

	identLen  = 16
	randLen   = 16
	pubLen    = 32
	preamble  = pubLen + randLen + identLen // bytes sent in the clear at open
	maxRecord = 16384                       // max plaintext per AEAD record
)

// GenerateKeypair returns an X25519 private/public keypair.
func GenerateKeypair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

// PubFromPriv derives the X25519 public key for a private key (used to restore
// a persisted server keypair).
func PubFromPriv(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

func hkdfKey(secret, salt []byte, info string, n int) []byte {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, n)
	io.ReadFull(r, out)
	return out
}

// computeIdent derives the rotating, random-looking connection identifier for a
// PSK at a given epoch: HMAC-SHA256(PSK, "kelp-id" || epoch)[:16].
func computeIdent(psk []byte, epoch int64) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("kelp-id"))
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(epoch))
	m.Write(eb[:])
	return m.Sum(nil)[:identLen]
}

// deriveKeys turns the shared secret material into directional AEAD keys.
func deriveKeys(es, psk, ident, clientRand []byte) (c2s, s2c []byte) {
	salt := append(append([]byte{}, ident...), clientRand...)
	secret := append(append([]byte{}, es...), psk...)
	sessionKey := hkdfKey(secret, salt, "kelp-v0 session", 32)
	c2s = hkdfKey(sessionKey, salt, "kelp-v0 c2s", chacha20poly1305.KeySize)
	s2c = hkdfKey(sessionKey, salt, "kelp-v0 s2c", chacha20poly1305.KeySize)
	return c2s, s2c
}

func nonce(counter uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[chacha20poly1305.NonceSize-8:], counter)
	return n[:]
}

func wantErr(what string, err error) error {
	return fmt.Errorf("kelp: %s: %w", what, err)
}

// PSKFromString derives a 32-byte PSK from a passphrase. MVP convenience for
// sharing a key between client and server; production keys come from the
// control plane.
func PSKFromString(s string) []byte {
	h := sha256.Sum256([]byte("kelp-psk:" + s))
	return h[:]
}

