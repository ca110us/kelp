package core

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// The shaping engine re-chunks the outbound byte stream so the on-wire record
// size sequence follows a target model instead of mirroring the inner traffic
// (which is what TLS-in-TLS detection keys on). Data-phase record plaintext is
// framed as:
//
//	[2-byte real_len][real payload (real_len)][padding ...]
//
// so the receiver can strip padding. A real_len of 0 marks a cover record.
const (
	tagSize     = chacha20poly1305.Overhead // 16
	realLenSize = 2
	minCTSize   = realLenSize + tagSize + 1 // smallest useful record
)

// Model is the (currently size-only) target for the shaper. In production it is
// a measured low-order Markov model shipped by the control plane; here it is a
// plausible HTTP/2-over-TLS default.
type Model struct {
	Sizes []int       `json:"sizes"` // candidate on-wire ciphertext-record sizes
	Trans [][]float64 `json:"trans"` // row-stochastic transitions over Sizes indices
	HS    []int       `json:"hs"`    // handshake-smearing template (first data-phase records)
	Beta  float64     `json:"beta"`  // padding budget as a fraction of real bytes
}

// LoadModel reads a measured shaping model from JSON (produced by kelp-measure).
func LoadModel(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := &Model{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, err
	}
	if len(m.Sizes) == 0 || len(m.Trans) != len(m.Sizes) {
		return nil, errors.New("kelp: invalid model")
	}
	if m.Beta <= 0 {
		m.Beta = 0.10
	}
	return m, nil
}

// activeModel is the shaping model new sessions use. SetModel swaps it (e.g. to
// a measured model); defaults to the synthetic DefaultModel.
var activeModel = DefaultModel()

// SetModel installs the shaping model used by subsequently created sessions.
func SetModel(m *Model) { activeModel = m }

// DefaultModel approximates the record-size shape of a real H2/TLS session: a
// benign opening (small control frames growing into MTU-sized DATA), then a
// steady mix dominated by large records with occasional small ones.
func DefaultModel() *Model {
	return &Model{
		// 0:MTU 1:coalesced 2:large 3:medium 4:small
		Sizes: []int{1350, 8192, 4096, 600, 120},
		Trans: [][]float64{
			{0.55, 0.20, 0.15, 0.06, 0.04}, // from MTU
			{0.30, 0.45, 0.18, 0.05, 0.02}, // from coalesced
			{0.40, 0.25, 0.25, 0.07, 0.03}, // from large
			{0.45, 0.10, 0.15, 0.20, 0.10}, // from medium
			{0.50, 0.05, 0.10, 0.20, 0.15}, // from small
		},
		HS:   []int{90, 60, 320, 1350, 1350, 1350},
		Beta: 0.10,
	}
}

// step samples the next size index and its size given the current state.
func (m *Model) step(state int) (int, int) {
	row := m.Trans[state]
	r := rand.Float64()
	c := 0.0
	for i, p := range row {
		c += p
		if r <= c {
			return i, m.Sizes[i]
		}
	}
	last := len(m.Sizes) - 1
	return last, m.Sizes[last]
}

// nextSize returns the next target ciphertext-record size and whether it comes
// from the handshake-smearing window (which pads freely, ignoring the budget).
func (s *Session) nextSize() (size int, handshake bool) {
	if s.hsRemaining > 0 {
		idx := len(s.model.HS) - s.hsRemaining
		s.hsRemaining--
		return s.model.HS[idx], true
	}
	s.modelState, size = s.model.step(s.modelState)
	return size, false
}
