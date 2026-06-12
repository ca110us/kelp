# Kelp

A censorship-circumvention transport protocol (codename Kelp, Toko ecosystem).
Full design in `DESIGN.md`; working MVP in this repo. Go module
`github.com/ca110us/kelp`.

## Conventions

- **All documentation, code comments, identifiers, and commit messages must be
  in English.** No Chinese or other non-English in committed files.
- The `internal/core` package is the stable crypto core — keep it small,
  auditable, and never make its crypto/auth/state machine runtime-configurable.
  Dynamic behavior (shaping models, carriers, params) lives in data/profiles.

## Layout

- `internal/core/` — 0-RTT opening, AEAD record stream, anti-replay, shaping.
- `internal/mux/` — stream multiplexing over one carrier.
- `cmd/kelp-{server,client,measure}/` — exit/front, SOCKS5 client, model measurer.

## Build & test

`go build ./...`; manual concurrency check: `go run ./cmd/muxtest`.
