# Kelp

Kelp is a censorship-circumvention transport protocol (codename **Kelp**, part
of the Toko ecosystem). The design philosophy and full spec live in
[`DESIGN.md`](./DESIGN.md). This repository is the working MVP implementation.

> An octopus hides in a kelp forest: Kelp does not try to look like *nothing*,
> it rides inside a real protocol and evolves its appearance over time.

## What works today (MVP)

A full end-to-end stack, verified with concurrent traffic and a 5 MB transfer:

- **0-RTT authenticated opening** — X25519 + per-user PSK + HKDF, ChaCha20-Poly1305.
  The client speaks first with data, so there is no second handshake burst.
- **Anti-replay** — rotating `ident = HMAC(PSK, epoch)` (random-looking) with a
  replay cache.
- **Shaping engine** — re-chunks the byte stream so on-wire record sizes follow a
  Markov model, smears the first records into a benign-opening template, and
  pads within a budget. Decouples outer record boundaries from inner ones
  (the structural defense against TLS-in-TLS detection).
- **Measured models** — `kelp-measure` learns a real CDN's TLS record-size
  distribution and emits a model the engine loads, instead of a hand-written
  one ("measured, not mimicked").
- **Multiplexing** — many logical streams over one carrier; concurrent streams
  blend new inner handshakes into ongoing traffic.
- **Probe resistance / decoy** — single port. The server peeks the first bytes:
  a valid Kelp opening becomes a tunnel; anything else is reverse-proxied to a
  real decoy origin, so the server looks like a benign website.

### Carrier note

The MVP carrier is a **raw TLS connection**. The DESIGN's primary carriers
(real HTTP/2 CONNECT, HTTP/3 / MASQUE) give *structural* TLS-in-TLS immunity but
require a hand-rolled h2/h3 framer — Go's `net/http2` high-level transport
deadlocks on concurrent bidirectional muxed traffic over a single CONNECT
stream. That carrier is a separate, dedicated piece of work; the mux and shaping
are carrier-agnostic and proven correct independently.

## Layout

```
internal/core/      stable crypto core: 0-RTT opening, AEAD record stream, anti-replay
internal/core/shaping.go   Markov shaping engine + model load/save
internal/mux/       stream multiplexing over one carrier
cmd/kelp-server/    exit/front: TLS, peek-and-route (tunnel vs decoy), proxy
cmd/kelp-client/    local SOCKS5 -> muxed Kelp carrier
cmd/kelp-measure/   learn a shaping model from a real CDN's TLS records
cmd/muxtest/        isolated mux concurrency test (manual)
```

## Build

```sh
go build ./...
```

## Run (quick local test)

```sh
# server (persists its keypair; prints its pubkey + a ready client command)
go run ./cmd/kelp-server -listen 127.0.0.1:8443 -psk 'a-strong-secret' -key /tmp/k.key

# client (copy -pubkey from the server log)
go run ./cmd/kelp-client -server 127.0.0.1:8443 -psk 'a-strong-secret' -pubkey '<PUBKEY>'

curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

A direct browser/probe to the server (no Kelp) is reverse-proxied to the decoy
origin and sees a normal website.

## Deploy for real use

See [`DEPLOY.md`](./DEPLOY.md) — run the server on a VPS (port 443, systemd),
connect from your machine, and use the local SOCKS5 proxy. Prebuilt Linux/macOS
binaries can be produced with:

```sh
CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags="-s -w" -o kelp-server-linux-amd64 ./cmd/kelp-server
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o kelp-client-mac        ./cmd/kelp-client
```

## Status / non-goals

This is an MVP to validate the protocol's headline claims, not production code.
Notable gaps (tracked in `DESIGN.md`): the H2/H3 carriers, signed declarative
profiles + control plane, the sentinel network, per-stream flow control in the
mux, timing (gap) shaping, and a real (non-self-signed / REALITY-style) front.
Kelp provides circumvention, **not anonymity** — use Tor for that.
