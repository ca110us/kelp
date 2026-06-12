# Kelp Transport Protocol — Design v0

> Codename **Kelp**. The transport layer of the Toko ecosystem.
> An octopus hides in a kelp forest: Kelp does not try to look like *nothing*,
> it rides inside a *real* protocol and continuously evolves its appearance
> under control-plane guidance.

This document is a working design spec. It is opinionated and deliberately
states what is **out of scope** as loudly as what is in scope.

---

## 1. Thesis

Most circumvention protocols lose because they put their differentiation in the
**byte format** — and a state-level adversary does not classify on byte format,
it classifies on **behavior, statistics, active probing, and nested-TLS
structure**. Kelp inverts the usual split:

- **Carry traffic inside a genuine protocol** (real HTTP/3 / MASQUE, real
  HTTP/2 CONNECT) so the fingerprintable parts (handshake shape, record-size
  distribution, congestion behavior) are *real*, not imitated. This gives
  **structural** immunity to TLS-in-TLS detection rather than statistical
  best-effort.
- **Keep the security core small, fixed, and auditable in spirit.** Crypto,
  auth, key schedule, state machine, and resource limits never change at
  runtime.
- **Make only the *appearance* dynamic**, via signed declarative profiles that
  are bounded by the kernel and delivered out-of-band by the control plane.
- **Turn the client fleet into a sentinel network.** The real moat is not the
  protocol — it is a real-time blocking map that lets us rotate appearance
  *before* a block spreads. A closed binary protects the sentinel logic and the
  measured distributions, not the wire format (which will be reverse-engineered
  regardless).

One-line positioning: **a private tunnel whose appearance self-evolves, with
TLS-in-TLS immunity as a structural side effect.**

---

## 2. Threat model

### 2.1 Adversary capabilities (assumed)

- **Passive, line-rate observation** of all traffic crossing the border, with
  per-flow feature extraction and ML classification (packet sizes, inter-packet
  timing, flow duration, byte-direction sequences, burst structure).
- **Active probing**: the adversary may connect to any IP:port it has seen and
  send arbitrary bytes to see how the server responds.
- **TLS-in-TLS / nested-handshake detection**: the adversary inspects the
  outer record-size sequence right after a TLS handshake and flags the
  "small→large→small" inner-handshake shape.
- **Fully-encrypted-traffic heuristics**: high-entropy, structureless payloads
  are themselves suspicious (post-2023 GFW behavior).
- **Volume / longevity correlation**: long-lived, high-volume flows to an
  unusual destination are flagged.
- **SNI / IP / port blocking** and **QUIC throttling or wholesale UDP/443
  degradation**.
- **Replay**: the adversary may capture and replay a connection opening.

### 2.2 Adversary limits (assumed NOT capable)

- Cannot break TLS 1.3 / QUIC confidentiality or the inner AEAD.
- Cannot compromise the control-plane signing key.
- Cannot perform global, persistent, per-flow timing correlation across the
  whole internet (we defend against regional/border-local correlation, not a
  global passive adversary à la traffic-confirmation in Tor's threat model).
- Does not have a backdoor in the chosen CDN/front.

### 2.3 Explicit non-goals

- **Not** anonymity. Kelp hides *that you are tunneling* and *where to*, not
  *who you are* from the exit. Use Tor if you need anonymity.
- **Not** resistance to a global passive adversary doing end-to-end timing
  correlation.
- **Not** a general "run arbitrary protocol code" engine. Profiles are
  declarative and bounded (see §9).

---

## 3. Layering

```
┌──────────────────────────────────────────────────────────────┐
│  Application traffic (the user's own TCP/UDP, often HTTPS)     │
├──────────────────────────────────────────────────────────────┤
│  Kelp mux: logical streams, flow control, keep-busy           │   dynamic params
├──────────────────────────────────────────────────────────────┤
│  Kelp core: 0-RTT auth, key schedule, AEAD, anti-replay       │   STABLE / fixed
├──────────────────────────────────────────────────────────────┤
│  Shaping engine: re-frames the byte stream to a target        │   dynamic model
│  size/timing model; smears inner handshakes; stealth budget   │
├──────────────────────────────────────────────────────────────┤
│  Carrier: REAL HTTP/3 (MASQUE/CONNECT-UDP) ─ primary          │   selected by profile
│           REAL HTTP/2 CONNECT over TLS/TCP  ─ fallback         │
│           raw shaped TLS record stream      ─ last resort      │
├──────────────────────────────────────────────────────────────┤
│  Real TLS 1.3 / QUIC to a real front (CDN or REALITY-style)    │
└──────────────────────────────────────────────────────────────┘
```

Three change-cadences, mapped to the layers:

| Layer            | Who owns it      | Change cadence            |
|------------------|------------------|---------------------------|
| Core (crypto/auth/state) | binary    | release only, audited     |
| Mux / limits     | binary, profile-tuned within bounds | release; bounds fixed |
| Shaping model + carrier choice + fronts | **profile** | control-plane push, no release |

---

## 4. Carrier (the structural defense)

### 4.1 Primary: real HTTP/3 over QUIC (MASQUE / extended CONNECT)

- Establish a genuine QUIC connection (TLS 1.3 handshake inside QUIC) to a
  real H3-capable front.
- Open a tunnel with **Extended CONNECT** (RFC 9220) or **CONNECT-UDP / IP**
  (RFC 9298 / MASQUE) on an H3 stream.
- The user's traffic — *including their own inner HTTPS* — rides as the body of
  that stream, i.e. as **QUIC STREAM frames**. There is no
  inner-TLS-record → outer-TLS-record mapping; the inner records become opaque
  bytes re-chunked by QUIC's own framing and congestion control.

Why this is the strongest option:

- **TLS-in-TLS detection is largely inapplicable.** The published attacks key
  on the *outer TLS record-length sequence over TCP*. QUIC encrypts packet
  payloads, hides stream boundaries, ACKs and flow-control inside protected
  packets; the observable is UDP packets whose lengths we can pad to a target
  distribution. The "handshake-inside-data" signal evaporates because there is
  no cleartext record framing to leak it.
- **Entropy heuristics pass for free** — the bytes on the wire are a real
  QUIC/TLS stream, whose entropy profile is the carrier's, not raw random.
- **Performance**: we inherit QUIC loss recovery and (optionally) aggressive
  congestion control on lossy links — the Hysteria-class speed benefit, but
  while looking like real H3 to a CDN.

Cost / risk: some borders throttle or drop UDP/443 wholesale; MASQUE support at
CDNs is still maturing. Hence the fallback.

### 4.2 Fallback: real HTTP/2 CONNECT over TLS/TCP

- A genuine HTTP/2 connection to the front; tunnel via `CONNECT` (RFC 9113);
  user bytes ride as **H2 DATA frames**.
- H2's own framing re-chunks the inner TLS records into DATA frames whose size
  distribution is H2's, not the inner TLS's — this is the NaiveProxy property,
  re-implemented under our control.
- Here the outer carrier is TLS-over-TCP, so record lengths *are* observable —
  the **shaping engine (§7) becomes load-bearing** to keep the DATA-frame /
  record sequence distribution-matched and handshake-free.

### 4.3 Last resort: raw shaped record stream

- When even H2 CONNECT is unavailable (no usable front), fall to a raw AEAD
  stream over TLS, with the shaping engine forced to high stealth. Lowest
  throughput, highest stealth. Used only to bootstrap a fresh profile.

### 4.4 Probe resistance at the front

The front (our edge, or a REALITY-style borrow of a real server's handshake)
**must be indistinguishable from a benign server to anyone without a valid auth
token**:

- On any connection whose first authenticated token does not resolve to an
  active user (or replays one), the edge behaves *exactly* like the cover
  identity: for REALITY-style, complete the real TLS handshake stolen from the
  real site and reverse-proxy the request to that real site; for a real CDN
  origin, serve the decoy origin. No timing, no RST, no error differs.
- The auth token (see §6) is carried in a field that is normally random
  (QUIC Connection ID / a TLS ClientHello field), so its presence is not itself
  a signal.

---

## 5. Cryptographic core (STABLE — never profile-driven)

Built from standard primitives; no novel crypto.

- **KEX**: X25519. Server has a long-term static key `S` (public `S_pub`
  shipped in the profile, pinned). Client generates ephemeral `e` per
  connection.
- **PSK**: each user has a 32-byte `PSK_user` issued by the control plane.
- **AEAD**: ChaCha20-Poly1305 (default) or AES-256-GCM (if HW-accelerated and
  selected at *build* time, not by profile).
- **KDF**: HKDF-SHA256.
- **Hash**: SHA-256.

### 5.1 0-RTT authenticated opening (no second handshake burst)

The opening must (a) authenticate the user, (b) establish a forward-secret
session key, (c) carry initial data, (d) add **no distinct handshake-shaped
exchange**, and (e) be indistinguishable from random without the PSK.

```
epoch       = floor(unix_time / EPOCH_SECONDS)        // coarse, e.g. 600s
ident       = HMAC-SHA256(PSK_user, "kelp-id" || epoch)[:16]   // looks random
e           = X25519 ephemeral keypair
es          = X25519(e.priv, S_pub)                   // forward secret term
client_rand = 16 random bytes
salt        = ident || client_rand
session_key = HKDF(secret = es || PSK_user, salt = salt, info = "kelp-v0")[:32]

opening_record (client → server), all carried inside the first carrier frame,
shaped by §7 so it is just "the first DATA":
    e.pub (32) || client_rand (16) || ident (16) ||
    AEAD(session_key, nonce=0, plaintext = first_payload, ad = e.pub||ident)
```

- Server keeps, for the current and previous epoch, a map
  `ident → user` for all active users (cheap O(1) lookup; recomputed each
  epoch). Unknown `ident` ⇒ decoy behavior (§4.4).
- **Forward secrecy**: `es` uses ephemeral `e`; compromise of `PSK_user` later
  does not reveal past session keys (it reveals `ident`s, not `es`).
- **No round trip, no handshake shape**: the client speaks first with data; the
  server's first response is already application data. There is no
  small→large→small pattern to detect.

### 5.2 Anti-replay

- Server caches seen `(epoch, ident, client_rand)` tuples within the epoch
  validity window (current + previous epoch). A replay hits the cache ⇒ treated
  as an unauthenticated probe ⇒ decoy behavior. Bounded memory: the window is
  short and per-user rate-limited.

### 5.3 Rekey

- Session keys rekey by sequence-number-driven HKDF ratchet every `N` records
  or `T` seconds (whichever first), preventing nonce exhaustion and bounding the
  damage of a key leak. Ratchet is in the core, fixed.

---

## 6. Authentication & access (STABLE)

- One `PSK_user` per user (or per device, for binding). Issued, rotated, and
  revoked by the control plane.
- Revocation: the control plane stops publishing the user's `ident` set to
  edges; within one epoch the user can no longer authenticate.
- Device binding / billing / quota live **only** in the control plane and the
  edge, never in a profile. Profiles cannot grant or change access.

---

## 7. Shaping engine (the appearance, dynamic but bounded)

Goal: emit carrier frames (QUIC STREAM payloads or H2 DATA / TLS records) whose
**size and timing sequence is statistically indistinguishable from real traffic
to the chosen front**, while smearing any inner handshake and respecting a
user-set overhead budget.

### 7.1 The target model

Not an IID size histogram (too weak — classifiers look at transitions). The
profile ships a **low-order Markov model** over `(size_bucket, gap_bucket)`
tuples, learned offline from real H2/H3 traffic to that specific front:

```
M : state (last k tuples) → distribution over next (size_bucket, gap_bucket)
```

`k` is small (1–2) and bounded by the kernel. Buckets are coarse to keep `M`
small (kilobytes) and shippable.

### 7.2 The shaper loop (token-bucket over the model)

```
buffer  := []                      // outbound bytes from mux
state   := M.initial_state
budget  := β * total_real_bytes    // padding allowance, β from profile/user
loop:
    (size, gap) := M.sample(state) // next target record size & delay
    sleep(gap)                     // timing shaping (jitter)
    take := min(size, len(buffer))
    pad  := size - take
    if pad > 0:
        if budget < pad and not in_handshake_window: 
            size := take           // out of budget → shrink instead of pad
            pad  := 0
        else:
            budget -= pad
    record := frame_header(real_len = take, pad_len = pad)
            || buffer[:take] || random_pad(pad)
    emit(AEAD(session_key, seq++, record))
    buffer := buffer[take:]
    state  := M.advance(state, (size, gap))
```

- `frame_header` (inside AEAD) tells the receiver how many bytes are real vs
  pad, plus the mux stream id / control flags. Receiver de-pads trivially.
- **Shrink-not-pad** when out of budget keeps overhead within β at the cost of
  slightly worse distribution match — a deliberate, bounded trade.

### 7.3 Handshake smearing (defeats TLS-in-TLS on the TCP fallback)

For the first `HANDSHAKE_WINDOW` records after the carrier handshake completes,
the shaper ignores the natural buffer cadence and instead follows a
**benign-opening template** baked into the profile (the size/timing of a real
H2/H3 connection opening to that front: SETTINGS-shaped, WINDOW_UPDATE,
HEADERS, then growing DATA). The user's first inner-HTTPS handshake bytes are
dribbled into these template records. Result: at the outer layer there is no
isolated small→large→small inner-handshake burst — the opening looks like a
normal page load to the CDN.

### 7.4 Keep-busy and idle matching

- While streams are active but the buffer briefly empties, the shaper may emit
  **cover records** (pure pad) at a capped rate to preserve the target cadence
  (counts against budget).
- Idle periods are allowed to match the *real* idle behavior of the modeled
  traffic (browsing has idle gaps; forcing constant traffic is itself a
  fingerprint). The model includes long-gap states.

### 7.5 The stealth budget β

A single user-facing knob with a sane default and kernel-enforced bounds:

| β     | overhead | use case                                   |
|-------|----------|--------------------------------------------|
| 0.03  | ~3%      | speed-first, lower-risk regions            |
| 0.08  | ~8%      | **default**                                |
| 0.20+ | 20%+     | high-stealth, degraded/hostile regions     |

The control plane can raise the *floor* of β for a region when the sentinel
network detects increased scrutiny.

---

## 8. Multiplexing (dynamic params, bounded)

- Many logical streams over one carrier connection. Streams carry the user's
  separate TCP/UDP connections.
- Multiplexing is also a defense: concurrent streams blend new inner handshakes
  into ongoing traffic so no handshake stands out (complements §7.3).
- Per-connection limits (kernel constants, profile may lower only):
  `MAX_STREAMS`, per-stream and connection flow-control windows, max buffered
  bytes. Prevents a profile or peer from exhausting memory.

---

## 9. Profiles (dynamic, declarative, signed, bounded)

A profile is **data, not code** — a signed, versioned document. The kernel acts
like an eBPF verifier: it statically validates every field against fixed bounds
before loading; an out-of-bounds or malformed profile is rejected, never
clamped silently into danger.

### 9.1 Schema (sketch)

```jsonc
{
  "version": 42,                  // monotonic epoch, anti-rollback
  "not_before": 1730000000,
  "not_after":  1735000000,
  "min_client": "0.4.0",
  "carriers": ["h3-masque", "h2-connect"],   // ordered preference
  "fronts": [
    { "sni": "cdn.example.com", "alpn": ["h3","h2"],
      "addrs": ["…"], "server_static_pub": "base64…" }
  ],
  "shaping": {
    "markov_order": 2,
    "model": "base64(compact Markov model)",
    "handshake_template": "base64(opening template)",
    "beta_default": 0.08, "beta_floor": 0.03
  },
  "mux": { "max_streams": 128, "window": 1048576 },
  "timing": { "keepalive_s": 30, "idle_close_s": 300 },
  "sig": "ed25519(control-plane key) over canonical bytes"
}
```

### 9.2 What a profile MAY change

Carrier choice & order, front pool, shaping model & template, β default/floor,
mux/timing params **within kernel bounds**.

### 9.3 What a profile MUST NOT touch

Crypto suite, key schedule, auth model, the 0-RTT opening structure, the state
machine, resource ceilings. These are compiled in.

### 9.4 Trust & anti-downgrade

- Signed with the control-plane Ed25519 key; client pins the key at build time.
- Client refuses any profile with `version < last_seen_version` (monotonic
  anti-rollback) and any expired profile (`now > not_after`).
- Binary embeds a `floor_version`; profiles below it are rejected even on a
  fresh install (defeats "ship an ancient weak profile").
- **No in-band negotiation.** A connection never advertises "I support A/B/C".
  The client simply uses its current profile. This removes the negotiation
  fingerprint entirely (the gap we flagged earlier). Profiles arrive
  out-of-band over the control channel (§10), not at connect time.

---

## 10. Control plane & sentinel network (the real moat)

### 10.1 Sentinel telemetry (privacy-preserving)

Clients report, over the tunnel, aggregated health beacons:

```
{ profile_version, front_id, carrier, country, asn,
  outcome (ok | slow | probe_suspected | blocked),
  rtt_bucket, ts_bucket }
```

- **No IP, no per-user identifiers, no destinations.** Geo is country+ASN only.
- Counts are aggregated with differential-privacy noise before leaving the
  device; reporting is rate-limited and opt-in with a clear scope.

### 10.2 Blocking map & rotation

- The control plane aggregates beacons into a live map:
  `(front, carrier, profile) × (country, asn) → health`.
- When a cell degrades, it: marks the front/profile burned in that region,
  selects a clean `(front, carrier, shaping model)`, signs a new profile, and
  **pushes it to affected clients before the block generalizes**.
- This is the network-effect moat: more clients ⇒ earlier detection ⇒ rotate
  ahead of the censor. It cannot be cloned from the open-source wire format; it
  lives in the data and the decision logic. **This is what closed-source
  actually protects** — not the byte layout.

### 10.3 Profile delivery channel

- Profiles are delivered over the established tunnel (steady state) and, for
  cold-start or when all fronts are burned, via an out-of-band rendezvous:
  DoH-delivered bootstrap blobs, domain-fronted fetch, or a signed blob on a
  high-availability neutral host. Rendezvous endpoints are themselves rotated.

---

## 11. Degradation ladder (failure handling)

```
1. H3/MASQUE → front A                 (fast + structurally stealthy)
2. QUIC throttled/blocked → H2/CONNECT → front A   (shaping load-bearing)
3. front A burned → front B (from pool)
4. all known fronts burned → fetch emergency profile via OOB rendezvous (§10.3)
5. nothing reachable → raw shaped stream, β raised, low throughput, just enough
   to pull a fresh profile, then climb back up the ladder
```

Each rung is automatic and driven by both local signals (timeouts, RST, loss)
and pushed control-plane state.

---

## 12. Resource & safety limits (STABLE — the verifier)

| Limit                         | Why                                  |
|-------------------------------|--------------------------------------|
| max profile size              | DoS via huge model                   |
| max Markov order & model size | bounded memory/CPU for shaping       |
| max concurrent streams        | memory exhaustion                    |
| per-conn buffer cap           | memory exhaustion                    |
| max cover-traffic rate        | a bad profile can't flood/expose     |
| β ceiling                     | a profile can't make traffic absurd  |
| allowed carriers (allowlist)  | profile can't select an unsafe path  |
| CPU budget per connection     | shaping can't starve the device      |

A profile that violates any limit at validation time is **rejected**, and the
client keeps its previous good profile.

---

## 13. Security analysis notes

- **TLS-in-TLS**: structurally avoided on H3 (no outer record framing leaks);
  on the H2/TLS fallback, neutralized by §7.3 handshake smearing + §8 mux
  blending. The claim "we defeat what REALITY does not" rests on (a) preferring
  a carrier where the attack does not apply and (b) actively reshaping the one
  carrier where it does.
- **Active probing**: §4.4 decoy fallthrough + §5.1 random-looking `ident`
  give probe resistance equivalent to REALITY, with O(1) auth.
- **Entropy heuristics**: payload rides inside real TLS/QUIC; only the
  last-resort raw mode must shape ciphertext entropy, and it is used briefly.
- **Volume correlation**: mux + optional multi-front stream splitting (future,
  §15) break single-flow volume signals.
- **Replay**: §5.2.
- **The Parrot is Dead caveat**: we do **not** hand-mimic a protocol; we carry
  inside the *real* one. The shaping engine matches a *measured* distribution of
  the *actual* front, not a hand-written imitation — and degrades to "shrink,
  don't fabricate" under budget pressure rather than emitting an implausible
  shape.

---

## 14. MVP scope (phase 1)

Build the smallest thing that can prove the headline claim.

1. **Carrier**: H2/CONNECT over TLS/TCP only (defer QUIC). This is the *harder*
   carrier for TLS-in-TLS, so winning here is the strongest demo.
2. **Core**: §5 opening, ChaCha20-Poly1305, HKDF, anti-replay, rekey.
3. **Shaping**: order-1 Markov model + handshake-smearing template, single
   measured front. β fixed at 0.08.
4. **Mux**: basic streams + flow control + limits.
5. **Profile**: signed, versioned, anti-rollback; delivered out-of-band; no
   negotiation.
6. **Control plane**: minimal — issue PSKs, sign/push one profile, collect a
   coarse health beacon.

**Acceptance test for phase 1**: run a public TLS-in-TLS detector (reproduce the
record-sequence classifier from the literature) against Kelp H2/CONNECT vs.
Trojan/REALITY. Target: Kelp is not flagged where Trojan/REALITY are.

Phase 2: H3/MASQUE carrier, multi-front pool, automated rotation from the
sentinel map. Phase 3: multi-front stream splitting, adaptive β, DP telemetry.

---

## 15. Open questions / honest risks

- **MASQUE availability**: how many real CDNs we can ride for H3 today; may
  bottleneck phase 2.
- **Model staleness**: real front traffic distributions drift; the control plane
  must re-measure and re-ship shaping models periodically — operational cost.
- **Front relationships**: the whole scheme leans on having *real* fronts we can
  terminate behind. Sourcing and rotating them is the hard operational problem
  (and, honestly, a bigger moat than the protocol).
- **Shaping vs latency**: timing jitter (`gap`) adds latency; interactive use
  (gaming, RTC) may need a low-jitter profile variant.
- **Closed-source trust**: we will be asked "why should I trust an opaque
  binary with my traffic?" Plan: publish the core crypto/auth spec and possibly
  open-source the *core* while keeping the sentinel logic + measured models +
  control plane closed. The wire format is not the secret; the operations are.
- **Legal/abuse**: exit-side abuse handling, jurisdiction, and acceptable-use
  are product decisions outside this spec but must exist before launch.

---

## 16. Naming & ecosystem

- Protocol codename: **Kelp**.
- Fits the Toko / TakoMesh ocean theme (octopus hidden in kelp = traffic hidden
  in a real carrier).
- TakoMesh (the DNS router) and Kelp (the transport) are separate products that
  can share the control-plane and account system later.
