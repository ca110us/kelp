# Deploying Kelp

A practical guide to run a Kelp server on a VPS and use it from your machine.
This is an MVP: good enough for personal use, not hardened for hostile scale.

## 0. Pick a shared secret

Generate one strong secret used by BOTH ends (treat it like a password):

```sh
openssl rand -base64 24      # e.g. 9Xf2...  — keep it secret
```

## 1. Server (on the VPS, Linux)

Copy the right binary to the VPS (`scp dist/kelp-server-linux-amd64 user@vps:`),
then run it. Port 443 makes it look like normal HTTPS but needs privilege.

### Recommended: a real domain + automatic Let's Encrypt cert

Point a domain you control at the VPS (an `A` record), then pass `-domain`. The
server obtains and renews a real, browser-trusted cert automatically (TLS-ALPN-01
over :443), so the **TLS handshake is indistinguishable from a normal HTTPS
site** — no self-signed fingerprint, no `InsecureSkipVerify` on the client.

```sh
sudo setcap 'cap_net_bind_service=+ep' ./kelp-server-linux-amd64

./kelp-server-linux-amd64 \
  -listen 0.0.0.0:443 \
  -domain tunnel.example.com \
  -certdir /etc/kelp/certs \
  -psk 'YOUR_SHARED_SECRET' \
  -key /etc/kelp/server.key \
  -decoy https://www.cloudflare.com
```

The domain must resolve to this VPS and :443 must be reachable from the internet
when the cert is first issued. On start it prints the pubkey and client command:

```
server static pubkey: VmW7vrXDPUvZSk0rxJPMJBYhAtAMbI28IOvVldVceBw=
client: kelp-client -server tunnel.example.com:443 -psk <same-psk> -pubkey VmW7... -domain tunnel.example.com
```

### Quick test without a domain (self-signed)

```sh
./kelp-server-linux-amd64 -listen 0.0.0.0:443 -psk 'YOUR_SHARED_SECRET' \
  -key /etc/kelp/server.key -sni www.cloudflare.com -decoy https://www.cloudflare.com
```

The client must then pass `-sni www.cloudflare.com` (and trusts the self-signed
cert; fine for testing, but the self-signed cert is a fingerprint — prefer
`-domain` for real use).

The keypair is persisted to `-key`, so the pubkey stays the same across
restarts (the client never needs reconfiguring).

Open the firewall for the port (e.g. `ufw allow 443/tcp`).

### Run it as a service (systemd)

```ini
# /etc/systemd/system/kelp.service
[Unit]
Description=Kelp server
After=network.target

[Service]
ExecStart=/usr/local/bin/kelp-server -listen 0.0.0.0:443 -psk YOUR_SHARED_SECRET -key /etc/kelp/server.key -sni www.cloudflare.com -decoy https://www.cloudflare.com
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```sh
sudo mkdir -p /etc/kelp
sudo systemctl enable --now kelp
```

## 2. Client (your machine)

Use the pubkey from the server's startup log. With a real domain (recommended):

```sh
./kelp-client-darwin-arm64 \
  -server tunnel.example.com:443 \
  -psk 'YOUR_SHARED_SECRET' \
  -pubkey 'VmW7vrXDPUvZSk0rxJPMJBYhAtAMbI28IOvVldVceBw=' \
  -domain tunnel.example.com \
  -listen 127.0.0.1:1080
```

(For a self-signed server, drop `-domain` and pass `-sni <same-as-server>` instead.)

This exposes a local **SOCKS5** proxy on `127.0.0.1:1080`. Point apps at it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org   # should show the VPS IP
```

System-wide on macOS: System Settings → Network → your interface → Details →
Proxies → SOCKS, host `127.0.0.1`, port `1080`. In browsers, set a SOCKS5 proxy
with "remote DNS" enabled.

## 2b. Global TUN proxy (all apps, TCP + UDP)

For a true system-wide tunnel (every app, including UDP/DNS) without per-app
proxy settings, use `kelp-tun`. It runs the Kelp client internally plus a
userspace TUN (tun2socks) and routes everything through it.

```sh
sudo ./kelp-tun \
  -server tunnel.example.com:443 \
  -psk 'YOUR_SHARED_SECRET' \
  -pubkey 'VmW7...' \
  -domain tunnel.example.com
```

It needs **root** (creates a `utun` device and edits the routing table). It:
- pins a host route for the server IP to your real gateway (so the tunnel's own
  connection doesn't loop), and
- installs a split default route (`0/1` + `128/1`) through the tun.

On Ctrl-C / SIGTERM it removes those routes. If it is killed uncleanly, restore
networking with: `sudo route delete -net 0.0.0.0/1; sudo route delete -net 128.0.0.0/1`
(or just toggle Wi-Fi off/on).

> The route manipulation has not been exercised in CI — review it for your
> setup and test on a machine you can recover. A clean menu-bar-app integration
> needs a macOS NetworkExtension (paid Apple Developer account + entitlements).

## 3. Optional: realistic traffic shaping

Learn a real CDN's TLS record distribution and load it on BOTH ends with
`-model model.json`:

```sh
./kelp-measure -host www.cloudflare.com:443 -path / -out model.json
# then add -model model.json to BOTH kelp-server and kelp-client
```

## Notes & limits

- **Cert fingerprint — solved with `-domain`.** With a real domain the TLS
  handshake (SNI + a valid Let's Encrypt cert) is indistinguishable from a
  normal HTTPS site. Without `-domain` the self-signed cert is a fingerprint;
  only use that for testing.
- **TLS-in-TLS — handled by shaping.** The carrier is raw TLS, but the shaping
  engine re-chunks the encrypted record-size sequence to match a measured CDN
  distribution and smears the inner handshake, which is what TLS-in-TLS
  detectors key on. Use `-model` on both ends for the best match. (A
  structural "ride real H2/H3" carrier is an alternative in `DESIGN.md`, not a
  prerequisite for the defense.)
- A direct browser/probe to the server gets the `-decoy` site, so it looks like
  a benign reverse proxy. Point `-decoy` at a site that plausibly matches your
  domain.
- Provides circumvention, **not anonymity** — use Tor for that.
