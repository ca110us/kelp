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
then run it. Port 443 makes it look like normal HTTPS but needs privilege:

```sh
# allow binding 443 without root (once):
sudo setcap 'cap_net_bind_service=+ep' ./kelp-server-linux-amd64

./kelp-server-linux-amd64 \
  -listen 0.0.0.0:443 \
  -psk 'YOUR_SHARED_SECRET' \
  -key /etc/kelp/server.key \
  -sni www.cloudflare.com \
  -decoy https://www.cloudflare.com
```

On start it prints the static **pubkey** and a ready-to-paste client command:

```
server static pubkey: VmW7vrXDPUvZSk0rxJPMJBYhAtAMbI28IOvVldVceBw=
client: kelp-client -server <this-host>:443 -psk <same-psk> -pubkey VmW7... -sni www.cloudflare.com
```

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

Use the pubkey and SNI from the server's startup log:

```sh
./kelp-client-darwin-arm64 \
  -server YOUR_VPS_IP:443 \
  -psk 'YOUR_SHARED_SECRET' \
  -pubkey 'VmW7vrXDPUvZSk0rxJPMJBYhAtAMbI28IOvVldVceBw=' \
  -sni www.cloudflare.com \
  -listen 127.0.0.1:1080
```

This exposes a local **SOCKS5** proxy on `127.0.0.1:1080`. Point apps at it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org   # should show the VPS IP
```

System-wide on macOS: System Settings → Network → your interface → Details →
Proxies → SOCKS, host `127.0.0.1`, port `1080`. In browsers, set a SOCKS5 proxy
with "remote DNS" enabled.

## 3. Optional: realistic traffic shaping

Learn a real CDN's TLS record distribution and load it on BOTH ends with
`-model model.json`:

```sh
./kelp-measure -host www.cloudflare.com:443 -path / -out model.json
# then add -model model.json to BOTH kelp-server and kelp-client
```

## Notes & limits

- The outer TLS cert is self-signed; the client uses `InsecureSkipVerify`. The
  real authentication is the Kelp PSK + X25519, so this is safe for the tunnel,
  but the self-signed cert is a fingerprint. A production front would use a real
  cert or borrow a real handshake (REALITY-style) — see `DESIGN.md`.
- The `-sni` you pick is sent in cleartext in the TLS ClientHello; choose a
  plausible domain (and ideally one your VPS could believably host).
- A direct browser/probe to the server gets the `-decoy` site, so the server
  looks like a benign reverse proxy.
- Carrier is raw TLS (the H2/H3 "looks like real HTTP" carriers are future
  work). Provides circumvention, not anonymity.
