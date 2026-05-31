# atreoAGENT

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/atreoLABS/atreoAGENT/actions/workflows/ci.yml/badge.svg)](https://github.com/atreoLABS/atreoAGENT/actions/workflows/ci.yml)

**Your home server, everywhere.**

atreoAGENT runs on your home server and pairs it with [atreoLINK](https://atreolink.com) so you and your family can reach the apps you self-host, like Jellyfin, Immich or Home Assistant, from anywhere.

## What it does

- **Encrypted tunnel.** Family members reach your apps over WireGuard, peer-to-peer.
- **Automatic port mapping.** UPnP, NAT-PMP and PCP (IPv4 and IPv6) open the path for direct connections, so there's no manual port forwarding to set up.
- **Per-member app access.** Give one family member Jellyfin and Immich, give another only Home Assistant. The agent enforces it at the proxy.
- **Auto TLS.** Every server gets a free atreoLINK subdomain with a Let's Encrypt certificate, obtained and renewed automatically. Custom domains are supported too.
- **End-to-end encrypted notifications.** Server-side alerts such as a doorbell ring, a backup completing, a new photo, a password reset or a sharing invite become sealed-box-encrypted push notifications addressed to specific family members. atreoLINK relays the ciphertext and only the recipient can decrypt it.
- **SMTP gateway** *(optional)*. Self-hosted apps that send email alerts can route them through the agent as encrypted push notifications, with no external mail server needed.
- **Family invites with cryptographic identity pinning.** Once a family member accepts an invite, the agent verifies every later message they send against the identity key they pinned at pair time.

atreoLINK never sees your traffic. It coordinates pairing, relays signed control messages, and stores opaque encrypted notification ciphertexts. The agent and clients (mobile, TV, browser) pin each other's identity keys at pair time and verify everything against them.

## Quick start

```yaml
# docker-compose.yml
services:
  atreoagent:
    image: ghcr.io/atreolabs/atreoagent:latest
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    volumes:
      - ./data:/var/lib/atreoagent
      # Optional: mount the Docker socket (read-only) to use container names
      # as app targets, e.g. http://jellyfin:8096, without exposing ports.
      # - /var/run/docker.sock:/var/run/docker.sock:ro
```

```bash
docker compose up -d
docker logs -f atreoagent
```

The agent prints a pairing URL on first run. Visit it to approve the pairing from your atreoLINK account, and the agent does the rest: WireGuard, port mapping, TLS, proxy and notifications.

Full installation guide, configuration reference, troubleshooting and the security architecture: **[docs.atreolink.com](https://docs.atreolink.com)**.

## SMTP gateway

The agent ships an optional SMTP-to-push gateway on port `2525` (set `smtp.enabled: true`). Point a self-hosted app's email-alert settings at the agent and every message becomes an end-to-end-encrypted push notification, routed to the right family member by `RCPT TO`. Connections authenticate with SMTP AUTH PLAIN/LOGIN using the notify API key as the password, and STARTTLS is available on the same port with `smtp.tls_enabled: true`.

Full configuration reference: **[docs.atreolink.com](https://docs.atreolink.com)**.

## Requirements

- Linux host with the WireGuard kernel module (built in on 5.6+).
- Docker, with the `NET_ADMIN` capability and `/dev/net/tun`.
- An [atreoLINK](https://atreolink.com) account.

## Contributing

Bug reports, feature requests and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR. For security issues, see [SECURITY.md](SECURITY.md) and do not open public issues for vulnerabilities.

## License

Copyright © 2026 Atreo Labs Ltd. Licensed under the [Apache License 2.0](LICENSE).
