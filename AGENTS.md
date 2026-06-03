# atreoAGENT: AI assistant guide

Orientation for Claude Code / Codex / Cursor / Aider. User-facing docs are at [docs.atreolink.com](https://docs.atreolink.com); the human-facing intro to the project is [README.md](README.md).

atreoAGENT is the open-source component of [atreoLINK](https://atreolink.com). When working in this repo, describe the **agent's side of the contract** (its inputs, outputs, and invariants) — do not reference the internal storage or layout of the coordination service or its client apps in code comments.

## What this is

Go daemon that runs on the user's server in Docker. Terminates WireGuard, enforces per-app ACLs, encrypts push notifications (sealed-box, addressed to the recipient member's identity pubkey), runs an SMTP-to-push gateway for self-hosted apps that emit email alerts, and maintains a WebSocket control channel to atreoLINK. Trusted by the server owner and family members (subject to ACL). The wire to atreoLINK is treated as untrusted for crypto decisions — every state-changing message is verified against a key the agent or a client (mobile / TV / browser) pinned at pair time.

## Commands

```bash
# Build
go build -o atreoagent ./cmd/atreoagent

# Run locally (needs wg kernel module, NET_ADMIN, /dev/net/tun)
sudo ./atreoagent run

# Run in docker
docker compose up -d
docker logs -f atreoagent

# Subcommands
./atreoagent pair       # interactive pair (normally run does this automatically)
./atreoagent status     # tunnel state + peer count
./atreoagent apps       # registered app list

# Test / vet / format
go test ./...
go vet ./...
gofmt -s -w .
```

## Project conventions

- **One process, many goroutines.** Up to seven long-lived: WG, UPnP, HTTPS proxy, forward-auth, notify API, tunnel client, SMTP gateway *(opt-in)*. Plus a 5-minute maintenance ticker.
- **All persistence via atomic write-and-rename.** Never truncate-in-place.
- **Config via YAML + env var overrides.** Env vars always win.
- **No DB.** Everything is flat JSON files under `/var/lib/atreoagent`.
- **Kernel WireGuard, CLI-driven.** Calls `wg` and `ip` as subprocesses; no netlink library.
- **Sentinel errors, explicit returns.**
- **No `cgo`.** The Docker image builds statically.

## Critical invariants

1. **ACL identity pubkeys pin member identity.** `handler.go` verifies client provision signatures against `member.IdentityPublic` from the ACL — never from `req.*`. This is the keystone of the identity-pinning model. Don't bypass.
2. **Owner identity pubkey is pinned at pairing time.** Lives in `admin_pin.json` (atomically written). Any atreolink-relayed message (`member:added`, `acl` mutations, etc.) attempting to change the admin entry's `IdentityKey` is rejected. Never overwrite the pin from an atreolink-relayed message.
3. **Every websocket command carries a signed envelope.** Documented exception: the join attestation (ownerSig over `invitePayload` + acceptanceSig over the invitee's pubkey) — the owner is offline at acceptance time so no fresh outer signature is available. The attestation authorises both *admission* of the new member AND the member's *initial app permissions*: the owner-signed `allowedAppIds` inside `invitePayload` becomes the member's `AllowedApps` until a fresh `member:permissions` envelope (owner online) supersedes it. The fresh envelope, when present, wins for both adding and removing apps. For all other commands, the signer is `owner` (admin actions) or a member UUID (self-scoped actions). Every signed payload struct embeds `CommandEnvelopeFields` (intent + ts); handlers go through one of two helpers in `internal/tunnel/verify.go`, both of which dispatch to `OwnerAuth` / `MemberAuth` / `OwnerOrMemberAuth` / `AttestedAuth`:
    - **`verifyCommand(msg, auth, env, expectedIntent)`** — for fresh point-in-time actions. Enforces the 120 s `ts` window via `CommandTimestampSkew`. Use this by default.
    - **`verifyAuthorization(msg, auth, env, expectedIntent)`** — sibling for **long-lived state authorisations** atreoLINK replays on every WS reconnect (currently: `app:upserted`, `device:custom-domain-set`). Skips the `ts` window because a months-old replay-on-reconnect envelope is legitimate. Replay protection comes from intent binding + device binding + only the latest envelope per authorisation being replayed + idempotent handlers.

    Expected intents are ALWAYS built from `h.deviceID`, never from `payload.DeviceID` — this defeats cross-device replay between two devices owned by the same user. Every command requires a valid envelope signature with intent + timestamp matching — including read-only queries like `wg:challenge`, `notify:apikey`, `push:devices:list`, and `push:pair:authed:init`. The agent rejects envelopes that are missing, unsigned, signed by the wrong authority, intent-mismatched, or replayed outside `CommandTimestampSkew` (120 s) where applicable.
4. **Custom-domain envelopes are intent-bound.** `device:custom-domain-set` / `device:custom-domain-cleared` carry an `intent` string fixed to `<action>-<deviceId>-<parentZone>`. Tampering with either field invalidates the signature. Verify intent before EnsureCert.
5. **Endpoint envelopes are signed and pinned.** The agent publishes `device:endpoints` (LAN candidates + DDNS) signed with its identity key. Clients verify the signature against the pubkey they pinned at pair time before trusting any candidate. The `/atreo/ping` LAN probe is the additional proof that a candidate IP actually resolves to the same agent.
6. **Push notifications are sealed-box.** Per-recipient ciphertext addressed to the member's identity pubkey. atreoLINK relays the per-recipient ciphertext — it cannot decrypt.
7. **Agent Ed25519 identity key is long-term.** Rotation = every paired client must re-pin. Treat the key file (`keys/ed25519.key`) as irreplaceable within a pairing lifecycle.
8. **25 s WS keepalive is not optional.** Below NAT/CGNAT idle timeouts. Without it, the WS looks alive while being dead.
9. **Port mismatch detection never auto-updates DDNS.** Changing the endpoint mid-session would break every active peer. Agent logs + alerts; never silently "fixes."
10. **Agent auth signature in WS URL query string** is the only practical way to auth a WS upgrade. The agent signs `{deviceId, intent, ts}` canonical-JSON with its identity key and carries `?intent=…&ts=…&sig=…`; atreoLINK verifies against the per-device public key it captured at pair time. Don't "fix" by moving to an Authorization header — WebSocket libraries don't preserve it reliably. The 120 s ts skew window is real; clocks must be NTP-synced.
11. **SMTP gateway is LAN-only and opt-in.** Plaintext by default; STARTTLS is opt-in (`smtp.tls_enabled`) on the same port via a self-signed cert persisted under the data dir (`internal/smtp/tlscert.go`) — opportunistic encryption for clients like Grafana that refuse plaintext, not server authentication. AUTH PLAIN / LOGIN is always required and the shared password is the notify HTTP API key (same secret, single rotation point — see `internal/smtp/session.go::validatePassword`). Defence in depth: AUTH password + per-IP rate limit + `trusted_networks` allowlist all apply; AUTH (and TLS) are additive, not a replacement for keeping the bind on a LAN.

## Critical files

| File | Why it's critical |
|------|-------------------|
| `cmd/atreoagent/daemon.go` | Signal handling, agent bootstrap. |
| `internal/agent/agent.go` | Goroutine orchestration, 5-min maintenance loop, port-mismatch detector. |
| `internal/tunnel/client.go` | WS control channel, 25 s keepalive, exponential reconnect backoff. |
| `internal/tunnel/handler.go` | Core dispatch table + ACL / app / member / wg-provision handlers. |
| `internal/tunnel/handler_mobile.go` | Mobile push pairing handlers (authenticated flow). |
| `internal/tunnel/handler_customdomain.go` | `device:custom-domain-set` / `cleared` envelope handlers; intent-bound. |
| `internal/tunnel/verify.go` | `VerifyEnvelope` + `requireOwner` / `requireMember`. Single point of truth for envelope checks. |
| `internal/tunnel/attestation.go` | `VerifyJoinAttestation` for the `member:added` inner-attestation path. |
| `internal/tunnel/pair_approval.go` | Decrypt + verify the owner-signed approval blob at pair time; pins admin pubkey. Also enforces the NAS-key anchor: the blob's `nasPubkey` MUST equal this agent's own identity pubkey and carry a valid owner signature over `{deviceId, nasPubkey}` — a relayer-substituted key fails pairing here visibly instead of being served to clients as the server key. |
| `internal/canonjson/` | RFC 8785-restricted canonical JSON. Must produce byte-identical output to the canonicalisers used by every client and the coordination service. |
| `internal/crypto/keys.go` | Ed25519 identity, Curve25519 WG, X25519 push key derivation, AES-GCM, libsodium sealed-box. |
| `internal/wireguard/server.go` | `wg`/`ip` CLI wrapper. |
| `internal/wireguard/ip_allocator.go` | 100.64.0.0/24 allocator, persistent. |
| `internal/firewall/firewall.go` | iptables rules confining peers to the proxy ports. Without this, `network_mode: host` exposes every 0.0.0.0-bound service on the server to every paired peer. |
| `internal/proxy/server.go` | ACL-enforcing reverse proxy, SNI dispatch across registered cert suffixes. |
| `internal/proxy/auth.go` | Forward-auth endpoint for external proxies (Caddy / Traefik / nginx). |
| `internal/certs/manager.go` + `registry.go` | Lego-driven Let's Encrypt issuance + renewal; multi-suffix registry for the operator-issued hostname AND active custom domains. |
| `internal/acl/store.go` | In-memory ACL with JSON persistence; pinned admin pubkey lives in a sibling file. |
| `internal/notify/server.go` | Local notification API; sealed-boxes per recipient before relay. |
| `internal/smtp/server.go` | LAN-side SMTP-to-push gateway (opt-in). |
| `internal/probe/server.go` | LAN-bound `/atreo/ping` signed-response endpoint for endpoint-candidate proof. |
| `internal/endpoints/service.go` | Builds + signs the `device:endpoints` envelope on every WS attach. |
| `internal/store/customdomain.go` | Persistent record of the active custom domain so a restart can re-load the cert without round-tripping atreoLINK. |

## Things to check before…

### Adding a tunnel message type
- Add handler in `internal/tunnel/handler.go` (or a topical sibling — see `handler_mobile.go`, `handler_customdomain.go` for examples).
- **Every message must envelope-verify.** Build the payload struct with `CommandEnvelopeFields` embedded, then call `h.verifyCommand(msg, auth, payload.CommandEnvelopeFields, expectedIntent)` BEFORE any state mutation or response that leaks data. Pick `auth` from `OwnerAuth`, `MemberAuth(memberID)`, `OwnerOrMemberAuth(memberID)`, or `AttestedAuth(pubkey)`. Build the intent string as `<commandName>-<binding-fields>-<unixSeconds>`.
- Add the typed payload struct alongside existing ones (`MemberLeftPayload`, `ClientRemovedPayload`, `NotifyAPIKeyPayload`, etc.).
- If the message is relayed by the coordination server, ensure the relay forwards the envelope verbatim — no re-signing.
- Responses must echo the correlation ID.

### Touching the ACL
- The ACL is built from a stream of per-mutation envelopes (`member:added`, `member:removed`, `member:permissions`, `member:status`, `member:left`, `client:removed`, `app:upserted`, `app:removed`) replayed by atreoLINK on every reconnect. There is no `acl:sync` snapshot message — atreoLINK can't synthesise one because the owner's identity privkey is offline post-pairing. The agent applies each envelope, verifies its signature against the pinned admin pubkey or the relevant member, and reconstructs the ACL from scratch on reconnect.
- `identityPublic` per member is the pin. Don't overwrite from any other source.
- Persist via atomic write after any update.
- Reconcile WG peers on every ACL change — stale peers are a security hole.

### Touching WG peer management
- `wg set` is the only path. Don't modify config files directly.
- IP allocator state must stay in sync with kernel state. Load from JSON on startup, call `wg set` for each known peer.
- Peer removal: always release the IP allocator entry AND call `wg set peer <pubkey> remove` AND delete the route.

### Touching push encryption
- Sealed-box (libsodium `crypto_box_seal`) per recipient, addressed to the member's identity pubkey converted to X25519. Don't fall back to symmetric encryption.
- Three-field envelope: `summary` (required), `html` (optional), `plaintext` (optional). Each field is its own sealed ciphertext.
- atreoLINK gets only the envelope ciphertexts + the recipient's userId. No metadata leakage.

### Touching custom-domain handlers
- Verify owner signature first. Then verify the `intent` string matches `<action>-<deviceId>-<parentZone>` exactly — this binds the signature to this device + this zone, preventing cross-zone replay.
- EnsureCert before persisting the row. Persist after success so a restart-while-atreoLINK-down can re-load the cert from disk.

### Adding a config option
- YAML field + env var override + default in `internal/config/config.go`.
- Document in [docs.atreolink.com](https://docs.atreolink.com) (the agent config-file + environment-variables pages).
- **YAML-presence-aware booleans:** if a default-true field needs to be settable to `false` via YAML, model it as `*bool` (see `ProxyConfig.Enabled`). `applyDefaults()` only fills it in when nil, so a literal `false` in YAML survives.

## Don't do this

- Don't log the WS URL (contains the agent's identity signature; 120 s replay window is short but logging it widens the surface).
- Don't bypass `member.IdentityPublic` for signature verification. Agent pins; atreolink relays.
- Don't increase the 25 s keepalive interval. NAT timeouts aren't fun to debug.
- Don't change the WG interface name (`wg-atreo`). Hardcoded in multiple places.
- Don't auto-update DDNS on port mismatch.
- Don't skip atomic writes for JSON persistence — half-written files on crash are painful.
- Don't widen `trusted_networks` defaults. LAN bypass is an explicit opt-in.
- Don't add dependencies that require `cgo` — the Docker image builds statically.
- Don't bind the SMTP gateway to anything other than a LAN address. STARTTLS is opt-in and self-signed (opportunistic only); on the plaintext path the AUTH password rides base64-encoded on the wire, so it belongs on a LAN.
- Don't echo `pushKeyHex` in any response that travels through atreoLINK — the recipient client re-derives it locally from the agent's ephemeral pubkey.

## Commenting standard

The repo is Apache-2.0 open source; future contributors (and future AI assistants) read these comments without the conversation context that produced them. Apply this standard to every comment you add or touch.

- **Why, not what.** If a reader can see what the code does by reading it, the comment is redundant — delete it. Reserve comments for the *why*: the invariant, the workaround, the gotcha.
- **Brief.** Prefer a single line. Strip filler, hedging, and restatement. If you find yourself needing a paragraph, the code probably needs refactoring more than the comment needs words.
- **Update or delete, don't let it drift.** A stale comment is worse than no comment. If you change the code, update the comment in the same change.
- **No narrating comments.** Lines like `// loop through users` above a `for user := range users` are noise.
- **Do keep non-obvious context.** Tricky invariants, why a workaround exists, references to external specs (RFC numbers, vendor docs), platform-specific gotchas — these earn their place.
- **No references to internal-only artefacts.** Don't mention ADRs, ticket IDs, internal vault paths, or the internals of the proprietary coordination service or its client apps in code comments. Describe the agent's side of the contract — its inputs, outputs, and invariants. If you need to record a contract a client or the coordination service must satisfy, frame it as a property of the wire protocol, not a pointer into another codebase.

## Where to look

- Agent main loop: `internal/agent/agent.go`.
- WS client: `internal/tunnel/client.go::Start`.
- Provision handler: `internal/tunnel/handler.go` (search for `wg:provision`).
- WireGuard interface: `internal/wireguard/server.go`.
- ACL: `internal/acl/store.go`.
- Proxy ACL check: `internal/proxy/server.go`.
- Forward-auth: `internal/proxy/auth.go`.
- Notify API: `internal/notify/server.go`.
- SMTP gateway: `internal/smtp/server.go`.
- LAN probe: `internal/probe/server.go`.
- Endpoint envelope: `internal/endpoints/service.go`.
- Cert automation: `internal/certs/manager.go`.
- Custom-domain handlers: `internal/tunnel/handler_customdomain.go`.
- UPnP: `internal/upnp/`.
- Pairing / atreolink client: `internal/atreolink/client.go`.

## Testing

- Go tests (`*_test.go`). Run `go test -race ./...`.
- Manual integration via the Docker compose against a running atreoLINK coordination service and a paired client. There's no in-repo end-to-end test harness.
