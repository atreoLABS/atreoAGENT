# Security Policy

## Reporting a vulnerability

Please **do not** open public GitHub issues for security vulnerabilities.

Report security issues privately by either:

- Emailing **security@atreolabs.com**, or
- Using GitHub's [private vulnerability advisory](https://github.com/atreoLABS/atreoAGENT/security/advisories/new) feature.

For sensitive disclosures, prefer GitHub's private advisory — it offers built-in encryption and integrates with CVE issuance.

Include as much detail as you can: affected version / commit, reproduction steps, expected vs. actual behaviour, and any proof-of-concept. Reports will be promptly acknowledged and addressed.

## Supported versions

Only the latest release of atreoAGENT is supported. There is no LTS — operators are expected to track the latest release.

The agent must run against the latest version of atreoLINK; older coordination-server versions are not supported.

## Threat model

`atreoAGENT` runs inside the server owner's trust boundary and explicitly distrusts the coordination server it talks to. Some non-obvious things to keep in mind when reporting:

- The coordination server is treated as a relay only. It cannot mint credentials, sign envelopes, or substitute keys. Findings that assume coordination-server compromise are still valuable; please describe the attacker capability.
- Per-app ACL enforcement happens **on the agent**, not on the coordination server. The agent pins owner identity at pairing time and verifies every state-changing message against the pinned key.
- The 25-second WebSocket keepalive is a known correctness invariant, not a tuning knob — please don't report it as a finding without context.

See [AGENTS.md](AGENTS.md) for the full list of architectural invariants if your finding crosses one of them.

## Scope

In scope:

- Code in this repository (`atreoAGENT`).
- Default Docker image build configuration in this repository.

Out of scope (please report to the relevant project / vendor instead):

- Issues in upstream dependencies (file with the upstream project).
- Issues in the closed-source coordination server (`atreoLINK`).
- Findings that require root access on the host the agent runs on.
- Self-XSS / social engineering attacks against the operator.
