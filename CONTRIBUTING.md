# Contributing

Contributions are welcome.

## Report an Issue

If you think you've found a bug in atreoAGENT, then please [report an issue](https://github.com/atreoLABS/atreoAGENT/issues/new?assignees=&labels=bug&template=bug_report.md&title=)
using the GitHub issue tracker for the project.

Please provide as much detail as you can and follow the issue template as much as possible.

For **security vulnerabilities**, do not open a public issue — see [SECURITY.md](SECURITY.md).

## Documentation Issues

If you've found an issue with the documentation, or would like to improve it in any way, then
we encourage that you don't open an issue, and instead submit a pull request with your proposed changes.

Our documentation is written in Markdown and GitHub has a built-in editor for markdown files. Just find
the file you want to amend, and click the edit button. GitHub will then guide you through the process of
submitting your change to the project.

## Request a Feature

Before submitting a Pull Request with a new feature, we suggest that you first [propose the feature](https://github.com/atreoLABS/atreoAGENT/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=)
in the issue tracker. This will allow us to discuss your feature request and decide whether or not
we think it's right for the project.

## Development setup

Requirements: Go 1.25+. Optional, for end-to-end testing: Docker and a Linux host with the WireGuard kernel module.

```bash
# Build
go build -o atreoagent ./cmd/atreoagent

# Run tests (race detector enabled by default)
go test -race ./...

# Vet + format
go vet ./...
gofmt -s -w .

# Coverage report (matches CI)
make coverage
```

CI runs `go build`, `go vet`, `go test -race`, `golangci-lint run`, and `make coverage`. PRs must pass all of these.

Skim [AGENTS.md](AGENTS.md) before opening a PR — it documents the critical invariants (ACL pinning, atomic writes, 25-second keepalive, envelope verification). Changes that cross these need explicit discussion.

## Coding standards

### Comments

- Comment only what the code doesn't show. Explain *why*, not *what*. If a reader can see what the code does by reading it, the comment is redundant — delete it.
- Keep comments brief. Prefer a single line. Strip filler, hedging, and restatement. If you find yourself needing a paragraph, the code probably needs refactoring more than it needs a long comment.
- Update or delete existing comments rather than letting them go stale.
- No narrating comments. Lines like `// loop through users` above a `for user := range users` are noise.
- Do keep comments that record non-obvious context: tricky invariants, why a workaround exists, references to external specs (RFCs, vendor docs), platform-specific gotchas.

### Tests

- Use [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) reserved domains (`example.com`, `example.org`) for fixtures. Don't hard-code real domains.
- Tests live next to the code they exercise (`*_test.go`).
- New behaviour needs a test. Bug fixes need a regression test.

### Commits

- Make each commit a coherent change. If you produced intermediate "WIP" commits while developing, squash them before opening the PR.
- Commit messages: short subject line, then a body if the *why* needs explaining. Don't paste the diff into the message.

## Pull Requests

- **Document any change in behaviour** — keep [README.md](README.md) and [AGENTS.md](AGENTS.md) up to date alongside the code change.
- **Branch from `main`** — all PRs target `main`. Use a feature branch.
- **One PR per feature/fix.** If you want to do two things, send two PRs.
- **Pass CI.** PRs that fail `go build`, `go vet`, `go test -race`, `golangci-lint run`, or `make coverage` will not be merged until they're green.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports of unacceptable behaviour go to community@atreolabs.com.

## License

By contributing, you agree that your contribution will be released under the [Apache License 2.0](LICENSE).
