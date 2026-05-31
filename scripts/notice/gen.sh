#!/usr/bin/env bash
# Regenerate NOTICE from the modules linked into ./cmd/atreoagent.
# Invoked by `make notice`. Pin the detector version via DETECTOR_VERSION.

set -euo pipefail

DETECTOR_VERSION="${DETECTOR_VERSION:-v0.10.0}"
MAIN_MODULE="github.com/atreoLABS/atreoAGENT"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

# `go list -deps` walks the package import graph rooted at the binary's main
# package, which (unlike `go list -m all`) excludes build-tooling modules such
# as golang.org/x/tools and golang.org/x/mod that appear in go.mod only because
# something in the dependency tree imports them under a build tag we never use.
binary_modules="$(go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./cmd/atreoagent \
  | sort -u | grep -v "^${MAIN_MODULE}\$")"

# shellcheck disable=SC2086 # word splitting is intentional here
go list -m -json $binary_modules \
  | go run "go.elastic.co/go-licence-detector@${DETECTOR_VERSION}" \
      -includeIndirect \
      -overrides "$SCRIPT_DIR/overrides.json" \
      -rules "$SCRIPT_DIR/rules.json" \
      -noticeTemplate "$SCRIPT_DIR/template.tmpl" \
      -noticeOut "$REPO_ROOT/NOTICE"
