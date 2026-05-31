.PHONY: build test vet fmt coverage coverage-html notice notice-check

PKGS_NO_CMD := $(shell go list ./... | grep -v /cmd/)

# Release version only when HEAD is exactly a tag; empty otherwise (incl.
# commits past a tag), so the binary falls back to the commit-based VCS
# stamp rather than reporting a stale nearest-tag version.
VERSION ?= $(shell git describe --tags --exact-match --dirty 2>/dev/null)
LDFLAGS := -X main.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o atreoagent ./cmd/atreoagent

# Regenerate NOTICE from the modules linked into ./cmd/atreoagent.
notice:
	./scripts/notice/gen.sh

# CI gate: fail if NOTICE is stale relative to the current dependency set.
notice-check: notice
	@git diff --exit-code -- NOTICE \
	  || (echo "NOTICE is stale — run 'make notice' and commit the result"; exit 1)

vet:
	go vet ./...

fmt:
	gofmt -s -w .

test:
	go test ./...

# Coverage excludes cmd/* (thin main packages) and reports the total.
# Run `make coverage-html` to open a per-line report in the browser.
coverage:
	go test -race -covermode=atomic -coverprofile=coverage.out $(PKGS_NO_CMD)
	@go tool cover -func=coverage.out | tail -1

coverage-html: coverage
	go tool cover -html=coverage.out
