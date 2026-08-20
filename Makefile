# Makefile for deterministic local and CI release scaffolding.

SHELL := /bin/bash
.ONESHELL:

GO := go
GOFLAGS :=
CGO_ENABLED ?= 1
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
GORELEASER ?= goreleaser
ACTIONLINT ?= actionlint
GOVULNCHECK_VERSION := v1.7.0
GO_LICENSES_VERSION := v2.1.0

VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.1.0)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PACKAGE ?= github.com/ArshyaAI/runnel/internal/buildinfo
LDFLAGS := -s -w -buildid= -X $(PACKAGE).Version=$(VERSION) -X $(PACKAGE).Commit=$(COMMIT) -X $(PACKAGE).Date=$(BUILD_DATE)
GOFMT_TARGETS := $(shell git ls-files '*.go')
BIN_PATH := dist/runnel-$(GOOS)-$(GOARCH)
TARGET ?= darwin/amd64

.PHONY: help
help:
	@echo "runnel release scaffolding"
	@echo "make test             run go test ./..."
	@echo "make test-race         run go test -race ./..."
	@echo "make vet              run go vet ./..."
	@echo "make fmt-check        verify gofmt + goimports-like cleanliness"
	@echo "make test-schema      run schema-focused unit package checks"
	@echo "make security         run pinned vulnerability and license gates"
	@echo "make ci               run fmt-check test test-race vet test-schema"
	@echo "make build            build a deterministic local binary"
	@echo "make smoke            native compile and read-only scan smoke target"
	@echo "make clean            remove build artifacts"
	@echo "make release-archives  run goreleaser snapshot build"
	@echo "make release-homebrew  generate non-mutating Homebrew formula template"
	@echo "make package-release   build one reproducible native release archive"

.PHONY: fmt-check
fmt-check:
	@files="$(GOFMT_TARGETS)"; \
	if [ -z "$$files" ]; then \
		echo "no go files found"; \
		exit 1; \
	fi; \
	fmt_out=$$(gofmt -l $$files); \
	if [ -n "$$fmt_out" ]; then \
		echo "gofmt required:"; \
		echo "$$fmt_out"; \
		exit 1; \
	fi

.PHONY: test
test:
	CGO_ENABLED=1 $(GO) test ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 $(GO) test -race ./...

.PHONY: vet
vet:
	CGO_ENABLED=1 $(GO) vet ./...

.PHONY: test-schema
test-schema:
	CGO_ENABLED=1 $(GO) test ./internal/model ./internal/receipt ./schema

.PHONY: ci
ci: fmt-check test test-race vet test-schema security check-config check-scripts

.PHONY: check-config
check-config:
	bash -n scripts/*.sh
	@ruby -e "require 'yaml'; YAML.load_file('.github/dependabot.yml'); YAML.load_file('.github/workflows/ci.yml'); YAML.load_file('.github/workflows/release.yml'); YAML.load_file('.goreleaser.yaml')"
	@git diff --check -- .github .goreleaser.yaml Makefile scripts
	@GORELEASER="$(GORELEASER)" scripts/check-goreleaser.sh
	@if ! command -v "$(ACTIONLINT)" >/dev/null 2>&1; then \
		echo "actionlint is required"; \
		exit 1; \
	fi
	@$(ACTIONLINT) .github/workflows/*.yml

.PHONY: security
security:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./cmd/runnel
	$(GO) run github.com/haproxytech/go-licenses/v2@$(GO_LICENSES_VERSION) check --ignore_nongo ./cmd/runnel

.PHONY: check-scripts
check-scripts:
	tmp_dir=$$(mktemp -d /tmp/runnel-script-checks.XXXXXX); \
	mkdir -p "$$tmp_dir/.cache" "$$tmp_dir/.tmp"; \
	GOCACHE=$$tmp_dir/.cache GOTMPDIR=$$tmp_dir/.tmp; \
	export GOCACHE GOTMPDIR; \
	trap 'rm -rf -- "$$tmp_dir"' EXIT; \
	$(GO) test ./internal/model ./internal/receipt >/dev/null; \
	$(GO) build -trimpath -o "$$tmp_dir/runnel-host" ./cmd/runnel; \
	"$$tmp_dir/runnel-host" completion bash > "$$tmp_dir/bash" 2>/dev/null; \
	"$$tmp_dir/runnel-host" completion zsh > "$$tmp_dir/zsh" 2>/dev/null; \
	"$$tmp_dir/runnel-host" completion fish > "$$tmp_dir/fish" 2>/dev/null; \
	"$$tmp_dir/runnel-host" completion powershell > "$$tmp_dir/ps1" 2>/dev/null; \
	echo "completions generated to $$tmp_dir"; \
	scripts/build-release-completions.sh darwin/arm64 v0.1.0 "$$tmp_dir"; \
	[ -s "$$tmp_dir/completions/runnel.bash" ] || exit 1; \
	[ -s "$$tmp_dir/completions/runnel.zsh" ] || exit 1; \
	grep -Eq '^#compdef runnel' "$$tmp_dir/completions/runnel.zsh"; \
	[ -s "$$tmp_dir/completions/runnel.fish" ] || exit 1; \
	[ -s "$$tmp_dir/completions/runnel.ps1" ] || exit 1; \
	printf '%s\n' \
	  "0000000000000000000000000000000000000000000000000000000000000000  runnel_v0.1.0_darwin_arm64.tar.gz" \
	  "1111111111111111111111111111111111111111111111111111111111111111  runnel_v0.1.0_darwin_amd64.tar.gz" > "$$tmp_dir/checksums.txt"; \
	scripts/build-homebrew-formula.sh darwin/amd64 v0.1.0 "$$tmp_dir"; \
	[ -s "$$tmp_dir/runnel.rb" ] || exit 1; \
	grep -Fq 'download/v#{version}/runnel_v#{version}_darwin_arm64.tar.gz' "$$tmp_dir/runnel.rb"; \
	grep -Fq 'zsh_completion.install "completions/runnel.zsh" => "_runnel"' "$$tmp_dir/runnel.rb"; \
	if grep -Fq '.write ' "$$tmp_dir/runnel.rb"; then \
		echo "formula overwrites a packaged completion"; \
		exit 1; \
	fi; \
	printf '%s\n' \
	  "not-a-sha256  runnel_v0.1.0_darwin_arm64.tar.gz" \
	  "1111111111111111111111111111111111111111111111111111111111111111  runnel_v0.1.0_darwin_amd64.tar.gz" > "$$tmp_dir/checksums.txt"; \
	if scripts/build-homebrew-formula.sh darwin/amd64 v0.1.0 "$$tmp_dir" >/dev/null 2>&1; then \
		echo "formula accepted an invalid digest"; \
		exit 1; \
	fi

.PHONY: build
build:
	mkdir -p dist
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_PATH) ./cmd/runnel

.PHONY: smoke
smoke: assert-target
	@set +e; \
	os="$${TARGET%%/*}"; arch="$${TARGET##*/}"; \
	tmp_snapshot="$$(mktemp /tmp/runnel-smoke-XXXXXXXX.json)"; \
	trap 'rm -f "$$tmp_snapshot"' EXIT; \
	export CGO_ENABLED=1 GOOS="$$os" GOARCH="$$arch"; \
	mkdir -p dist; \
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/runnel ./cmd/runnel; \
	./dist/runnel version; \
	status=0; \
	./dist/runnel scan --json > "$$tmp_snapshot"; status=$$?; \
	if [ "$$status" -ne 0 ] && [ "$$status" -ne 3 ]; then \
		echo "scan failed with unsupported exit code $$status"; \
		exit 1; \
	fi; \
		python3 -c 'import json,sys; json.load(open(sys.argv[1],"r",encoding="utf-8"))' "$$tmp_snapshot"

.PHONY: assert-target
assert-target:
	@case "$(TARGET)" in \
		darwin/arm64|darwin/amd64) ;; \
		*) echo "TARGET must be darwin/arm64 or darwin/amd64"; exit 1;; \
	esac

.PHONY: release-archives
release-archives:
	@if ! command -v $(GORELEASER) >/dev/null 2>&1; then \
		echo "goreleaser missing"; \
		exit 1; \
	fi
	$(GORELEASER) check
	$(GORELEASER) build --clean --snapshot --single-target --id runnel

.PHONY: package-release
package-release: assert-target assert-version
	scripts/package-release.sh $(TARGET) $(VERSION) dist

.PHONY: release-homebrew
release-homebrew: assert-version
	@scripts/build-homebrew-formula.sh darwin/amd64 $(VERSION) .

.PHONY: assert-version
assert-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "VERSION is required"; \
		exit 1; \
	fi; \
	if ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]$'; then \
		echo "VERSION must be vX.Y.Z"; \
		exit 1; \
	fi

.PHONY: clean
clean:
	rm -rf -- dist
