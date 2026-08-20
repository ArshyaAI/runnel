#!/usr/bin/env bash
set -euo pipefail

goreleaser_bin="${GORELEASER:-goreleaser}"
if ! command -v "$goreleaser_bin" >/dev/null 2>&1; then
	echo "goreleaser is required" >&2
	exit 4
fi
if git remote get-url origin >/dev/null 2>&1; then
	"$goreleaser_bin" check
	exit 0
fi

# Local pre-publication repositories may intentionally have no remote. Check
# the exact config in a disposable repository with a syntactic fake origin;
# no network call or persistent git mutation occurs.
check_root="$(mktemp -d /private/tmp/runnel-goreleaser-check.XXXXXX)"
trap 'rm -rf -- "$check_root"' EXIT
cp .goreleaser.yaml "$check_root/.goreleaser.yaml"
git -C "$check_root" init -q
git -C "$check_root" remote add origin https://github.com/ArshyaAI/runnel.git
(
	cd "$check_root"
	"$goreleaser_bin" check
)
