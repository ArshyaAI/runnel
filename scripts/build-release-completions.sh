#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <target> <version> <output>"
	exit 1
fi

TARGET="$1"
VERSION="$2"
OUTPUT_DIR="$3"

case "$TARGET" in
	darwin/arm64 | darwin/amd64)
		;;
	*)
		echo "unsupported target ${TARGET}; expected darwin/arm64 or darwin/amd64"
		exit 1
		;;
esac

if [ -z "$VERSION" ]; then
	echo "version must be explicit and non-empty"
	exit 1
fi
if ! echo "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]$'; then
	echo "version must be semantic tag vX.Y.Z"
	exit 1
fi
if [ -z "$OUTPUT_DIR" ]; then
	echo "output directory must be explicit and non-empty"
	exit 1
fi
if [ ! -d "$(dirname "$OUTPUT_DIR")" ]; then
	mkdir -p "$(dirname "$OUTPUT_DIR")"
fi

OS="${TARGET%%/*}"
ARCH="${TARGET##*/}"
build_root="$(mktemp -d /private/tmp/runnel-completions.XXXXXX)"
trap 'rm -rf -- "$build_root"' EXIT
BINARY_PATH="$build_root/runnel-${OS}-${ARCH}"
mkdir -p "${OUTPUT_DIR}/completions"

CGO_ENABLED=1 GOOS="$OS" GOARCH="$ARCH" \
	go build -trimpath -o "$BINARY_PATH" ./cmd/runnel

"$BINARY_PATH" completion bash > "${OUTPUT_DIR}/completions/runnel.bash"
"$BINARY_PATH" completion zsh > "${OUTPUT_DIR}/completions/runnel.zsh"
"$BINARY_PATH" completion fish > "${OUTPUT_DIR}/completions/runnel.fish"
"$BINARY_PATH" completion powershell > "${OUTPUT_DIR}/completions/runnel.ps1"
