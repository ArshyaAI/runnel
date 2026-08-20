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
	darwin/amd64 | darwin/arm64 | darwin)
		;;
	*)
		echo "unsupported target ${TARGET}; expected darwin"
		exit 1
		;;
esac

if ! printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]$'; then
	echo "version must be semantic tag vX.Y.Z"
	exit 1
fi
if [ -z "$OUTPUT_DIR" ]; then
	echo "output path must be explicit and non-empty"
	exit 1
fi

CHECKSUM_FILE="${OUTPUT_DIR%/}/checksums.txt"
FORMULA_PATH="${OUTPUT_DIR%/}/runnel.rb"
if [ ! -f "$CHECKSUM_FILE" ]; then
	echo "checksums.txt missing at ${CHECKSUM_FILE}; run with snapshot/tagged checksums first"
	exit 1
fi

ARM_NAME="runnel_${VERSION}_darwin_arm64.tar.gz"
AMD_NAME="runnel_${VERSION}_darwin_amd64.tar.gz"
ARM_HASHES="$(awk -v name="$ARM_NAME" 'NF == 2 && $2 == name {print $1}' "$CHECKSUM_FILE")"
AMD_HASHES="$(awk -v name="$AMD_NAME" 'NF == 2 && $2 == name {print $1}' "$CHECKSUM_FILE")"
if [ "$(printf '%s\n' "$ARM_HASHES" | awk 'NF {count++} END {print count+0}')" -ne 1 ] ||
	[ "$(printf '%s\n' "$AMD_HASHES" | awk 'NF {count++} END {print count+0}')" -ne 1 ]; then
	echo "checksums must contain exactly one entry for each native archive" >&2
	exit 1
fi
ARM_HASH="$ARM_HASHES"
AMD_HASH="$AMD_HASHES"
VALID_HASH_COUNT="$(printf '%s\n%s\n' "$ARM_HASH" "$AMD_HASH" | grep -Ec '^[0-9a-f]{64}$' || true)"
if [ "$VALID_HASH_COUNT" -ne 2 ]; then
	echo "archive checksums must be lowercase SHA-256 values" >&2
	exit 1
fi

cat > "$FORMULA_PATH" <<EOF
class Runnel < Formula
  desc "Trace the work. Stop only what the evidence proves safe."
  homepage "https://github.com/ArshyaAI/runnel"
  license "Apache-2.0"

  version "${VERSION#v}"

  if OS.mac?
    on_macos do
      on_arm do
        url "https://github.com/ArshyaAI/runnel/releases/download/v#{version}/runnel_v#{version}_darwin_arm64.tar.gz"
        sha256 "${ARM_HASH}"
      end

      on_intel do
        url "https://github.com/ArshyaAI/runnel/releases/download/v#{version}/runnel_v#{version}_darwin_amd64.tar.gz"
        sha256 "${AMD_HASH}"
      end
    end
  end

  def install
    bin.install "runnel"
    bash_completion.install "completions/runnel.bash"
    zsh_completion.install "completions/runnel.zsh" => "_runnel"
    fish_completion.install "completions/runnel.fish"
  end
end
EOF
