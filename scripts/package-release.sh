#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <target> <version> <output>" >&2
	exit 2
fi

target="$1"
version="$2"
output_dir="$3"

case "$target" in
	darwin/arm64 | darwin/amd64) ;;
	*)
		echo "target must be darwin/arm64 or darwin/amd64" >&2
		exit 2
		;;
esac
if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "version must be vX.Y.Z" >&2
	exit 2
fi
if [ -z "$output_dir" ]; then
	echo "output directory must be explicit" >&2
	exit 2
fi
if ! command -v goreleaser >/dev/null 2>&1; then
	echo "goreleaser is required" >&2
	exit 4
fi

# Make exports command-line variables to recipes. Its TARGET uses `darwin/arm64`,
# while GoReleaser interprets TARGET as its internal build target identifier and
# would silently select no binary. The explicit GOOS/GOARCH below are authoritative.
unset TARGET

os="${target%%/*}"
arch="${target##*/}"
archive_name="runnel_${version}_${os}_${arch}.tar.gz"
package_root="$(mktemp -d /private/tmp/runnel-package.XXXXXX)"
trap 'rm -rf -- "$package_root"' EXIT
stage="$package_root/stage"
mkdir -p "$stage/completions" "$stage/schema" "$output_dir"

release_flags=(build --clean --single-target --id runnel)
if [ "${RUNNEL_SNAPSHOT:-0}" = "1" ]; then
	release_flags+=(--snapshot --skip=before)
else
	exact_tag="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
	if [ "$exact_tag" != "$version" ]; then
		echo "HEAD must be tagged exactly ${version}" >&2
		exit 4
	fi
fi
CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" goreleaser "${release_flags[@]}"
built_binaries="$(find dist -type f -name runnel -print)"
built_binary_count="$(printf '%s\n' "$built_binaries" | awk 'NF { count++ } END { print count + 0 }')"
if [ "$built_binary_count" -ne 1 ]; then
	echo "expected exactly one GoReleaser binary, found $built_binary_count" >&2
	exit 4
fi
cp "$built_binaries" "$stage/runnel"
mkdir -p "$output_dir"

"$stage/runnel" completion bash > "$stage/completions/runnel.bash"
"$stage/runnel" completion zsh > "$stage/completions/runnel.zsh"
"$stage/runnel" completion fish > "$stage/completions/runnel.fish"
"$stage/runnel" completion powershell > "$stage/completions/runnel.ps1"
package_files=(
	LICENSE
	PRIVACY.md
	README.md
	SECURITY.md
	CONTRIBUTING.md
	docs/CODEX_ADAPTER_CALIBRATION.md
	docs/ORIGIN_STORY.md
	docs/PERFORMANCE.md
	docs/THREAT_MODEL.md
	docs/XNU_IDENTITY_PROOF.md
	assets/launch/runnel-launch-card.png
)
for package_file in "${package_files[@]}"; do
	if [ ! -f "$package_file" ]; then
		echo "required package file is missing: $package_file" >&2
		exit 4
	fi
	mkdir -p "$stage/$(dirname "$package_file")"
	cp "$package_file" "$stage/$package_file"
done
for schema_file in schema/*.json; do
	cp "$schema_file" "$stage/$schema_file"
done
chmod 0755 "$stage/runnel"
find "$stage" -type f ! -name runnel -exec chmod 0644 {} +

# Normalize metadata and gzip headers so two builds of the same binary and
# source tree produce byte-identical archives.
TZ=UTC find "$stage" -type f -exec touch -t 198001010000 {} +
file_list="$package_root/files.txt"
(cd "$stage" && find . -type f -print | LC_ALL=C sort) > "$file_list"
uncompressed="$package_root/${archive_name%.gz}"
COPYFILE_DISABLE=1 /usr/bin/tar \
	--format ustar --uid 0 --gid 0 --uname root --gname wheel \
	--no-xattrs --no-mac-metadata -cf "$uncompressed" -C "$stage" -T "$file_list"
gzip -n -9 "$uncompressed"
cp "$uncompressed.gz" "$output_dir/$archive_name"

# Keep the release contract executable: every relative README target must be
# present at the same path in the extracted archive, with no missing package
# content.
scripts/check-release-archive.sh "$output_dir/$archive_name" "$version" --contract-only

(
	cd "$output_dir"
	shasum -a 256 "$archive_name" > "checksums-${arch}.txt"
)

printf '%s\n' "$output_dir/$archive_name"
