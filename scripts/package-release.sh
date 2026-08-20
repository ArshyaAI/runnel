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

os="${target%%/*}"
arch="${target##*/}"
archive_name="runnel_${version}_${os}_${arch}.tar.gz"
package_root="$(mktemp -d /private/tmp/runnel-package.XXXXXX)"
trap 'rm -rf -- "$package_root"' EXIT
stage="$package_root/stage"
mkdir -p "$stage/completions" "$stage/schema" "$output_dir"

release_flags=(build --clean --single-target --id runnel --output "$stage/runnel")
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
mkdir -p "$output_dir"

"$stage/runnel" completion bash > "$stage/completions/runnel.bash"
"$stage/runnel" completion zsh > "$stage/completions/runnel.zsh"
"$stage/runnel" completion fish > "$stage/completions/runnel.fish"
"$stage/runnel" completion powershell > "$stage/completions/runnel.ps1"
cp LICENSE PRIVACY.md README.md SECURITY.md "$stage/"
cp schema/*.json "$stage/schema/"
chmod 0755 "$stage/runnel"
chmod 0644 "$stage"/*.md "$stage/LICENSE" "$stage/completions"/* "$stage/schema"/*.json

# Normalize metadata and gzip headers so two builds of the same binary and
# source tree produce byte-identical archives.
TZ=UTC touch -t 198001010000 "$stage/runnel" "$stage"/*.md "$stage/LICENSE" "$stage/completions"/* "$stage/schema"/*.json
file_list="$package_root/files.txt"
(cd "$stage" && find . -type f -print | LC_ALL=C sort) > "$file_list"
uncompressed="$package_root/${archive_name%.gz}"
COPYFILE_DISABLE=1 /usr/bin/tar \
	--format ustar --uid 0 --gid 0 --uname root --gname wheel \
	--no-xattrs --no-mac-metadata -cf "$uncompressed" -C "$stage" -T "$file_list"
gzip -n -9 "$uncompressed"
cp "$uncompressed.gz" "$output_dir/$archive_name"

(
	cd "$output_dir"
	shasum -a 256 "$archive_name" > "checksums-${arch}.txt"
)

printf '%s\n' "$output_dir/$archive_name"
