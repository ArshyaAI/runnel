#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 <archive> <version> [--contract-only]" >&2
	exit 2
fi

archive="$1"
version="$2"
mode="${3:-smoke}"
if [ "$mode" != "--contract-only" ] && [ "$mode" != "smoke" ]; then
	echo "mode must be --contract-only or smoke" >&2
	exit 2
fi
if [ ! -f "$archive" ]; then
	echo "archive does not exist: $archive" >&2
	exit 2
fi
if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "version must be vX.Y.Z" >&2
	exit 2
fi

archive_name="$(basename "$archive")"
case "$archive_name" in
	runnel_${version}_darwin_arm64.tar.gz) arch=arm64 ;;
	runnel_${version}_darwin_amd64.tar.gz) arch=amd64 ;;
	*)
		echo "archive name does not match version and native target: $archive_name" >&2
		exit 1
		;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
check_root="$(mktemp -d /private/tmp/runnel-archive-check.XXXXXX)"
trap 'rm -rf -- "$check_root"' EXIT
extract_root="$check_root/extracted"
mkdir -p "$extract_root"

# Reject path traversal before extraction, then extract the exact archive that
# was produced by the release job.
member_list="$check_root/members.txt"
tar -tzf "$archive" > "$member_list"
while IFS= read -r member; do
	case "$member" in
		/*|../*|*/../*|*/..)
			echo "unsafe archive member: $member" >&2
			exit 1
			;;
	esac
done < "$member_list"

# Member names alone are insufficient: tar extraction follows archive-defined
# symlink and hard-link metadata. Reject every non-regular, non-directory entry
# before extraction, and reject traversal after POSIX path normalization.
python3 - "$archive" <<'PY'
import pathlib
import sys
import tarfile

archive_path = sys.argv[1]
seen = set()
with tarfile.open(archive_path, mode="r:gz") as bundle:
    for member in bundle.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe archive member: {member.name}")
        normalized = str(path)
        if member.isfile():
            if normalized in seen:
                raise SystemExit(f"duplicate archive member: {member.name}")
            seen.add(normalized)
            continue
        if member.isdir():
            continue
        raise SystemExit(
            f"unsupported archive member type for {member.name}: {member.type!r}"
        )
PY
tar -xzf "$archive" -C "$extract_root"

expected="$check_root/expected.txt"
{
	printf '%s\n' \
		LICENSE \
		PRIVACY.md \
		README.md \
		SECURITY.md \
		CONTRIBUTING.md \
		docs/CODEX_ADAPTER_CALIBRATION.md \
		docs/ORIGIN_STORY.md \
		docs/PERFORMANCE.md \
		docs/THREAT_MODEL.md \
		docs/XNU_IDENTITY_PROOF.md \
		assets/launch/runnel-launch-card.png
	for file in "$repo_root"/schema/*.json; do
		printf 'schema/%s\n' "$(basename "$file")"
	done
	printf '%s\n' completions/runnel.bash completions/runnel.fish completions/runnel.ps1 completions/runnel.zsh runnel
} | LC_ALL=C sort > "$expected"

archive_files="$check_root/archive-files.txt"
sed -e '/\/$/d' -e 's#^\./##' "$member_list" | LC_ALL=C sort > "$archive_files"
if ! cmp -s "$expected" "$archive_files"; then
	echo "archive contents differ from the deterministic release contract" >&2
	diff -u "$expected" "$archive_files" >&2 || true
	exit 1
fi

while IFS= read -r file; do
	if [ ! -f "$extract_root/$file" ] || [ -L "$extract_root/$file" ]; then
		echo "archive member is not a regular file: $file" >&2
		exit 1
	fi
done < "$expected"

# Resolve every relative README link against the extracted archive root.
while IFS= read -r link; do
	case "$link" in
		''|\#*|*://*|mailto:*) continue ;;
		/*) echo "README contains an absolute link: $link" >&2; exit 1 ;;
	esac
	if [ ! -f "$extract_root/$link" ]; then
		echo "README link target is absent from archive: $link" >&2
		exit 1
	fi
done < <(sed -nE 's/.*\]\(([^)#?]+).*/\1/p' "$extract_root/README.md" | LC_ALL=C sort -u)

# Packaged text and image assets must be byte-for-byte copies of the governed
# repository sources; this catches accidental link rewrites and stale docs.
while IFS= read -r file; do
	if ! cmp -s "$repo_root/$file" "$extract_root/$file"; then
		echo "packaged content differs from source: $file" >&2
		exit 1
	fi
done < <(sed -e '/^runnel$/d' -e '/^completions\//d' "$expected")

if [ "$mode" = "--contract-only" ]; then
	echo "archive contract: ok ($archive_name)"
	exit 0
fi

version_output="$check_root/version.txt"
"$extract_root/runnel" version | tee "$version_output"
version_line="$(cat "$version_output")"
expected_version="${version#v}"
case "$version_line" in
	"$expected_version ("* | "$expected_version-SNAPSHOT-"*) ;;
	*)
		echo "packaged binary version does not match $version: $version_line" >&2
		exit 1
		;;
esac
"$extract_root/runnel" doctor --self-test

scan_output="$check_root/scan.json"
set +e
"$extract_root/runnel" scan --json > "$scan_output"
scan_status=$?
set -e
if [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 3 ]; then
	echo "packaged scan failed with unsupported exit code $scan_status" >&2
	exit 1
fi
python3 -c 'import json,sys; json.load(open(sys.argv[1], "r", encoding="utf-8"))' "$scan_output"
echo "archive smoke: ok ($archive_name, darwin/$arch, scan exit $scan_status)"
