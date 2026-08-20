#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tape="$repo_root/assets/launch/runnel-demo-v011.tape"
terminal_video="/private/tmp/runnel-demo-v011-terminal.mp4"
reference_output="$repo_root/assets/launch/runnel-demo-v011-social.mp4"
output="/private/tmp/runnel-demo-v011-social.generated.mp4"
expected_version="0.1.1 (9bd826e, 2026-08-20T15:50:05Z)"
render_root="$(mktemp -d /private/tmp/runnel-demo-render.XXXXXX)"
rendered="$render_root/runnel-demo-v011-social.mp4"
staged="$output.tmp.$$"
trap 'rm -rf -- "$render_root"; rm -f -- "$staged"' EXIT

for command_name in vhs ffmpeg ffprobe jq runnel; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "$command_name is required" >&2
		exit 4
	fi
done

actual_version="$(runnel version)"
if [ "$actual_version" != "$expected_version" ]; then
	echo "expected Runnel $expected_version, got $actual_version" >&2
	exit 4
fi

# The public tape is intentionally synthetic and action-free. Keep these
# content guards next to the renderer so a future edit cannot silently turn a
# launch artifact into a live scan or recovery run.
grep -Fqx 'Type "runnel version" Enter' "$tape"
grep -Fqx 'Type "runnel doctor --self-test --json | jq" Enter' "$tape"
grep -Fqx 'Type "# SYNTHETIC FIXTURE: contradictory.json — no live scan" Enter' "$tape"
grep -Fqx 'Type "# ACTION LOCKED  |  signals sent: 0" Enter' "$tape"
if grep -Eq '^Type "runnel (scan|recover)( |")' "$tape"; then
	echo "demo tape must not run live scan or recovery" >&2
	exit 1
fi

cd "$repo_root"
vhs validate "$tape"
vhs "$tape"

ffmpeg -y \
	-loop 1 -framerate 25 -i assets/launch/runnel-social-01-incident.png \
	-i "$terminal_video" \
	-loop 1 -framerate 25 -i assets/launch/runnel-social-02-refusal.png \
	-filter_complex \
	"[0:v]scale=1200:1500:force_original_aspect_ratio=decrease,pad=1200:1500:(ow-iw)/2:(oh-ih)/2,trim=duration=2.5,setpts=PTS-STARTPTS,fps=25,format=yuv420p[v0];[1:v]scale=1200:1500,tpad=stop_mode=clone:stop_duration=5,trim=duration=17.6,setpts=PTS-STARTPTS,fps=25,format=yuv420p[v1];[2:v]scale=1200:1500:force_original_aspect_ratio=decrease,pad=1200:1500:(ow-iw)/2:(oh-ih)/2,trim=duration=2.5,setpts=PTS-STARTPTS,fps=25,format=yuv420p[v2];[v0][v1][v2]concat=n=3:v=1:a=0[outv]" \
	-map "[outv]" \
	-c:v libx264 -preset slow -crf 18 -movflags +faststart \
	"$rendered"

metadata="$(ffprobe -v error \
	-show_entries stream=codec_name,width,height,pix_fmt,r_frame_rate,nb_frames:format=duration \
	-of default=noprint_wrappers=1 "$rendered")"
printf '%s\n' "$metadata"
printf '%s\n' "$metadata" | grep -Fqx 'codec_name=h264'
printf '%s\n' "$metadata" | grep -Fqx 'width=1200'
printf '%s\n' "$metadata" | grep -Fqx 'height=1500'
printf '%s\n' "$metadata" | grep -Fqx 'pix_fmt=yuv420p'
printf '%s\n' "$metadata" | grep -Fqx 'r_frame_rate=25/1'
printf '%s\n' "$metadata" | grep -Fqx 'nb_frames=566'
printf '%s\n' "$metadata" | grep -Fqx 'duration=22.640000'

if [ -n "$(ffprobe -v error -select_streams a -show_entries stream=index -of csv=p=0 "$rendered")" ]; then
	echo "demo unexpectedly contains an audio stream" >&2
	exit 1
fi

actual_sha256="$(shasum -a 256 "$rendered" | awk '{print $1}')"
cp "$rendered" "$staged"
chmod 0644 "$staged"
mv -f "$staged" "$output"
printf '%s  %s\n' "$actual_sha256" "$output"
printf 'reference artifact remains unchanged: %s\n' "$reference_output"
