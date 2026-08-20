# Public-safe launch demo. This tape deliberately never runs `runnel scan` or
# `runnel recover`; the only real Runnel operation is the in-memory doctor
# self-test. The final segment renders expected values from a public synthetic
# fixture and labels them on screen throughout.

Output "/private/tmp/runnel-demo-v011-terminal.mp4"

Require runnel
Require jq

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontFamily "Menlo"
Set FontSize 32
Set Width 1200
Set Height 1500
Set Padding 52
Set LetterSpacing 0
Set LineHeight 1.1
Set BorderRadius 18
Set WindowBar "Colorful"
Set WindowBarSize 46
Set TypingSpeed 0ms
Set Framerate 25

Hide
Type "export PS1='❯ '; fixture() { jq '{fixture:.case_id, availability:.expected.availability, classification:.expected.classification, selectable:.expected.selectable, evidence:.expected.evidence}' fixtures/codex/v1/cases/$1.json; }; clear" Enter
Sleep 500ms
Show

Type "# Can this exact AI worker be stopped safely?" Enter
Sleep 2s

Type "runnel version" Enter
Sleep 2s

Type "runnel doctor --self-test --json | jq" Enter
Sleep 3s

Type "# SYNTHETIC FIXTURE: contradictory.json — no live scan" Enter
Sleep 1s

Type "fixture contradictory" Enter
Sleep 4s

Type "# ACTION LOCKED  |  signals sent: 0" Enter
Sleep 3s
