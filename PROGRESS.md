# Progress

## Release status — 2026-08-20

Status: Public launch complete; `Runnel v0.1.0` remains the current published release at
https://github.com/ArshyaAI/runnel/releases/tag/v0.1.0 and the launch X posts are live at
https://x.com/arshya_7/status/2090446169910477145 and
https://x.com/arshya_7/status/2090446547536285876.
Branch: `main`
Next step: Measure the 1-hour and 24-hour launch response, verify the first external
install path, and turn qualified user or maintainer feedback into the next bounded issue.

## Evidence boundary

- Product/design review: approved, 9/10
- Engineering review: PASS after three independent adversarial passes
- Implementation: complete for the approved v0.1 scope
- Verification: full tests, race, vet, vulnerability, license, config, scripts,
  deterministic package, performance, privacy, and independent review passed
- CI: main CI pipeline is green
- Live safety proof: protected workflow classified; action locked; no signal sent
- GitHub repository: public and created (historical launch prerequisite complete).
- Public v0.1.0 release and X launch: completed and published (historical launch prerequisite complete).
- v0.1.1 patch candidate: package-relative documentation, exact packaged-binary smoke,
  and fail-closed tar member validation for links, traversal, duplicates, and special
  files are locally verified; publication remains pending the tagged native workflow.
- Homebrew tap: `brew install ArshyaAI/tap/runnel`; native install and self-test CI passed.
