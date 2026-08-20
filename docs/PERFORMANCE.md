# Fast-path performance evidence

Measured locally on 2026-08-20 with an Apple M4 Pro (`darwin/arm64`), macOS
27.0 build `26A5353q`, against the real running workstation process tree.

## Read-only scan

Command under test:

```bash
./dist/runnel scan --json >/dev/null
```

Ten consecutive wall-clock samples, in seconds:

```text
0.24  0.21  0.21  0.20  0.20  0.20  0.21  0.21  0.23  0.20
```

- nearest-rank p95: **0.24 s**
- maximum observed resident set size: **23,281,664 bytes (22.2 MiB)**
- configured product budgets: p95 below 2 s and peak RSS below 50 MiB
- result: both fast-path budgets passed on this dogfood host

The host exposed more than 300 workflow/process groups during this run. macOS denied
some metadata for unrelated processes, so Runnel correctly returned the documented
partial exit code `3` while still emitting schema-valid JSON. No deep Codex database,
rollout-tail, stack-sample, or process-signal path was used.

## Pure grouping scale

One-iteration benchmark results for deterministic process-tree grouping:

| Processes | Time | Allocated bytes |
| ---: | ---: | ---: |
| 100 | 0.268 ms | 156,512 |
| 500 | 0.930 ms | 775,168 |
| 1,500 | 2.740 ms | 2,212,464 |
| 5,000 | 8.901 ms | 7,447,296 |

Reproduce with:

```bash
go test ./internal/workflow -run '^$' \
  -bench BenchmarkGroupProcessTrees -benchtime=1x -benchmem
```

These numbers are local calibration evidence, not a universal hardware claim. CI
continues to enforce correctness, race, schema, and native install gates; performance
should be remeasured on release candidates when the collector or grouping logic changes.
