# Parser candidate benchmark

The production parser is Rust. `python_candidate.py` is a synchronous streaming baseline in a second technology. Both candidates must read the same canonical NDJSON, retain no complete event array, and report throughput and peak RSS.

```powershell
cargo build --release -p t32perf-trace32 --example ndjson_candidate
uv run --no-project tools/bench/run_candidates.py `
  target/benchmark-data/session-1m/normalized/observations.ndjson
```

`run_candidates.py` streams the input SHA-256 before execution, runs Rust then Python exactly once under an explicitly warm-cache condition, then recomputes SHA-256 and requires the byte count and digest to match exactly. Evidence records `cache_conditioning`, `candidate_order`, and `input_integrity_verified`; this is not a cold-storage-throughput measurement. The parent samples child peak working set every 100 ms: `GetProcessMemoryInfo` on Windows and `/proc/<pid>/status` on Linux. Discrete sampling can miss short peaks, so evidence must state the interval. The Python candidate also reports its own peak RSS.

The manual benchmark workflow submits the same ordered-run result to the regression gate:

```powershell
uv run --no-project tools/bench/check_regression.py `
  target/parser-candidates-Windows.json
```

The gate requires at least one million observations, first checks identical input, dictionary, and quota claims for both candidates, then checks Rust-vs-Python throughput and externally sampled peak RSS, plus a 64 MiB absolute Rust RSS ceiling. Relative checks reduce false positives from differing runner CPUs, but this is not a controlled-laboratory benchmark and does not replace real TRACE32 input or higher-frequency memory sampling.

After `cargo xtask check`, tag-release Windows/Linux package jobs must generate one million observations and run this same gate. A performance failure on either platform blocks packaging and publishing. Candidate and regression JSON are retained as separate `performance-<OS>` workflow artifacts, not GitHub Release assets.

Candidate evidence and verdict use tooling-private `format=t32perf-parser-candidates-v1` and `format=t32perf-benchmark-regression-v1`. They are not Session/public-artifact contracts in `schemas/v1`, and therefore do not masquerade as an unpublished JSON Schema through a `schema` field. The gate checks exact format, warm-cache condition, fixed candidate order, input integrity before and after, digest/environment, input/quota claims, candidate status, RSS interval, and internal consistency of count/elapsed/rate; Python unit tests lock this contract.

Each candidate enforces independent dictionary bounds: 65,536 definitions and 64 MiB physical dictionary bytes by default, with hard caps of 1,048,576 and 1 GiB. Rust and Python accept `--max-dictionary-entries` and `--max-dictionary-bytes`; zero or a value beyond a hard cap is rejected before parsing. Physical bytes include the LF on every dictionary line.

Analyzer-only Criterion benchmark:

```powershell
$env:T32PERF_BENCH_10M = "1"
cargo bench -p t32perf-analysis --bench streaming -- --noplot
```

Once real TRACE32 samples are available, run 1M, 10M, and multi-GB inputs separately. Synthetic data validates only algorithmic scale and deployment cost; it cannot establish TRACE32 field compatibility, time bases, or native-statistics differentials.

## TRACE32 vendor-text candidate

`trace32_export_candidate.py` is an independent streaming Python-stdlib candidate that checks whether a raw TRACE32 export satisfies the frozen text contract before it enters Rust production normalization. It does not produce canonical observations and cannot be a production adapter or Session evidence.

It accepts exactly two frozen dialects: single-core SNOOPer `ShowRecord Address CYcle TIme.Zero sYmbol` ASCII and three-semantic-column TASKEVENTS without `/TRaceRecord`. Unknown cycle, address class, event, invalid column width, time regression, or truncated input without LF/CRLF termination fails. Output is bounded statistics, input SHA-256, and rate only; no events or symbols accumulate.

For the current TC234L profile, where `P` is the profile's closed Address class:

```powershell
uv run --no-project tools/bench/trace32_export_candidate.py ascii `
  crates/t32perf-trace32/tests/fixtures/trace32/snooper-tc234l-simulator-build190766.txt `
  --address-class P
uv run --no-project tools/bench/trace32_export_candidate.py taskevents `
  crates/t32perf-trace32/tests/fixtures/trace32/taskevents-r2026.02-vendor-sample.csv
```

This candidate is deliberately outside the canonical-NDJSON Rust/Python gate in `run_candidates.py`: its input and output contracts differ. Its bounded JSON uses tooling-private `format=t32perf-trace32-export-candidate/v1`, likewise not a public artifact schema.
