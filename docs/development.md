---
title: Developer guide
description: Repository workflows, checks, benchmarks, packaging, and documentation development
icon: material/code-braces
---

# Developer guide

T32Perf is a Rust 2024 workspace with a C99 target SDK and a uv-managed Python HIL harness.
Repository workflows are intentionally centralized in `cargo xtask`.

!!! tip "Discover before executing"

    Run `cargo xtask --help` before selecting a workflow. The task runner owns the order,
    tools, and cross-platform fallbacks used by repository checks.

## Workspace

```text
crates/t32perf-model     Versioned contracts and schemas
crates/t32perf-session   Session lifecycle and artifact security
crates/t32perf-trace32   Streaming input and TRACE32 adapters
crates/t32perf-analysis  Reconstruction, health, metrics, and comparison
crates/t32perf-perfetto  Streaming Perfetto JSON writer
crates/t32perf-heatmap   Bounded accessible SVG projection for PC-hit heatmaps
crates/t32perf-flamegraph Takumi-backed flat-PC and stack flame-graph renderer
src/                     t32perf CLI orchestration
xtask/                   Repository workflows
sdk/c/                   Target-side C99 event SDK
skill-trace32-perf/      t32mcp skill and fixed PRACTICE scripts
skills/t32perf-mcp/      User-facing skill for the Host MCP service
hil/                     Hardware-in-the-loop orchestration
tools/lauterbach-sampling-mcp/  uv-managed aggregate-PC and intrusive-stack TRACE32 sidecars
```

## Standard workflows

| Goal | Command |
|---|---|
| Discover tasks | `cargo xtask --help` |
| Build the host CLI | `cargo build --release -p t32perf` |
| Run the complete software check | `cargo xtask check` |
| Verify generated schemas | `cargo xtask schemas --check` |
| Build and test the C SDK | `cargo xtask sdk` |
| Run software-only HIL checks | `cargo xtask hil` |
| Run configured hardware HIL | `cargo xtask hil --hardware` |
| Validate the t32mcp skill | `cargo xtask skill` |
| Exercise the Host MCP service | `cargo nextest run -p t32perf --test mcp_server` |
| Check the sampling sidecar | `uv --directory tools/lauterbach-sampling-mcp run pytest` |
| Benchmark one canonical input | `cargo xtask bench --input <canonical.ndjson>` |
| Run analyzer benchmarks | `cargo xtask bench --extended` |
| Create a verified release bundle | `cargo xtask package --output dist` |

`cargo xtask check` runs, in order:

1. `cargo fmt --all --check`.
2. Clippy for all workspace targets and features with warnings denied.
3. `cargo nextest run --workspace --all-features`, with a Cargo test fallback.
4. Rust documentation tests.
5. Schema drift and identity checks.
6. CMake and CTest for the C99 SDK.
7. Software-only HIL tests.
8. Sampling-sidecar lockfile, Ruff, Pyright, and pytest checks.
9. Python benchmark unit tests.
10. Repository-owned skill validation.

The `mcp` subcommand belongs to the same provenance-bound Host binary; it does not replace the
hash-bound `skill-trace32-perf` PRACTICE bundle. `skills/t32perf-mcp` must remain independent
from that bundle. MCP tests cover only software protocol and Controller behavior; they do not
provide HIL evidence.

## Focused test commands

=== "Rust"

    ```bash
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo nextest run --workspace --all-features
    cargo test --workspace --doc
    ```

=== "Python and HIL"

    ```bash
    uv sync --project hil --locked
    uv run --project hil ruff check --config hil/pyproject.toml hil tools/bench
    uv run --project hil ruff format --check --config hil/pyproject.toml hil tools/bench
    uv run --project hil pytest hil/tests -m "not hardware"
    uv run --no-project -m unittest discover -s tools/bench -p "test_*.py"
    uv --directory tools/lauterbach-sampling-mcp run ruff check src tests
    uv --directory tools/lauterbach-sampling-mcp run pyright src tests
    uv --directory tools/lauterbach-sampling-mcp run pytest
    ```

=== "C SDK"

    ```bash
    cmake -S sdk/c -B target/c-sdk -DT32PERF_BUILD_TESTS=ON
    cmake --build target/c-sdk --config Release
    ctest --test-dir target/c-sdk -C Release --output-on-failure
    ```

## Benchmark interpretation

Parser comparison and analyzer benchmarks answer different questions:

- `cargo xtask bench --input ...` runs Rust and Python candidates against the same canonical
  NDJSON input and verifies the input digest before and after each run.
- `cargo xtask bench --extended` measures the streaming analyzer with Criterion.
- `T32PERF_BENCH_10M=1` enables the ten-million-event analyzer case.

!!! warning

    These are host software benchmarks. Synthetic throughput and sampled resident memory
    do not establish TRACE32 capture performance, target overhead, or short-lived peak RSS.

Checked-in measurements and their limitations are indexed in
[Verification evidence](verification-evidence.md).

## Build the documentation

The repository pins the latest published Zensical version available when this site was
introduced: `0.0.57`. Zensical is still a `0.0.x` alpha project, so the explicit pin protects
the build from incompatible releases.

=== "Preview"

    ```bash
    uvx --from zensical==0.0.57 zensical serve
    ```

=== "Strict build"

    ```bash
    uvx --from zensical==0.0.57 zensical build --clean --strict
    ```

The strict build validates internal pages and anchors. Documentation source belongs in
`docs/`, navigation in `zensical.toml`, and theme adjustments in
`docs/stylesheets/extra.css`.

### Authoring conventions

- Write documentation in English.
- Link to the relative Markdown source, not generated HTML.
- Use admonitions for evidence or safety boundaries, not decoration.
- Use tabs for genuine platform or workflow alternatives.
- Prefer Mermaid when a state or data relationship is clearer visually.
- Keep large generated evidence as JSON and summarize its scope in prose.
- Do not introduce a second copy of a contract that can drift from source or schema.

## Continuous integration

CI runs Rust, C SDK, Python/HIL, packaging, and Perfetto importer jobs on the supported
host matrices. The repository's CI files pin Rust `1.95.0`; local development follows
`rust-toolchain.toml`, which currently selects stable. Treat those as two explicit
environments, not interchangeable labels.
