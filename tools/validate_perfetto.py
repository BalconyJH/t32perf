#!/usr/bin/env python3
"""Load a T32Perf report with the official Perfetto trace processor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig


def scalar(processor: TraceProcessor, query: str, column: str) -> int:
    rows = list(processor.query(query))
    if len(rows) != 1:
        raise RuntimeError(f"query returned {len(rows)} rows instead of one")
    return int(getattr(rows[0], column))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--trace-processor", type=Path)
    arguments = parser.parse_args()
    trace = arguments.trace.resolve(strict=True)
    binary = (
        arguments.trace_processor.resolve(strict=True)
        if arguments.trace_processor
        else None
    )
    processor = TraceProcessor(
        trace=str(trace),
        config=TraceProcessorConfig(bin_path=str(binary) if binary else None),
    )
    try:
        slices = scalar(processor, "select count(*) as value from slice", "value")
        counters = scalar(processor, "select count(*) as value from counter", "value")
        tracks = scalar(processor, "select count(*) as value from track", "value")
    finally:
        processor.close()
    print(
        json.dumps(
            {
                "ok": True,
                "trace": str(trace),
                "trace_processor": str(binary) if binary else "package-pinned-download",
                "slices": slices,
                "counters": counters,
                "tracks": tracks,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
