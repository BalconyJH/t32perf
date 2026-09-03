#!/usr/bin/env python3
"""Reference Python streaming parser candidate for canonical T32Perf NDJSON."""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import BinaryIO, NoReturn

DICTIONARY_TYPES = {"DefineContext", "DefineFunction", "DefineCounter"}
DEFAULT_MAX_DICTIONARY_ENTRIES = 65_536
DEFAULT_MAX_DICTIONARY_BYTES = 64 * 1024 * 1024
HARD_MAX_DICTIONARY_ENTRIES = 1_048_576
HARD_MAX_DICTIONARY_BYTES = 1024 * 1024 * 1024
DICTIONARY_FIELDS = {
    "DefineContext": {"type", "id", "kind", "name", "core_id", "priority"},
    "DefineFunction": {"type", "id", "name", "module", "address", "file", "line"},
    "DefineCounter": {
        "type",
        "id",
        "name",
        "unit",
        "description",
        "semantic",
        "subject",
    },
}
DICTIONARY_REQUIRED = {
    "DefineContext": {"type", "id", "kind", "name"},
    "DefineFunction": {"type", "id", "name"},
    "DefineCounter": {"type", "id", "name"},
}
HEADER_FIELDS = {
    "schema",
    "session_id",
    "encoding",
    "time_unit",
    "time_origin",
    "properties",
}
COMMON_EVENT_FIELDS = {"source_id", "source_seq", "quality", "type", "ts_ns"}
EVENT_FIELDS = {
    "FunctionEnter": {"core_id", "context_id", "function_id", "frame_id"},
    "FunctionExit": {"core_id", "context_id", "function_id", "frame_id"},
    "ContextSwitch": {"core_id", "prev_context_id", "next_context_id", "reason"},
    "InterruptEnter": {"core_id", "interrupt_id", "priority", "activation_id"},
    "InterruptExit": {"core_id", "interrupt_id", "priority", "activation_id"},
    "Sample": {"core_id", "context_id", "function_id", "address", "weight_ns"},
    "Instant": {"core_id", "context_id", "name", "args"},
    "SpanBegin": {"core_id", "context_id", "span_id", "name", "args"},
    "SpanEnd": {"core_id", "context_id", "span_id", "args"},
    "AsyncBegin": {"core_id", "context_id", "correlation_id", "name", "args"},
    "AsyncEnd": {"core_id", "context_id", "correlation_id", "args"},
    "Counter": {"core_id", "context_id", "counter_id", "value", "args"},
    "TraceGap": {"duration_ns", "reason"},
    "Metadata": {"key", "value"},
}
EVENT_REQUIRED = {
    "FunctionEnter": {"core_id", "context_id", "function_id"},
    "FunctionExit": {"core_id", "context_id", "function_id"},
    "ContextSwitch": {"core_id", "next_context_id"},
    "InterruptEnter": {"core_id", "interrupt_id", "activation_id"},
    "InterruptExit": {"core_id", "interrupt_id", "activation_id"},
    "Sample": {"core_id"},
    "Instant": {"name"},
    "SpanBegin": {"span_id", "name"},
    "SpanEnd": {"span_id"},
    "AsyncBegin": {"correlation_id", "name"},
    "AsyncEnd": {"correlation_id"},
    "Counter": {"counter_id", "value"},
    "TraceGap": {"duration_ns", "reason"},
    "Metadata": {"key", "value"},
}


class ParseFailure(ValueError):
    """A precise canonical stream validation failure."""


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object names at every nesting depth."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ParseFailure(f"duplicate JSON object member name `{key}`")
        result[key] = value
    return result


def parse_stream(
    stream: BinaryIO,
    max_line_bytes: int,
    max_dictionary_entries: int = DEFAULT_MAX_DICTIONARY_ENTRIES,
    max_dictionary_bytes: int = DEFAULT_MAX_DICTIONARY_BYTES,
) -> dict[str, int | str]:
    """Parse and validate one canonical stream without retaining events."""

    if max_line_bytes <= 0:
        raise ParseFailure("max_line_bytes must be positive")
    if not 0 < max_dictionary_entries <= HARD_MAX_DICTIONARY_ENTRIES:
        raise ParseFailure(
            "max_dictionary_entries must be between 1 and "
            f"{HARD_MAX_DICTIONARY_ENTRIES}"
        )
    if not 0 < max_dictionary_bytes <= HARD_MAX_DICTIONARY_BYTES:
        raise ParseFailure(
            f"max_dictionary_bytes must be between 1 and {HARD_MAX_DICTIONARY_BYTES}"
        )

    line_number = 0
    byte_offset = 0
    observations = 0
    dictionary_entries = 0
    dictionary_bytes = 0
    last_timestamp: int | None = None
    source_sequences: dict[str, int] = {}
    observations_started = False
    session_id: str | None = None
    dictionary_ids: dict[str, set[str]] = {
        "DefineContext": set(),
        "DefineFunction": set(),
        "DefineCounter": set(),
    }

    while True:
        line_start = byte_offset
        raw = stream.readline(max_line_bytes + 1)
        if not raw:
            break
        line_number += 1
        byte_offset += len(raw)
        if len(raw) > max_line_bytes and not raw.endswith(b"\n"):
            fail(line_number, line_start, f"line exceeds {max_line_bytes} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(line_number, line_start + error.start, "invalid UTF-8")
        if not text.strip():
            fail(line_number, line_start, "empty lines are not allowed")
        try:
            record = json.loads(
                text,
                parse_constant=reject_nonfinite,
                object_pairs_hook=reject_duplicate_pairs,
            )
        except (json.JSONDecodeError, ParseFailure) as error:
            column = getattr(error, "colno", 1)
            fail(line_number, line_start + column - 1, f"invalid JSON: {error}")
        if not isinstance(record, dict):
            fail(line_number, line_start, "record must be a JSON object")

        if line_number == 1:
            session_id = validate_header(record, line_number, line_start)
            continue

        record_type = record.get("type")
        if record_type in DICTIONARY_TYPES:
            if observations_started:
                fail(line_number, line_start, "dictionary entry follows observations")
            if dictionary_entries >= max_dictionary_entries:
                fail(
                    line_number,
                    line_start,
                    f"dictionary entry count exceeds {max_dictionary_entries}",
                )
            remaining = max_dictionary_bytes - dictionary_bytes
            if len(raw) > remaining:
                fail(
                    line_number,
                    line_start + min(remaining, len(raw) - 1),
                    f"dictionary physical bytes exceed {max_dictionary_bytes}",
                )
            dictionary_bytes += len(raw)
            validate_dictionary_entry(record, dictionary_ids, line_number, line_start)
            dictionary_entries += 1
            continue
        observations_started = True
        if not isinstance(record_type, str):
            fail(line_number, line_start, "event type is missing")
        event_fields = EVENT_FIELDS.get(record_type)
        if event_fields is None:
            fail(line_number, line_start, f"unknown event type {record_type!r}")
        unknown = set(record) - COMMON_EVENT_FIELDS - event_fields
        if unknown:
            fail(line_number, line_start, f"unknown fields: {sorted(unknown)!r}")
        missing = EVENT_REQUIRED[record_type] - set(record)
        if missing:
            fail(line_number, line_start, f"missing fields: {sorted(missing)!r}")

        source_id = record.get("source_id")
        source_seq = record.get("source_seq")
        timestamp = record.get("ts_ns")
        quality = record.get("quality")
        if not isinstance(source_id, str) or not source_id:
            fail(line_number, line_start, "source_id must be a non-empty string")
        if not is_integer(source_seq) or source_seq < 0:
            fail(line_number, line_start, "source_seq must be a non-negative integer")
        if not is_integer(timestamp):
            fail(line_number, line_start, "ts_ns must be an integer")
        if quality not in {"exact", "inferred", "statistical"}:
            fail(line_number, line_start, "quality is invalid")
        if record_type == "Counter" and (
            not isinstance(record["value"], (int, float))
            or isinstance(record["value"], bool)
            or not math.isfinite(record["value"])
        ):
            fail(line_number, line_start, "counter value must be finite")
        if record_type == "TraceGap" and (
            not is_integer(record["duration_ns"]) or record["duration_ns"] < 0
        ):
            fail(line_number, line_start, "duration_ns must be non-negative")
        previous_sequence = source_sequences.get(source_id)
        if previous_sequence is not None and source_seq <= previous_sequence:
            fail(
                line_number,
                line_start,
                f"source sequence {source_seq} follows {previous_sequence} for {source_id}",
            )
        if last_timestamp is not None and timestamp < last_timestamp:
            fail(
                line_number,
                line_start,
                f"timestamp {timestamp} follows {last_timestamp}",
            )
        source_sequences[source_id] = source_seq
        last_timestamp = timestamp
        observations += 1

    if line_number == 0:
        raise ParseFailure("line 1, byte 0: stream is empty")
    assert session_id is not None
    return {
        "session_id": session_id,
        "bytes": byte_offset,
        "lines": line_number,
        "dictionary_entries": dictionary_entries,
        "dictionary_bytes": dictionary_bytes,
        "observations": observations,
        "sources": len(source_sequences),
    }


def validate_header(record: dict[str, object], line: int, offset: int) -> str:
    """Validate the mandatory first stream record."""

    expected = {
        "schema": "t32perf.observation/v1",
        "encoding": "ndjson",
        "time_unit": "ns",
        "time_origin": "session_relative",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            fail(line, offset, f"header {key} must be {value!r}")
    unknown = set(record) - HEADER_FIELDS
    if unknown:
        fail(line, offset, f"unknown header fields: {sorted(unknown)!r}")
    if not isinstance(record.get("session_id"), str) or not record["session_id"]:
        fail(line, offset, "header session_id must be a non-empty string")
    properties = record.get("properties")
    if properties is not None and not isinstance(properties, dict):
        fail(line, offset, "header properties must be an object")
    return str(record["session_id"])


def validate_dictionary_entry(
    record: dict[str, object],
    namespaces: dict[str, set[str]],
    line: int,
    offset: int,
) -> None:
    """Validate one dictionary definition before the observation stream starts."""

    entry_type = record.get("type")
    assert isinstance(entry_type, str) and entry_type in DICTIONARY_TYPES
    unknown = set(record) - DICTIONARY_FIELDS[entry_type]
    if unknown:
        fail(line, offset, f"unknown dictionary fields: {sorted(unknown)!r}")
    missing = DICTIONARY_REQUIRED[entry_type] - set(record)
    if missing:
        fail(line, offset, f"missing dictionary fields: {sorted(missing)!r}")
    entry_id = record.get("id")
    if not isinstance(entry_id, str) or not entry_id:
        fail(line, offset, "dictionary entry id must be non-empty")
    name = record.get("name")
    if not isinstance(name, str) or not name:
        fail(line, offset, "dictionary entry name must be non-empty")
    if entry_type == "DefineContext" and record.get("kind") not in {
        "task",
        "isr",
        "idle",
        "core",
        "unknown",
    }:
        fail(line, offset, "dictionary context kind is invalid")
    if entry_id in namespaces[entry_type]:
        fail(line, offset, f"duplicate {entry_type} id {entry_id!r}")
    namespaces[entry_type].add(entry_id)


def reject_nonfinite(value: str) -> NoReturn:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""

    raise ParseFailure(f"non-finite number {value}")


def is_integer(value: object) -> bool:
    """Return true for JSON integers but not booleans."""

    return isinstance(value, int) and not isinstance(value, bool)


def fail(line: int, offset: int, message: str) -> NoReturn:
    """Raise a location-rich parser failure."""

    raise ParseFailure(f"line {line}, byte {offset}: {message}")


def peak_rss_bytes() -> int | None:
    """Return peak resident memory using only the Python standard library."""

    if os.name == "nt":

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("page_fault_count", ctypes.c_ulong),
                ("peak_working_set_size", ctypes.c_size_t),
                ("working_set_size", ctypes.c_size_t),
                ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                ("quota_paged_pool_usage", ctypes.c_size_t),
                ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                ("quota_non_paged_pool_usage", ctypes.c_size_t),
                ("pagefile_usage", ctypes.c_size_t),
                ("peak_pagefile_usage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        get_current_process = ctypes.windll.kernel32.GetCurrentProcess
        get_current_process.restype = ctypes.c_void_p
        get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        get_process_memory_info.restype = ctypes.c_int
        process = get_current_process()
        if get_process_memory_info(process, ctypes.byref(counters), counters.cb):
            return int(counters.peak_working_set_size)
        return None

    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1024)
    except (ImportError, OSError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--max-line-bytes", type=int, default=1024 * 1024)
    parser.add_argument(
        "--max-dictionary-entries",
        type=int,
        default=DEFAULT_MAX_DICTIONARY_ENTRIES,
    )
    parser.add_argument(
        "--max-dictionary-bytes",
        type=int,
        default=DEFAULT_MAX_DICTIONARY_BYTES,
    )
    arguments = parser.parse_args()
    if arguments.max_line_bytes <= 0:
        parser.error("--max-line-bytes must be positive")
    if not 0 < arguments.max_dictionary_entries <= HARD_MAX_DICTIONARY_ENTRIES:
        parser.error(
            "--max-dictionary-entries must be between 1 and "
            f"{HARD_MAX_DICTIONARY_ENTRIES}"
        )
    if not 0 < arguments.max_dictionary_bytes <= HARD_MAX_DICTIONARY_BYTES:
        parser.error(
            f"--max-dictionary-bytes must be between 1 and {HARD_MAX_DICTIONARY_BYTES}"
        )

    started = time.perf_counter()
    try:
        with arguments.input.open("rb") as stream:
            statistics = parse_stream(
                stream,
                arguments.max_line_bytes,
                arguments.max_dictionary_entries,
                arguments.max_dictionary_bytes,
            )
    except (OSError, ParseFailure) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - started
    observations = statistics["observations"]
    byte_count = statistics["bytes"]
    result = {
        "ok": True,
        "candidate": "python-stdlib",
        **statistics,
        "max_dictionary_entries": arguments.max_dictionary_entries,
        "max_dictionary_bytes": arguments.max_dictionary_bytes,
        "elapsed_seconds": elapsed,
        "observations_per_second": observations / elapsed if elapsed else math.inf,
        "bytes_per_second": byte_count / elapsed if elapsed else math.inf,
        "peak_rss_bytes": peak_rss_bytes(),
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
