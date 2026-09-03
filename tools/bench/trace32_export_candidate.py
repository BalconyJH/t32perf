#!/usr/bin/env python3
"""Strict streaming candidate for the two TRACE32 vendor text dialects.

This is benchmark tooling only.  It validates raw vendor exports and emits
bounded evidence; it does not create canonical observations or replace the
Rust normalization adapters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

EVIDENCE_FORMAT = "t32perf-trace32-export-candidate/v1"
ASCII_FORMAT = (
    "trace32.export-ascii/"
    "snooper-single-core-show-record-address-cycle-time-zero-symbol/v1"
)
TASK_EVENTS_FORMAT = "trace32.export-taskevents/time-name-event-no-trace-record/v1"
TASK_EVENTS = (
    "activate",
    "schedule",
    "start",
    "stop",
    "terminate",
    "preempt",
    "resume",
    "wait",
    "release",
    "switch",
    "runnablestart",
    "runnablestop",
    "isrstart",
    "isrend",
)
TASK_EVENT_SET = frozenset(TASK_EVENTS)
MAX_I64 = (1 << 63) - 1
MIN_I64 = -(1 << 63)
MAX_U64 = (1 << 64) - 1
ASCII_ROW = re.compile(
    rb"^[ \t]*([+-]?\d+)[ \t]+([A-Za-z]):([0-9A-Fa-f]+)"
    rb"[ \t]+([A-Za-z]+)[ \t]+([+-]?\d+)\.(\d{9})s"
    rb"(?:[ \t]+(.+))?$"
)


class ParseFailure(ValueError):
    """A fail-closed vendor export validation error."""


class StreamingLines:
    """Bound vendor text rows, preserve physical offsets, and hash input bytes."""

    def __init__(self, stream: BinaryIO, max_line_bytes: int) -> None:
        if max_line_bytes <= 0:
            raise ParseFailure("max_line_bytes must be positive")
        self.stream = stream
        self.max_line_bytes = max_line_bytes
        self.digest = hashlib.sha256()
        self.byte_count = 0
        self.line_number = 0

    def __iter__(self) -> Iterator[tuple[int, int, bytes]]:
        while raw := self.stream.readline(self.max_line_bytes + 1):
            line_start = self.byte_count
            self.digest.update(raw)
            self.byte_count += len(raw)
            self.line_number += 1
            if len(raw) > self.max_line_bytes and not raw.endswith(b"\n"):
                self.fail(line_start, "line exceeds configured byte limit")
            if not raw.endswith(b"\n"):
                self.fail(line_start, "truncated final line without LF or CRLF")
            content = raw[:-1]
            if content.endswith(b"\r"):
                content = content[:-1]
            elif b"\r" in content:
                self.fail(line_start, "bare CR is not a valid vendor line ending")
            yield self.line_number, line_start, content

    def fail(self, offset: int, message: str) -> None:
        raise ParseFailure(f"line {self.line_number}, byte {offset}: {message}")


def checked_int(value: bytes, *, minimum: int, maximum: int, label: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise ParseFailure(f"{label} is not a decimal integer") from error
    if not minimum <= parsed <= maximum:
        raise ParseFailure(f"{label} is outside the supported integer range")
    return parsed


def checked_hex_u64(value: bytes, *, label: str) -> int:
    try:
        parsed = int(value, 16)
    except ValueError as error:
        raise ParseFailure(f"{label} is not a hexadecimal integer") from error
    if not 0 <= parsed <= MAX_U64:
        raise ParseFailure(f"{label} is outside the unsigned 64-bit range")
    return parsed


def checked_time_ns(seconds: bytes, fraction: bytes) -> int:
    negative = seconds.startswith(b"-")
    absolute_seconds = seconds[1:] if seconds[:1] in {b"+", b"-"} else seconds
    whole = checked_int(absolute_seconds, minimum=0, maximum=MAX_I64, label="seconds")
    nanos = checked_int(fraction, minimum=0, maximum=999_999_999, label="fraction")
    result = whole * 1_000_000_000 + nanos
    if result > MAX_I64 + int(negative):
        raise ParseFailure("TIme.Zero is outside the signed nanosecond range")
    return -result if negative else result


def parse_ascii(
    stream: BinaryIO, *, max_line_bytes: int, address_classes: frozenset[str]
) -> dict[str, object]:
    """Validate the fixed SNOOPer profile without retaining rows or symbols."""

    if not address_classes:
        raise ParseFailure("at least one ASCII Address class is required")
    lines = StreamingLines(stream, max_line_bytes)
    records = 0
    symbolled_records = 0
    first_timestamp_ns: int | None = None
    last_timestamp_ns: int | None = None
    previous_record: int | None = None
    for line_number, offset, row in lines:
        match = ASCII_ROW.fullmatch(row)
        if match is None:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: expected fixed SNOOPer "
                "ShowRecord Address CYcle TIme.Zero sYmbol row"
            )
        record = checked_int(
            match.group(1), minimum=MIN_I64, maximum=MAX_I64, label="ShowRecord"
        )
        address_class = match.group(2).decode("ascii")
        if address_class not in address_classes:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: unsupported Address class "
                f"{address_class!r}"
            )
        checked_hex_u64(match.group(3), label="Address")
        if match.group(4) != b"snoop":
            raise ParseFailure(
                f"line {line_number}, byte {offset}: unsupported CYcle "
                f"{match.group(4).decode('ascii', 'backslashreplace')!r}"
            )
        timestamp = checked_time_ns(match.group(5), match.group(6))
        if previous_record is not None and record <= previous_record:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: ShowRecord is not strictly increasing"
            )
        if last_timestamp_ns is not None and timestamp < last_timestamp_ns:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: TIme.Zero moves backwards"
            )
        if match.group(7) is not None:
            try:
                match.group(7).decode("utf-8")
            except UnicodeDecodeError as error:
                raise ParseFailure(
                    f"line {line_number}, byte {offset + error.start}: invalid UTF-8 symbol"
                ) from error
            symbolled_records += 1
        first_timestamp_ns = (
            timestamp if first_timestamp_ns is None else first_timestamp_ns
        )
        last_timestamp_ns = timestamp
        previous_record = record
        records += 1
    if records == 0:
        raise ParseFailure("line 1, byte 0: export contains no SNOOPer records")
    return evidence(
        lines,
        input_format=ASCII_FORMAT,
        records=records,
        first_timestamp_ns=first_timestamp_ns,
        last_timestamp_ns=last_timestamp_ns,
        extra={"symbolled_records": symbolled_records},
    )


def parse_task_events(stream: BinaryIO, *, max_line_bytes: int) -> dict[str, object]:
    """Validate no-/TRaceRecord TASKEVENTS rows with a closed event vocabulary."""

    lines = StreamingLines(stream, max_line_bytes)
    iterator = iter(lines)
    header = []
    for expected_line in range(1, 5):
        try:
            header.append(next(iterator))
        except StopIteration as error:
            raise ParseFailure(
                f"line {expected_line}, byte 0: truncated TASKEVENTS header"
            ) from error
    _, first_offset, opening = header[0]
    _, title_offset, title = header[1]
    _, columns_offset, columns = header[2]
    _, closing_offset, closing = header[3]
    if len(opening) < 8 or opening != b"#" * len(opening) or closing != opening:
        raise ParseFailure(
            f"line 1, byte {first_offset}: invalid TASKEVENTS rule header"
        )
    if title != b"# Task events trace file":
        raise ParseFailure(f"line 2, byte {title_offset}: invalid TASKEVENTS title")
    if columns != b"# time(ns); task name; event;":
        raise ParseFailure(f"line 3, byte {columns_offset}: invalid TASKEVENTS columns")
    if not closing:
        raise ParseFailure(
            f"line 4, byte {closing_offset}: invalid TASKEVENTS closing rule"
        )

    records = 0
    event_counts = dict.fromkeys(TASK_EVENTS, 0)
    first_timestamp_ns: int | None = None
    last_timestamp_ns: int | None = None
    for line_number, offset, row in iterator:
        fields = row.split(b";")
        if len(fields) != 4 or fields[3].strip(b" \t"):
            raise ParseFailure(
                f"line {line_number}, byte {offset}: expected exactly three TASKEVENTS "
                "fields and one empty trailing field"
            )
        timestamp = checked_int(
            fields[0].strip(b" \t"), minimum=MIN_I64, maximum=MAX_I64, label="time(ns)"
        )
        name = fields[1].strip(b" \t")
        event_bytes = fields[2].strip(b" \t")
        try:
            event = event_bytes.decode("ascii")
            name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ParseFailure(
                f"line {line_number}, byte {offset + error.start}: invalid UTF-8 field"
            ) from error
        if event not in TASK_EVENT_SET:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: unsupported TASKEVENTS event {event!r}"
            )
        if not name and not (records == 0 and event == "preempt"):
            raise ParseFailure(
                f"line {line_number}, byte {offset}: empty task name is only valid "
                "for the initial preempt boundary"
            )
        if last_timestamp_ns is not None and timestamp < last_timestamp_ns:
            raise ParseFailure(
                f"line {line_number}, byte {offset}: time(ns) moves backwards"
            )
        event_counts[event] += 1
        first_timestamp_ns = (
            timestamp if first_timestamp_ns is None else first_timestamp_ns
        )
        last_timestamp_ns = timestamp
        records += 1
    if records == 0:
        raise ParseFailure("line 5, byte 0: export contains no TASKEVENTS records")
    return evidence(
        lines,
        input_format=TASK_EVENTS_FORMAT,
        records=records,
        first_timestamp_ns=first_timestamp_ns,
        last_timestamp_ns=last_timestamp_ns,
        extra={"event_counts": event_counts},
    )


def evidence(
    lines: StreamingLines,
    *,
    input_format: str,
    records: int,
    first_timestamp_ns: int | None,
    last_timestamp_ns: int | None,
    extra: dict[str, object],
) -> dict[str, object]:
    """Create fixed-size evidence after the complete input was validated."""

    return {
        "format": EVIDENCE_FORMAT,
        "ok": True,
        "candidate": "python-stdlib-trace32-export",
        "input_format": input_format,
        "input_bytes": lines.byte_count,
        "input_sha256": lines.digest.hexdigest(),
        "lines": lines.line_number,
        "records": records,
        "first_timestamp_ns": first_timestamp_ns,
        "last_timestamp_ns": last_timestamp_ns,
        **extra,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=("ascii", "taskevents"))
    parser.add_argument("input", type=Path)
    parser.add_argument("--max-line-bytes", type=int, default=1024 * 1024)
    parser.add_argument(
        "--address-class",
        action="append",
        default=[],
        help="accepted SNOOPer Address class; required for ASCII and repeatable",
    )
    arguments = parser.parse_args()
    if arguments.max_line_bytes <= 0:
        parser.error("--max-line-bytes must be positive")
    if any(
        not value.isascii() or not value.isalnum() for value in arguments.address_class
    ):
        parser.error(
            "--address-class values must be non-empty ASCII alphanumeric tokens"
        )
    started = time.perf_counter()
    try:
        with arguments.input.open("rb") as stream:
            if arguments.format == "ascii":
                classes = frozenset(arguments.address_class or ["P"])
                result = parse_ascii(
                    stream,
                    max_line_bytes=arguments.max_line_bytes,
                    address_classes=classes,
                )
            else:
                if arguments.address_class:
                    parser.error("--address-class is only valid for ascii input")
                result = parse_task_events(
                    stream, max_line_bytes=arguments.max_line_bytes
                )
    except (OSError, ParseFailure) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    result["elapsed_seconds"] = time.perf_counter() - started
    result["records_per_second"] = result["records"] / result["elapsed_seconds"]
    print(json.dumps(result, separators=(",", ":"), sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
