from __future__ import annotations

import hashlib
import io
import tracemalloc
import unittest
from pathlib import Path

from trace32_export_candidate import ParseFailure, parse_ascii, parse_task_events

FIXTURES = (
    Path(__file__).parents[2]
    / "crates"
    / "t32perf-trace32"
    / "tests"
    / "fixtures"
    / "trace32"
)


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class Trace32ExportCandidateTests(unittest.TestCase):
    def test_tc234l_ascii_fixture_is_streamed_with_p_class(self) -> None:
        payload = fixture("snooper-tc234l-simulator-build190766.txt")
        result = parse_ascii(
            io.BytesIO(payload), max_line_bytes=4096, address_classes=frozenset({"P"})
        )
        self.assertEqual(result["records"], 3)
        self.assertEqual(result["first_timestamp_ns"], 0)
        self.assertEqual(result["input_sha256"], hashlib.sha256(payload).hexdigest())

    def test_x86_ascii_fixture_accepts_crlf_and_requires_its_class(self) -> None:
        payload = fixture("snooper-x86-simulator-build190766.txt").replace(
            b"\n", b"\r\n"
        )
        result = parse_ascii(
            io.BytesIO(payload), max_line_bytes=4096, address_classes=frozenset({"C"})
        )
        self.assertEqual(result["records"], 6)
        self.assertEqual(result["symbolled_records"], 3)
        with self.assertRaisesRegex(ParseFailure, "unsupported Address class"):
            parse_ascii(
                io.BytesIO(payload),
                max_line_bytes=4096,
                address_classes=frozenset({"P"}),
            )

    def test_taskevents_vendor_fixture_has_fixed_closed_counts(self) -> None:
        payload = fixture("taskevents-r2026.02-vendor-sample.csv")
        result = parse_task_events(io.BytesIO(payload), max_line_bytes=4096)
        self.assertEqual(result["records"], 5)
        self.assertEqual(result["event_counts"]["switch"], 2)
        self.assertEqual(result["event_counts"]["start"], 1)
        self.assertEqual(result["event_counts"]["stop"], 1)
        self.assertEqual(result["event_counts"]["terminate"], 1)
        self.assertEqual(len(result["event_counts"]), 14)

    def test_unknown_event_and_trace_record_dialect_fail_closed(self) -> None:
        header = b"########\n# Task events trace file\n# time(ns); task name; event;\n########\n"
        with self.assertRaisesRegex(ParseFailure, "unsupported TASKEVENTS event"):
            parse_task_events(
                io.BytesIO(header + b"0; Task; unknown;\n"), max_line_bytes=4096
            )
        with self.assertRaisesRegex(ParseFailure, "exactly three TASKEVENTS"):
            parse_task_events(
                io.BytesIO(header + b"0; 1; Task; switch;\n"), max_line_bytes=4096
            )

    def test_truncation_timestamp_order_and_ascii_cycle_fail_closed(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "truncated final line"):
            parse_ascii(
                io.BytesIO(b"+1 P:70100000 snoop 0.000000000s symbol"),
                max_line_bytes=4096,
                address_classes=frozenset({"P"}),
            )
        with self.assertRaisesRegex(ParseFailure, "unsupported CYcle"):
            parse_ascii(
                io.BytesIO(b"+1 P:70100000 cycle 0.000000000s symbol\n"),
                max_line_bytes=4096,
                address_classes=frozenset({"P"}),
            )
        header = b"########\n# Task events trace file\n# time(ns); task name; event;\n########\n"
        with self.assertRaisesRegex(ParseFailure, "moves backwards"):
            parse_task_events(
                io.BytesIO(header + b"1; Task; switch;\n0; Task; start;\n"),
                max_line_bytes=4096,
            )

    def test_one_million_ascii_records_are_streamed(self) -> None:
        class GeneratedAscii:
            def __init__(self, records: int) -> None:
                self.index = 0
                self.records = records

            def readline(self, limit: int = -1) -> bytes:
                if self.index >= self.records:
                    return b""
                self.index += 1
                return (
                    f"+{self.index} P:70100000 snoop "
                    f"{self.index // 1_000_000_000}."
                    f"{self.index % 1_000_000_000:09d}s symbol\n"
                ).encode()

        result = parse_ascii(
            GeneratedAscii(1_000_000),
            max_line_bytes=4096,
            address_classes=frozenset({"P"}),
        )
        self.assertEqual(result["records"], 1_000_000)
        self.assertEqual(result["symbolled_records"], 1_000_000)

    def test_traced_memory_does_not_grow_with_record_count(self) -> None:
        class GeneratedAscii:
            def __init__(self, records: int) -> None:
                self.index = 0
                self.records = records

            def readline(self, limit: int = -1) -> bytes:
                if self.index >= self.records:
                    return b""
                self.index += 1
                return f"+{self.index} P:70100000 snoop 0.000000000s symbol\n".encode()

        def peak_for(records: int) -> int:
            tracemalloc.start()
            try:
                parse_ascii(
                    GeneratedAscii(records),
                    max_line_bytes=4096,
                    address_classes=frozenset({"P"}),
                )
                _, peak = tracemalloc.get_traced_memory()
                return peak
            finally:
                tracemalloc.stop()

        small_peak = peak_for(1_000)
        large_peak = peak_for(100_000)
        self.assertLess(large_peak, 1024 * 1024)
        self.assertLess(large_peak - small_peak, 128 * 1024)


if __name__ == "__main__":
    unittest.main()
