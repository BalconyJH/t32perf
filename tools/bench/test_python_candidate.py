from __future__ import annotations

import io
import json
import unittest

from python_candidate import ParseFailure, parse_stream, peak_rss_bytes


def stream(*records: dict[str, object]) -> io.BytesIO:
    payload = b"".join(
        json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n"
        for record in records
    )
    return io.BytesIO(payload)


def header() -> dict[str, object]:
    return {
        "schema": "t32perf.observation/v1",
        "session_id": "test",
        "encoding": "ndjson",
        "time_unit": "ns",
        "time_origin": "session_relative",
    }


def function_definition() -> dict[str, object]:
    return {
        "type": "DefineFunction",
        "id": "marker-function",
        "name": "marker",
    }


def resource_counter_definition() -> dict[str, object]:
    return {
        "type": "DefineCounter",
        "id": "heap-current",
        "name": "Heap current allocated",
        "unit": "bytes",
        "semantic": "heap.current_allocated_bytes",
        "subject": {"kind": "allocator", "allocator_id": "system-heap"},
    }


def instant(sequence: int, timestamp: int) -> dict[str, object]:
    return {
        "source_id": "source",
        "source_seq": sequence,
        "quality": "exact",
        "type": "Instant",
        "ts_ns": timestamp,
        "name": "marker",
    }


class GeneratedStream:
    def __init__(self, dictionary_entries: int, observations: int) -> None:
        self.dictionary_entries = dictionary_entries
        self.observations = observations
        self.next_record = 0

    def readline(self, limit: int = -1) -> bytes:
        total = 1 + self.dictionary_entries + self.observations
        if self.next_record >= total:
            return b""
        record = self.next_record
        self.next_record += 1
        if record == 0:
            value = header()
        elif record <= self.dictionary_entries:
            index = record - 1
            value = {
                "type": "DefineFunction",
                "id": f"function-{index}",
                "name": f"namespace::function_{index}",
            }
        else:
            index = record - self.dictionary_entries - 1
            value = instant(index, index)
        line = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
        if limit >= 0 and len(line) > limit:
            return line[:limit]
        return line


class CandidateTests(unittest.TestCase):
    def test_valid_stream(self) -> None:
        result = parse_stream(
            stream(header(), function_definition(), instant(0, 0)), 4096
        )
        self.assertEqual(result["observations"], 1)
        self.assertEqual(result["dictionary_entries"], 1)

    def test_zero_dictionary_entries_are_valid(self) -> None:
        result = parse_stream(stream(header(), instant(0, 0)), 4096)
        self.assertEqual(result["dictionary_entries"], 0)

    def test_resource_counter_semantic_fields_are_accepted(self) -> None:
        result = parse_stream(
            stream(header(), resource_counter_definition(), instant(0, 0)), 4096
        )
        self.assertEqual(result["dictionary_entries"], 1)

    def test_dictionary_entry_after_observation_is_rejected(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "follows observations"):
            parse_stream(stream(header(), instant(0, 0), function_definition()), 4096)

    def test_duplicate_dictionary_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "duplicate DefineFunction"):
            parse_stream(
                stream(header(), function_definition(), function_definition()), 4096
            )

    def test_dictionary_entry_limit_is_independent_from_observations(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "entry count exceeds 1"):
            parse_stream(
                stream(header(), function_definition(), resource_counter_definition()),
                4096,
                max_dictionary_entries=1,
            )

    def test_dictionary_physical_byte_limit_reports_crossing(self) -> None:
        payload = stream(header(), function_definition())
        lines = payload.getvalue().splitlines(keepends=True)
        expected_offset = len(lines[0]) + len(lines[1]) - 1
        with self.assertRaisesRegex(
            ParseFailure,
            f"line 2, byte {expected_offset}: dictionary physical bytes exceed",
        ):
            parse_stream(
                io.BytesIO(b"".join(lines)),
                4096,
                max_dictionary_bytes=len(lines[1]) - 1,
            )

    def test_dictionary_hard_limits_are_rejected(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "max_dictionary_entries"):
            parse_stream(stream(header()), 4096, max_dictionary_entries=0)
        with self.assertRaisesRegex(ParseFailure, "max_dictionary_bytes"):
            parse_stream(stream(header()), 4096, max_dictionary_bytes=2**40)

    def test_million_observations_do_not_accumulate_with_large_dictionary(self) -> None:
        dictionary_entries = 20_000
        observations = 1_000_000
        result = parse_stream(
            GeneratedStream(dictionary_entries, observations),
            4096,
            max_dictionary_entries=dictionary_entries,
            max_dictionary_bytes=8 * 1024 * 1024,
        )
        self.assertEqual(result["dictionary_entries"], dictionary_entries)
        self.assertEqual(result["observations"], observations)
        peak = peak_rss_bytes()
        if peak is not None:
            self.assertLess(peak, 128 * 1024 * 1024)

    def test_unknown_field_is_rejected(self) -> None:
        event = instant(0, 0)
        event["unexpected"] = True
        with self.assertRaisesRegex(ParseFailure, "unknown fields"):
            parse_stream(stream(header(), event), 4096)

    def test_unknown_header_field_and_nested_duplicate_are_rejected(self) -> None:
        invalid_header = header()
        invalid_header["future"] = True
        with self.assertRaisesRegex(ParseFailure, "unknown header fields"):
            parse_stream(stream(invalid_header), 4096)

        payload = (
            json.dumps(header(), separators=(",", ":")).encode("utf-8")
            + b"\n"
            + b'{"source_id":"source","source_seq":0,"quality":"exact",'
            + b'"type":"Instant","ts_ns":0,"name":"marker",'
            + b'"args":{"mode":"first","mode":"last"}}\n'
        )
        with self.assertRaisesRegex(ParseFailure, "duplicate JSON object member"):
            parse_stream(io.BytesIO(payload), 4096)

    def test_reports_validated_session_identity(self) -> None:
        result = parse_stream(stream(header(), instant(0, 0)), 4096)
        self.assertEqual(result["session_id"], "test")

    def test_order_is_strict(self) -> None:
        with self.assertRaisesRegex(ParseFailure, "source sequence"):
            parse_stream(
                stream(header(), instant(1, 1), instant(1, 2)),
                4096,
            )


if __name__ == "__main__":
    unittest.main()
