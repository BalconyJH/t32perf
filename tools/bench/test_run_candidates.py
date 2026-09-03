from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from run_candidates import (
    fingerprint_input,
    run_candidate,
    sha256_file,
    verify_input_unchanged,
)


class CandidateRunnerTests(unittest.TestCase):
    def test_sha256_file_streams_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.bin"
            path.write_bytes(b"benchmark-evidence")
            self.assertEqual(
                sha256_file(path),
                "03eeb74e4f183e94225c7dfeac04b97033763bcf03afaf497c7c2d9366cf15e3",
            )

    def test_input_fingerprint_detects_candidate_time_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.ndjson"
            path.write_bytes(b"original input")
            byte_count, digest = fingerprint_input(path)

            verify_input_unchanged(
                path,
                expected_bytes=byte_count,
                expected_sha256=digest,
            )
            path.write_bytes(b"modified input")

            with self.assertRaisesRegex(RuntimeError, "candidates were running"):
                verify_input_unchanged(
                    path,
                    expected_bytes=byte_count,
                    expected_sha256=digest,
                )

    def test_runner_accepts_one_success_object(self) -> None:
        result = run_candidate(
            [
                sys.executable,
                "-c",
                "import json; print(json.dumps({'ok': True, 'candidate': 'mock'}))",
            ],
            0.01,
        )
        self.assertEqual(result["candidate"], "mock")
        self.assertEqual(result["rss_sample_interval_ms"], 10)

    def test_runner_rejects_failure_and_multiple_objects(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exited with 3"):
            run_candidate([sys.executable, "-c", "raise SystemExit(3)"], 0.01)
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            run_candidate([sys.executable, "-c", "print('{}'); print('{}')"], 0.01)
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON key"):
            run_candidate(
                [sys.executable, "-c", 'print(\'{"ok":true,"ok":false}\')'],
                0.01,
            )


if __name__ == "__main__":
    unittest.main()
