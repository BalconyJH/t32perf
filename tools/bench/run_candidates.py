#!/usr/bin/env python3
"""Run Rust and Python canonical parser candidates with external RSS sampling."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from python_candidate import (
    DEFAULT_MAX_DICTIONARY_BYTES,
    DEFAULT_MAX_DICTIONARY_ENTRIES,
    HARD_MAX_DICTIONARY_BYTES,
    HARD_MAX_DICTIONARY_ENTRIES,
)

EVIDENCE_FORMAT = "t32perf-parser-candidates-v1"
RUST_CANDIDATE = "rust-t32perf-trace32"
PYTHON_CANDIDATE = "python-stdlib"
CACHE_CONDITIONING = "sha256-prepass"
CANDIDATE_ORDER = [RUST_CANDIDATE, PYTHON_CANDIDATE]


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous candidate JSON before adding runner measurements."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key `{key}`")
        result[key] = value
    return result


def child_working_set_bytes(process: subprocess.Popen[bytes]) -> int | None:
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

        process_query_information = 0x0400
        process_vm_read = 0x0010
        open_process = ctypes.windll.kernel32.OpenProcess
        open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        open_process.restype = ctypes.c_void_p
        close_handle = ctypes.windll.kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        get_process_memory_info.restype = ctypes.c_int
        handle = open_process(
            process_query_information | process_vm_read, False, process.pid
        )
        if not handle:
            return None
        try:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if get_process_memory_info(handle, ctypes.byref(counters), counters.cb):
                return int(counters.peak_working_set_size)
            return None
        finally:
            close_handle(handle)

    status = Path(f"/proc/{process.pid}/status")
    try:
        for line in status.read_text(encoding="ascii").splitlines():
            if line.startswith(("VmHWM:", "VmRSS:")):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def run_candidate(command: list[str], sample_interval: float) -> dict[str, object]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        peak = 0
        while process.poll() is None:
            current = child_working_set_bytes(process)
            if current is not None:
                peak = max(peak, current)
            time.sleep(sample_interval)
        current = child_working_set_bytes(process)
        if current is not None:
            peak = max(peak, current)
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read().decode("utf-8")
        diagnostics = stderr.read().decode("utf-8")
    if process.returncode != 0:
        raise RuntimeError(
            f"candidate exited with {process.returncode}: {diagnostics.strip()}"
        )
    lines = output.splitlines()
    if len(lines) != 1:
        raise RuntimeError("candidate did not emit exactly one JSON object")
    try:
        result = json.loads(lines[0], object_pairs_hook=reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"candidate emitted invalid JSON: {error}") from error
    if not isinstance(result, dict):
        raise TypeError("candidate JSON root must be an object")
    if result.get("ok") is not True:
        raise RuntimeError(f"candidate reported failure: {result!r}")
    result["peak_rss_bytes_external"] = peak or None
    result["rss_sample_interval_ms"] = round(sample_interval * 1000)
    return result


def executable_default(workspace: Path) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return workspace / "target" / "release" / "examples" / f"ndjson_candidate{suffix}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stat_identity(path: Path) -> tuple[int, int, int, int]:
    metadata = path.stat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def fingerprint_input(path: Path) -> tuple[int, str]:
    """Hash a stable regular file and return its byte count plus digest."""

    before = stat_identity(path)
    digest = sha256_file(path)
    after = stat_identity(path)
    if before != after:
        raise RuntimeError("benchmark input changed while hashing")
    return before[2], digest


def verify_input_unchanged(
    path: Path, *, expected_bytes: int, expected_sha256: str
) -> None:
    """Require the post-candidate input fingerprint to match the prepass."""

    actual_bytes, actual_sha256 = fingerprint_input(path)
    if actual_bytes != expected_bytes or actual_sha256 != expected_sha256:
        raise RuntimeError("benchmark input changed while candidates were running")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).parents[2])
    parser.add_argument("--rust-executable", type=Path)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
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
    if arguments.sample_interval_ms <= 0:
        parser.error("--sample-interval-ms must be positive")
    if not 0 < arguments.max_dictionary_entries <= HARD_MAX_DICTIONARY_ENTRIES:
        parser.error(
            "--max-dictionary-entries must be between 1 and "
            f"{HARD_MAX_DICTIONARY_ENTRIES}"
        )
    if not 0 < arguments.max_dictionary_bytes <= HARD_MAX_DICTIONARY_BYTES:
        parser.error(
            f"--max-dictionary-bytes must be between 1 and {HARD_MAX_DICTIONARY_BYTES}"
        )
    workspace = arguments.workspace.resolve(strict=True)
    input_path = arguments.input.resolve(strict=True)
    rust_executable = (
        arguments.rust_executable or executable_default(workspace)
    ).resolve(strict=True)
    interval = arguments.sample_interval_ms / 1000
    limit_arguments = [
        "--max-dictionary-entries",
        str(arguments.max_dictionary_entries),
        "--max-dictionary-bytes",
        str(arguments.max_dictionary_bytes),
    ]
    input_bytes, input_sha256 = fingerprint_input(input_path)
    results = [
        run_candidate(
            [str(rust_executable), str(input_path), *limit_arguments], interval
        ),
        run_candidate(
            [
                sys.executable,
                str(workspace / "tools" / "bench" / "python_candidate.py"),
                str(input_path),
                *limit_arguments,
            ],
            interval,
        ),
    ]
    verify_input_unchanged(
        input_path,
        expected_bytes=input_bytes,
        expected_sha256=input_sha256,
    )
    source_commit = os.environ.get("GITHUB_SHA")
    runner_image = os.environ.get("ImageOS")
    runner_image_version = os.environ.get("ImageVersion")
    print(
        json.dumps(
            {
                "format": EVIDENCE_FORMAT,
                "ok": True,
                "input": str(input_path),
                "input_bytes": input_bytes,
                "input_sha256": input_sha256,
                "cache_conditioning": CACHE_CONDITIONING,
                "candidate_order": CANDIDATE_ORDER,
                "input_integrity_verified": True,
                "max_dictionary_entries": arguments.max_dictionary_entries,
                "max_dictionary_bytes": arguments.max_dictionary_bytes,
                "environment": {
                    "os": platform.platform(),
                    "arch": platform.machine(),
                    "python": platform.python_version(),
                    "source_commit": source_commit,
                    "runner_image": runner_image,
                    "runner_image_version": runner_image_version,
                },
                "results": results,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
