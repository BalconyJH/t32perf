"""Bounded request and result types for the sampling-only endpoint."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

MAX_RANGES = 256
MAX_BUCKETS = 256
MAX_DURATION_MS = 60_000
MAX_BUCKET_SIZE = 0x100000
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
OPERATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PROBE_IDENTITY_COMPONENT_LENGTH = 256
ENDPOINT_FINGERPRINT_SCHEME_V2 = "t32perf.endpoint-fingerprint/v2"


class InputError(ValueError):
    """A caller supplied a value outside the sampling protocol."""


@dataclass(frozen=True)
class AddressRange:
    start: int
    end: int

    def split(self, bucket_size: int) -> list[tuple[int, int]]:
        return [
            (start, min(start + bucket_size, self.end))
            for start in range(self.start, self.end, bucket_size)
        ]


@dataclass(frozen=True)
class CaptureRequest:
    session_id: str
    operation_id: str
    ranges: tuple[AddressRange, ...]
    bucket_size: int
    duration_ms: int
    method_policy: str
    core_id: int
    address_space: str
    deployed_firmware_elf_sha256: str | None

    @classmethod
    def parse(cls, arguments: dict[str, Any]) -> CaptureRequest:
        allowed = {
            "session_id",
            "operation_id",
            "ranges",
            "bucket_size",
            "duration_ms",
            "method_policy",
            "core_id",
            "address_space",
            "deployed_firmware_elf_sha256",
        }
        unknown = set(arguments) - allowed
        if unknown:
            raise InputError(f"unsupported input fields: {', '.join(sorted(unknown))}")
        session_id = arguments.get("session_id")
        if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
            raise InputError("session_id must be a portable session identifier")
        operation_id = arguments.get("operation_id")
        if not isinstance(operation_id, str) or not OPERATION_ID_RE.fullmatch(
            operation_id
        ):
            raise InputError("operation_id must be 32 lowercase hexadecimal characters")
        ranges_value = arguments.get("ranges")
        if not isinstance(ranges_value, list) or not (
            1 <= len(ranges_value) <= MAX_RANGES
        ):
            raise InputError(f"ranges must contain 1 to {MAX_RANGES} intervals")
        ranges: list[AddressRange] = []
        for item in ranges_value:
            if not isinstance(item, dict) or set(item) != {
                "start_address",
                "end_address",
            }:
                raise InputError("each range needs only start_address and end_address")
            start, end = item["start_address"], item["end_address"]
            if not _is_u64(start) or not _is_u64(end) or start >= end:
                raise InputError("ranges must be non-empty uint64 half-open intervals")
            ranges.append(AddressRange(start=start, end=end))
        ranges.sort(key=lambda item: item.start)
        if any(left.end > right.start for left, right in pairwise(ranges)):
            raise InputError("ranges must be pairwise non-overlapping")
        bucket_size = arguments.get("bucket_size")
        if (
            not isinstance(bucket_size, int)
            or isinstance(bucket_size, bool)
            or not 1 <= bucket_size <= MAX_BUCKET_SIZE
        ):
            raise InputError(
                f"bucket_size must be an integer from 1 to {MAX_BUCKET_SIZE}"
            )
        bucket_count = sum(
            (item.end - item.start + bucket_size - 1) // bucket_size for item in ranges
        )
        if bucket_count > MAX_BUCKETS:
            raise InputError(f"bucket_size creates more than {MAX_BUCKETS} buckets")
        duration_ms = arguments.get("duration_ms")
        if (
            not isinstance(duration_ms, int)
            or isinstance(duration_ms, bool)
            or not 1 <= duration_ms <= MAX_DURATION_MS
        ):
            raise InputError(
                f"duration_ms must be an integer from 1 to {MAX_DURATION_MS}"
            )
        method_policy = arguments.get("method_policy", "realtime_only")
        if method_policy not in {"realtime_only", "allow_stop_and_go"}:
            raise InputError("method_policy must be realtime_only or allow_stop_and_go")
        core_id = arguments.get("core_id", 0)
        if (
            not isinstance(core_id, int)
            or isinstance(core_id, bool)
            or not 0 <= core_id <= 0xFFFFFFFF
        ):
            raise InputError("core_id must be a uint32")
        address_space = arguments.get("address_space", "P")
        if address_space != "P":
            raise InputError("address_space is fixed to P for PC sampling")
        deployed_firmware_elf_sha256: str | None = None
        if "deployed_firmware_elf_sha256" in arguments:
            candidate = arguments["deployed_firmware_elf_sha256"]
            if not isinstance(candidate, str) or not SHA256_RE.fullmatch(candidate):
                raise InputError(
                    "deployed_firmware_elf_sha256 must be 64 lowercase hexadecimal characters"
                )
            deployed_firmware_elf_sha256 = candidate
        return cls(
            session_id,
            operation_id,
            tuple(ranges),
            bucket_size,
            duration_ms,
            method_policy,
            core_id,
            address_space,
            deployed_firmware_elf_sha256,
        )

    def buckets(self) -> list[tuple[int, int]]:
        return [
            bucket
            for address_range in self.ranges
            for bucket in address_range.split(self.bucket_size)
        ]

    def authorization_document(self) -> dict[str, Any]:
        """Exact Host request contract required before touching TRACE32."""
        document: dict[str, Any] = {
            "schema": "t32perf.sampling-capture-request/v1",
            "ranges": [
                {"start_address": item.start, "end_address": item.end}
                for item in self.ranges
            ],
            "bucket_size": self.bucket_size,
            "duration_ms": self.duration_ms,
            "method_policy": self.method_policy,
            "core_id": self.core_id,
            "address_space": self.address_space,
        }
        if self.deployed_firmware_elf_sha256 is not None:
            document["deployed_firmware_elf_sha256"] = self.deployed_firmware_elf_sha256
        return document


def _is_u64(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 0xFFFFFFFFFFFFFFFF
    )


def probe_fingerprint(
    debug_module_serial: str, cable_serial: str, debug_port: str
) -> str:
    """Hash stable probe identity without exposing TRACE32 serial values."""
    components = (debug_module_serial, cable_serial, debug_port)
    if any(
        not isinstance(component, str)
        or not 0 < len(component.strip()) <= MAX_PROBE_IDENTITY_COMPONENT_LENGTH
        for component in components
    ):
        raise InputError("TRACE32 probe identity is unreadable")
    canonical = json.dumps(
        [
            "t32perf.probe-fingerprint/v1",
            *(component.strip() for component in components),
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def endpoint_fingerprint(
    host: str, port: int, protocol: str, software: str, observed_probe_fingerprint: str
) -> str:
    """Return the v2 endpoint identity, bound to the observed TRACE32 probe."""
    if not isinstance(observed_probe_fingerprint, str) or not SHA256_RE.fullmatch(
        observed_probe_fingerprint
    ):
        raise InputError("observed_probe_fingerprint must be a SHA-256 digest")
    canonical = json.dumps(
        [
            ENDPOINT_FINGERPRINT_SCHEME_V2,
            protocol.upper(),
            host.strip().lower(),
            port,
            software.strip(),
            observed_probe_fingerprint,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def legacy_endpoint_fingerprint(
    host: str, port: int, protocol: str, software: str
) -> str:
    """Reproduce the development-only v1 endpoint digest for recovery.

    New captures must never use this unbound identity.  It exists solely to
    identify a quarantined v1 journal after a v2 probe-bound observation has
    already matched an operator-provided current pin.
    """
    canonical = f"{protocol.upper()}://{host.strip().lower()}:{port}/{software.strip()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_loopback_tcp_endpoint(host: str, protocol: str) -> tuple[str, str]:
    """Return the v1-allowed endpoint or reject it before RCL is contacted."""
    normalized_protocol = protocol.strip().upper()
    if normalized_protocol != "TCP":
        raise InputError("sampling sidecar v1 only permits TCP")
    candidate = host.strip().lower()
    if candidate == "localhost":
        return candidate, normalized_protocol
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as error:
        raise InputError("sampling sidecar v1 only permits loopback hosts") from error
    if not address.is_loopback:
        raise InputError("sampling sidecar v1 only permits loopback hosts")
    return candidate, normalized_protocol


def canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def schema_path() -> Path:
    return Path(__file__).with_name("schemas") / "pc-hit-histogram.schema.json"


def control_schema_path(name: str) -> Path:
    return Path(__file__).with_name("schemas") / name
