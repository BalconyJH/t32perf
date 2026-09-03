"""Input types for the explicitly intrusive stack-sampling sidecar."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import OPERATION_ID_RE, SESSION_ID_RE, SHA256_RE, InputError


@dataclass(frozen=True)
class StackCaptureRequest:
    session_id: str
    operation_id: str
    acknowledge_intrusive: bool
    sample_period_ms: int
    duration_ms: int
    max_samples: int
    max_frames: int
    core_id: int
    address_space: str
    deployed_firmware_elf_sha256: str | None

    @classmethod
    def parse(cls, value: dict[str, Any]) -> StackCaptureRequest:
        allowed = {
            "session_id",
            "operation_id",
            "acknowledge_intrusive",
            "sample_period_ms",
            "duration_ms",
            "max_samples",
            "max_frames",
            "core_id",
            "address_space",
            "deployed_firmware_elf_sha256",
        }
        if set(value) - allowed:
            raise InputError("unsupported input fields")
        session_id, operation_id = value.get("session_id"), value.get("operation_id")
        if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
            raise InputError("session_id must be a portable session identifier")
        if not isinstance(operation_id, str) or not OPERATION_ID_RE.fullmatch(
            operation_id
        ):
            raise InputError("operation_id must be 32 lowercase hexadecimal characters")
        if value.get("acknowledge_intrusive") is not True:
            raise InputError("acknowledge_intrusive must be exactly true")
        bounds = {
            "sample_period_ms": (10, 1000),
            "duration_ms": (100, 60_000),
            "max_samples": (1, 512),
            "max_frames": (1, 8),
            "core_id": (0, 0),
        }
        parsed: dict[str, int] = {}
        for name, (low, high) in bounds.items():
            candidate = value.get(name)
            if (
                not isinstance(candidate, int)
                or isinstance(candidate, bool)
                or not low <= candidate <= high
            ):
                if name == "core_id":
                    raise InputError("core_id is fixed to 0 by stack sampling v1")
                raise InputError(f"{name} must be an integer from {low} to {high}")
            parsed[name] = candidate
        if value.get("address_space") != "P":
            raise InputError("address_space is fixed to P")
        digest = value.get("deployed_firmware_elf_sha256")
        if digest is not None and (
            not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)
        ):
            raise InputError(
                "deployed_firmware_elf_sha256 must be 64 lowercase hexadecimal characters"
            )
        return cls(
            session_id,
            operation_id,
            True,
            **parsed,
            address_space="P",
            deployed_firmware_elf_sha256=digest,
        )

    def authorization_document(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema": "t32perf.stack-capture-request/v1",
            "acknowledge_intrusive": True,
            "sample_period_ms": self.sample_period_ms,
            "duration_ms": self.duration_ms,
            "max_samples": self.max_samples,
            "max_frames": self.max_frames,
            "core_id": self.core_id,
            "address_space": "P",
        }
        if self.deployed_firmware_elf_sha256 is not None:
            result["deployed_firmware_elf_sha256"] = self.deployed_firmware_elf_sha256
        return result
