"""Deliberately intrusive, bounded Break/Frame.Up stack sampler."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import lauterbach.trace32.rcl as t32
from jsonschema import Draft202012Validator

from .model import (
    ENDPOINT_FINGERPRINT_SCHEME_V2,
    SHA256_RE,
    InputError,
    canonical_json,
    endpoint_fingerprint,
    normalize_loopback_tcp_endpoint,
    probe_fingerprint,
)
from .stack_model import StackCaptureRequest
from .stack_storage import StackJournal, StackSessionLease, publish_stack_samples
from .storage import ExecutionLease, StorageError


class StackSamplingError(RuntimeError):
    pass


class StackSamplingCancelled(StackSamplingError):
    pass


class StackSamplingService:
    # TRACE32 RCL is local-only for this sidecar.  A short socket timeout and a
    # separate, tighter halt budget keep a stuck frame walk from extending a
    # target stop indefinitely.
    MAX_RCL_TIMEOUT_SECONDS = 0.100
    HALT_DEADLINE_SECONDS = 1.000

    def __init__(
        self,
        *,
        host: str,
        port: int,
        protocol: str,
        timeout: float,
        artifact_root: Path,
        expected_endpoint_fingerprint: str | None = None,
        recover_quarantined: bool = False,
        connector: Callable[..., Any] = t32.connect,
    ) -> None:
        self.host, self.protocol = normalize_loopback_tcp_endpoint(host, protocol)
        self.port, self.timeout, self.artifact_root = (
            port,
            min(timeout, self.MAX_RCL_TIMEOUT_SECONDS),
            ExecutionLease(artifact_root).root,
        )
        if expected_endpoint_fingerprint is not None and (
            not isinstance(expected_endpoint_fingerprint, str)
            or not SHA256_RE.fullmatch(expected_endpoint_fingerprint)
        ):
            raise InputError("expected_endpoint_fingerprint must be a SHA-256 digest")
        self.expected_endpoint_fingerprint, self.recover_quarantined, self.connector = (
            expected_endpoint_fingerprint,
            recover_quarantined,
            connector,
        )
        self.validator = Draft202012Validator(
            __import__("json").loads(
                (
                    Path(__file__).with_name("schemas") / "stack-samples.schema.json"
                ).read_text(encoding="utf-8")
            )
        )

    def _debugger(self) -> Any:
        return self.connector(
            node=self.host,
            port=str(self.port),
            protocol=self.protocol,
            timeout=self.timeout,
        )

    @staticmethod
    def _software(debugger: Any) -> str:
        try:
            return f"{debugger.fnc.software_version()}+{int(debugger.fnc.software_build())}"
        except Exception:  # noqa: BLE001 - optional build number
            return str(debugger.fnc.software_version())

    @staticmethod
    def _probe(debugger: Any) -> str:
        try:
            return probe_fingerprint(
                *(
                    str(debugger.fnc(expression))
                    for expression in (
                        "VERSION.SERIAL.DEBUG()",
                        "VERSION.SERIAL.CABLE()",
                        "SYStem.CONFIG.DEBUGPORT()",
                    )
                )
            )
        except Exception:  # noqa: BLE001 - capability probe
            return "unknown"

    @staticmethod
    def _state(debugger: Any) -> dict[str, bool]:
        try:
            state = {
                "powered": debugger.fnc.state_power(),
                "running": debugger.fnc.state_run(),
                "halted": debugger.fnc.state_halt(),
            }
        except Exception as error:
            raise StackSamplingError("target execution state is unreadable") from error
        if not all(type(value) is bool for value in state.values()):
            raise StackSamplingError("target execution state is unreadable")
        return state

    @staticmethod
    def _debugger_error_state(debugger: Any) -> dict[str, Any]:
        """Read TRACE32's sticky error slot without ever normalizing it away."""
        try:
            occurred_value = debugger.fnc("ERROR.OCCURRED()")
            error_id_value = debugger.fnc("ERROR.ID()")
        except Exception as error:
            raise StackSamplingError("TRACE32 ERROR state is unreadable") from error
        if type(occurred_value) is not bool:
            raise StackSamplingError("TRACE32 ERROR occurrence state is unreadable")
        if not isinstance(error_id_value, str):
            raise StackSamplingError("TRACE32 ERROR identifier is unreadable")
        # TRACE32 can return padded fixed-width strings. NULs and surrounding
        # whitespace are transport artifacts, not part of an ERROR identifier.
        error_id = error_id_value.replace("\0", "").strip()
        return {
            "occurred": occurred_value,
            "id": error_id,
        }

    def _require_clean_debugger_error(self, debugger: Any, context: str) -> None:
        error = self._debugger_error_state(debugger)
        if error != {"occurred": False, "id": ""}:
            raise StackSamplingError(
                f"TRACE32 ERROR is set {context}: {error['id'] or '<unnamed>'}"
            )

    def _clear_expected_noframe_after_go(self, debugger: Any) -> None:
        """Clear only the Frame.Up terminal marker after the owned Go completed."""
        if not self._wait_running(debugger, True, self.MAX_RCL_TIMEOUT_SECONDS):
            raise StackSamplingError(
                "TRACE32 go did not restore target running before ERROR validation"
            )
        error = self._debugger_error_state(debugger)
        if error != {"occurred": True, "id": "#emu_noframe"}:
            raise StackSamplingError(
                "TRACE32 ERROR changed after Frame.Up; refusing to clear it"
            )
        try:
            debugger.cmd("ERROR.RESet")
        except Exception as reset_error:
            raise StackSamplingError(
                "TRACE32 expected Frame.Up ERROR reset failed"
            ) from reset_error
        self._require_clean_debugger_error(debugger, "after expected Frame.Up reset")

    @staticmethod
    def _verify_single_core_zero(debugger: Any) -> None:
        try:
            count = int(debugger.fnc.core_number())
            selected = int(debugger.fnc.core())
        except Exception as error:
            raise StackSamplingError("TRACE32 core selection is unreadable") from error
        if count != 1 or selected != 0:
            raise StackSamplingError(
                "stack sampling v1 requires exactly one TRACE32 logical core selected as 0"
            )

    @staticmethod
    def _wait_running(debugger: Any, wanted: bool, timeout: float = 1.0) -> bool:
        """Bounded poll: RCL may report HALT false while a break is effective."""
        deadline = time.monotonic() + min(timeout, 1.0)
        while True:
            try:
                if debugger.fnc.state_run() is wanted:
                    return True
            except Exception as error:
                raise StackSamplingError(
                    "target execution state is unreadable"
                ) from error
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def capabilities(self) -> dict[str, Any]:
        with ExecutionLease(self.artifact_root), self._debugger() as debugger:
            self._verify_single_core_zero(debugger)
            state = self._state(debugger)
            error_state = self._debugger_error_state(debugger)
            software, probe = self._software(debugger), self._probe(debugger)
            endpoint = (
                endpoint_fingerprint(
                    self.host, self.port, self.protocol, software, probe
                )
                if probe != "unknown"
                else "unknown"
            )
            return {
                "schema": "t32perf.stack-sampling-capabilities/v1",
                "target": state,
                "debugger_error_state": error_state,
                "cpu": str(debugger.fnc.state_processor()),
                "method": "break_frame_walk",
                "intrusive": True,
                "endpoint_fingerprint": endpoint,
                "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
                "supported_core_ids": [0],
                "single_core_evidence": {"logical_core_count": 1, "selected_core": 0},
                "safety_budget": {
                    "max_rcl_timeout_ms": int(self.MAX_RCL_TIMEOUT_SECONDS * 1000),
                    "frame_walk_deadline_ms": int(self.HALT_DEADLINE_SECONDS * 1000),
                    "max_frames": 8,
                },
            }

    def recover_only(self) -> dict[str, Any]:
        """Consume one explicit authorization without starting a new capture."""
        if self.expected_endpoint_fingerprint is None:
            raise StackSamplingError(
                "stack recovery requires a pinned expected endpoint fingerprint"
            )
        authorized = self.recover_quarantined
        self.recover_quarantined = False
        if not authorized:
            raise StackSamplingError(
                "stack recovery requires a fresh --recover-quarantined authorization"
            )
        with ExecutionLease(self.artifact_root), self._debugger() as debugger:
            self._verify_single_core_zero(debugger)
            software, probe = self._software(debugger), self._probe(debugger)
            if probe == "unknown":
                raise StackSamplingError(
                    "stack recovery requires a readable TRACE32 probe fingerprint"
                )
            endpoint = endpoint_fingerprint(
                self.host, self.port, self.protocol, software, probe
            )
            if endpoint != self.expected_endpoint_fingerprint:
                raise StackSamplingError(
                    "observed TRACE32 endpoint does not match the pinned fingerprint"
                )
            journal = StackJournal(self.artifact_root, endpoint)
            journal.require_recovered(
                debugger,
                authorized=True,
                running=lambda: self._wait_running(debugger, True),
            )
            state = self._state(debugger)
            if not state["powered"] or not state["running"] or state["halted"]:
                raise StackSamplingError(
                    "stack recovery completed no owned Go and target is not running"
                )
            # Journal ownership proves only that Go is authorized. It does not
            # prove who created TRACE32's process-global ERROR slot, even when
            # the ID happens to be #emu_noframe. Preserve and report it.
            error_state = self._debugger_error_state(debugger)
            return {
                "endpoint_fingerprint": endpoint,
                "target": state,
                "debugger_error_state": error_state,
                "recovery_authorization_consumed": True,
            }

    def capture(
        self, request: StackCaptureRequest, cancel_event: threading.Event | None = None
    ) -> dict[str, Any]:
        cancel_event = cancel_event or threading.Event()
        if self.expected_endpoint_fingerprint is None:
            raise StackSamplingError(
                "stack_sampling_capture requires a pinned expected endpoint fingerprint"
            )
        with ExecutionLease(self.artifact_root), self._debugger() as debugger:
            self._verify_single_core_zero(debugger)
            software, probe = self._software(debugger), self._probe(debugger)
            if probe == "unknown":
                raise StackSamplingError(
                    "stack capture requires a readable TRACE32 probe fingerprint"
                )
            endpoint = endpoint_fingerprint(
                self.host, self.port, self.protocol, software, probe
            )
            if endpoint != self.expected_endpoint_fingerprint:
                raise StackSamplingError(
                    "observed TRACE32 endpoint does not match the pinned fingerprint"
                )
            with StackSessionLease(self.artifact_root, request) as session:
                staging = session.staging
                journal = StackJournal(self.artifact_root, endpoint)
                journal.require_recovered(
                    debugger,
                    authorized=False,
                    running=lambda: self._wait_running(debugger, True),
                )
                if debugger.fnc.perf_state() != 0:
                    raise StackSamplingError(
                        "PERF is already active; refusing intrusive stack capture"
                    )
                before = self._state(debugger)
                if not before["powered"] or not before["running"] or before["halted"]:
                    raise StackSamplingError(
                        "stack_sampling_capture requires an already powered, running, non-halted target"
                    )
                self._require_clean_debugger_error(
                    debugger, "before intrusive stack capture"
                )
                # Consumed before the first durable Break intent. The marker is
                # permanent even when capture is cancelled or export fails.
                session.consume(endpoint)
                return self._capture_leased(
                    debugger,
                    request,
                    endpoint,
                    software,
                    staging,
                    journal,
                    before,
                    cancel_event,
                )

    def _capture_leased(
        self,
        debugger: Any,
        request: StackCaptureRequest,
        endpoint: str,
        software: str,
        staging: Path,
        journal: StackJournal,
        before: dict[str, bool],
        cancel_event: threading.Event,
    ) -> dict[str, Any]:
        tx, samples, total_halt, attempted = str(uuid.uuid4()), [], 0, 0
        journal.reserve_transaction(tx, request.max_samples)
        started = time.monotonic_ns()
        end = started + request.duration_ms * 1_000_000
        journal.append(
            tx,
            "capture_intent",
            {
                "initial_running": True,
                "duration_ms": request.duration_ms,
                "sample_period_ms": request.sample_period_ms,
                "max_samples": request.max_samples,
                "max_frames": request.max_frames,
            },
        )
        primary: Exception | None = None
        restored = False
        owns_halt = False
        symbol_cache: dict[int, dict[str, Any]] = {}
        try:
            while attempted < request.max_samples and time.monotonic_ns() < end:
                self._raise_if_cancelled(cancel_event)
                current = self._state(debugger)
                if (
                    not current["powered"]
                    or not current["running"]
                    or current["halted"]
                ):
                    raise StackSamplingError(
                        "target changed state before intrusive Break; refusing to resume it"
                    )
                attempted += 1
                journal.append(tx, "break_intent", {"sample_index": attempted})
                self._raise_if_cancelled(cancel_event)
                cycle_started = time.monotonic_ns()
                halt_deadline = time.monotonic() + self.HALT_DEADLINE_SECONDS
                # The durable Break intent and immediately preceding running
                # check authorize exactly this cleanup Go. Set ownership before
                # the RCL call because a lost response can still halt the core.
                owns_halt = True
                debugger.break_()
                if not self._wait_running(
                    debugger, False, max(0.0, halt_deadline - time.monotonic())
                ):
                    raise StackSamplingError(
                        "TRACE32 break did not stop target before timeout"
                    )
                journal.append(tx, "break_observed", {"sample_index": attempted})
                frames, terminal = self._frames(
                    debugger, request.max_frames, halt_deadline, cancel_event
                )
                journal.append(tx, "go_intent", {"sample_index": attempted})
                debugger.go()
                if not self._wait_running(debugger, True, self.MAX_RCL_TIMEOUT_SECONDS):
                    raise StackSamplingError(
                        "TRACE32 go did not restore target running before timeout"
                    )
                duration = max(1, time.monotonic_ns() - cycle_started)
                total_halt += duration
                # The target is proven running. A later journal failure must not
                # authorize an extra Go that could race with an external stop.
                owns_halt = False
                journal.append(tx, "go_observed", {"sample_index": attempted})
                if terminal == "terminal_unverified":
                    self._clear_expected_noframe_after_go(debugger)
                if not frames:
                    raise StackSamplingError(
                        f"stack frame walk ended without a frame: {terminal}"
                    )
                samples.append(
                    {
                        "sample_index": attempted,
                        "frames": frames,
                        "termination": terminal,
                        "halt_cycle_duration_ns": duration,
                    }
                )
                self._symbolize(debugger, frames, symbol_cache, cancel_event)
                self._require_clean_debugger_error(debugger, "after symbolization")
                self._raise_if_cancelled(cancel_event)
                remaining = end - time.monotonic_ns()
                if attempted < request.max_samples and remaining > 0:
                    self._wait_interval(
                        min(request.sample_period_ms * 1_000_000, remaining),
                        cancel_event,
                    )
            journal.append(
                tx,
                "capture_observed",
                {"attempted_samples": attempted, "collected_samples": len(samples)},
            )
            final = self._state(debugger)
            if not final["powered"] or not final["running"] or final["halted"]:
                raise StackSamplingError(
                    "target stopped externally during stack capture cleanup; refusing to resume it"
                )
            journal.append(tx, "cleanup_intent", {})
            journal.append(tx, "cleanup_observed", {})
            restored = True
        except Exception as error:
            primary = error
            if isinstance(error, (OSError, StorageError)):
                try:
                    journal.mark_failure(error)
                except (OSError, StorageError):
                    pass
            journal.release_transaction(tx)
            raise
        finally:
            if not restored:
                external_stop = False
                if not owns_halt:
                    final = self._state(debugger)
                    external_stop = (
                        not final["powered"] or not final["running"] or final["halted"]
                    )
                if external_stop:
                    # The last durable state already proves our Go completed.
                    # Do not append a recovery-looking transition or issue Go.
                    pass
                else:
                    journal_error: Exception | None = None
                    try:
                        journal.append(tx, "cleanup_intent", {})
                    except Exception as error:  # noqa: BLE001 - Go is more important than journaling
                        journal_error = error
                    try:
                        # A durable journal failure must never prevent recovery of a
                        # halt this cycle owns, but must never resume an external halt.
                        if owns_halt:
                            # Do not spend a full poll window before issuing the
                            # matching Go: stdio cancellation gives this worker a
                            # finite grace period before its process is killed.
                            debugger.go()
                        if owns_halt and not self._wait_running(
                            debugger, True, self.MAX_RCL_TIMEOUT_SECONDS
                        ):
                            raise StackSamplingError(
                                "target is not running after stack cleanup"
                            )
                        if not owns_halt:
                            final = self._state(debugger)
                            if (
                                not final["powered"]
                                or not final["running"]
                                or final["halted"]
                            ):
                                raise StackSamplingError(
                                    "target stopped externally during failure cleanup; refusing to resume it"
                                )
                        if journal_error is None:
                            journal.append(tx, "cleanup_observed", {})
                    except Exception as cleanup_error:
                        try:
                            journal.append(
                                tx,
                                "cleanup_failed",
                                {"error": type(cleanup_error).__name__},
                            )
                        except Exception:  # noqa: BLE001,S110 - marker remains authoritative
                            pass
                        journal.mark_failure(cleanup_error)
                        if primary is None:
                            raise StackSamplingError(
                                "stack cleanup failed; capture quarantined"
                            ) from cleanup_error
                    if journal_error is not None:
                        journal.mark_failure(journal_error)
                        if primary is None:
                            raise StackSamplingError(
                                "stack journal failed; capture quarantined"
                            ) from journal_error
        after = self._state(debugger)
        raw = {
            "schema": "t32perf.stack-samples/v1",
            "session_id": request.session_id,
            "endpoint_fingerprint": endpoint,
            "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
            "trace32": software,
            "cpu": str(debugger.fnc.state_processor()),
            "core_id": request.core_id,
            "address_space": "P",
            "method": "break_frame_walk",
            "intrusive": True,
            "frame_order": "leaf_to_root",
            "requested_duration_ms": request.duration_ms,
            "observed_duration_ms": max(
                1, (time.monotonic_ns() - started) // 1_000_000
            ),
            "requested_sample_period_ms": request.sample_period_ms,
            "max_samples": request.max_samples,
            "max_frames": request.max_frames,
            "attempted_samples": attempted,
            "collected_samples": len(samples),
            "total_halt_cycle_duration_ns": total_halt,
            "target_state_before": before,
            "target_state_after": after,
            "firmware": {"status": "unverified"},
            "cleanup_complete": True,
            "debugger_symbolization_source": "trace32_symbol_table",
            "debugger_symbolization_trust": "debugger_reported",
            "samples": samples,
        }
        errors = list(self.validator.iter_errors(raw))
        if errors:
            raise StackSamplingError(
                f"stack sample schema validation failed: {errors[0].message}"
            )
        try:
            self._require_clean_debugger_error(debugger, "before publishing capture")
            journal.append(tx, "export_intent", {})
            artifact = publish_stack_samples(
                staging, request.session_id, canonical_json(raw)
            )
            journal.append(tx, "export_observed", artifact)
            return {
                "summary": {
                    "attempted_samples": attempted,
                    "collected_samples": len(samples),
                    "total_halt_cycle_duration_ns": total_halt,
                    "cleanup_complete": True,
                },
                "artifact": artifact,
            }
        except (OSError, StorageError) as error:
            try:
                journal.mark_failure(error)
            except (OSError, StorageError):
                pass
            raise
        finally:
            journal.release_transaction(tx)

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            raise StackSamplingCancelled("stack capture cancelled")

    def _wait_interval(self, duration_ns: int, cancel_event: threading.Event) -> None:
        if cancel_event.wait(duration_ns / 1_000_000_000):
            raise StackSamplingCancelled("stack capture cancelled")

    def _frames(
        self,
        debugger: Any,
        maximum: int,
        halt_deadline: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        halt_deadline = halt_deadline or (time.monotonic() + self.HALT_DEADLINE_SECONDS)
        cancel_event = cancel_event or threading.Event()
        frames: list[dict[str, Any]] = []
        seen: set[tuple[int, int]] = set()
        successful_up = 0
        try:
            for depth in range(maximum):
                self._raise_if_cancelled(cancel_event)
                if time.monotonic() >= halt_deadline:
                    return frames, "halt_deadline"
                try:
                    pc = int(str(debugger.fnc("Register(PC)")), 0)
                except Exception:  # noqa: BLE001 - target read failure is data
                    return frames, "pc_read_failed"
                try:
                    sp = int(str(debugger.fnc("Register(SP)")), 0)
                except Exception:  # noqa: BLE001 - SP is optional only for cycle detection
                    sp = None
                if sp is not None and (pc, sp) in seen:
                    return frames, "frame_cycle"
                if sp is not None:
                    seen.add((pc, sp))
                frames.append({"depth": len(frames), "pc": pc})
                if depth + 1 == maximum:
                    return frames, "max_frames"
                # Before changing virtual frame state, reserve enough bounded
                # RCL calls to restore every successful Up and issue Go.
                cleanup_budget = (successful_up + 3) * self.MAX_RCL_TIMEOUT_SECONDS
                if time.monotonic() + cleanup_budget >= halt_deadline:
                    return frames, "halt_deadline"
                self._raise_if_cancelled(cancel_event)
                try:
                    debugger.cmd("Frame.Up")
                except Exception as frame_error:
                    error = self._debugger_error_state(debugger)
                    if error == {"occurred": True, "id": "#emu_noframe"}:
                        return frames, "terminal_unverified"
                    raise StackSamplingError(
                        "Frame.Up failed without the expected #emu_noframe ERROR"
                    ) from frame_error
                successful_up += 1
            raise AssertionError("frame loop must return")
        finally:
            # The virtual frame selector is global to the PowerView session.
            # Restore it even when cancellation interrupts a later walk step.
            for _ in range(successful_up):
                debugger.cmd("Frame.Down")

    def _symbolize(
        self,
        debugger: Any,
        frames: list[dict[str, Any]],
        cache: dict[int, dict[str, Any]],
        cancel_event: threading.Event,
    ) -> None:
        for frame in frames:
            self._raise_if_cancelled(cancel_event)
            pc = frame["pc"]
            symbol = cache.get(pc)
            if symbol is None:
                symbol = {}
                try:
                    label = self._label(debugger.fnc(f"sYmbol.FUNCTION(P:0x{pc:x})"))
                    if label is not None:
                        symbol["function_name"] = label
                    source = self._basename(
                        debugger.fnc(f"sYmbol.SOURCEFILE(P:0x{pc:x})")
                    )
                    line = int(str(debugger.fnc(f"sYmbol.SOURCELINE(P:0x{pc:x})")), 0)
                    if source is not None and line > 0:
                        symbol["source_file"] = source
                        symbol["source_line"] = line
                except Exception:  # noqa: BLE001,S110 - optional debugger symbols
                    pass
                cache[pc] = symbol
            frame.update(symbol)

    @staticmethod
    def _basename(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        name = value.replace("\\", "/").rsplit("/", 1)[-1]
        if not name or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in name):
            return None
        return name.encode("utf-8")[:256].decode("utf-8", "ignore") or None

    @staticmethod
    def _label(value: Any) -> str | None:
        if (
            not isinstance(value, str)
            or not value
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
        ):
            return None
        # Rust's contract limits UTF-8 bytes, never emit a split code point.
        encoded = value.replace("\\", "/").rsplit("/", 1)[-1].encode("utf-8")
        return encoded[:256].decode("utf-8", "ignore") or None
