"""Synchronous TRACE32 PERF transaction executed under one socket lease."""

from __future__ import annotations

import heapq
import json
import re
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
    CaptureRequest,
    InputError,
    canonical_json,
    endpoint_fingerprint,
    normalize_loopback_tcp_endpoint,
    probe_fingerprint,
    schema_path,
)
from .model import (
    legacy_endpoint_fingerprint as calculate_legacy_endpoint_fingerprint,
)
from .storage import (
    ExecutionLease,
    SamplingJournal,
    SessionCaptureLease,
    StorageError,
    publish_histogram,
    staging_directory,
)


class SamplingError(RuntimeError):
    pass


SYMBOLIZATION_GLOBAL_QUERY_BUDGET = 512
SYMBOLIZATION_PER_BUCKET_QUERY_BUDGET = 128


class SamplingService:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        protocol: str,
        timeout: float,
        artifact_root: Path,
        expected_endpoint_fingerprint: str | None = None,
        capture_deadline_ms: int = 65_000,
        recover_quarantined: bool = False,
        recover_legacy_only: bool = False,
        legacy_endpoint_fingerprint: str | None = None,
        connector: Callable[..., Any] = t32.connect,
    ) -> None:
        self.host, self.protocol = normalize_loopback_tcp_endpoint(host, protocol)
        self.port, self.timeout = (
            port,
            timeout,
        )
        self.artifact_root = ExecutionLease(artifact_root).root
        if expected_endpoint_fingerprint is not None and (
            not isinstance(expected_endpoint_fingerprint, str)
            or not SHA256_RE.fullmatch(expected_endpoint_fingerprint)
        ):
            raise InputError("expected_endpoint_fingerprint must be a SHA-256 digest")
        self.expected_endpoint_fingerprint = expected_endpoint_fingerprint
        if legacy_endpoint_fingerprint is not None and (
            not isinstance(legacy_endpoint_fingerprint, str)
            or not SHA256_RE.fullmatch(legacy_endpoint_fingerprint)
        ):
            raise InputError("legacy_endpoint_fingerprint must be a SHA-256 digest")
        self.recover_legacy_only = recover_legacy_only
        self.legacy_endpoint_fingerprint = legacy_endpoint_fingerprint
        self.connector = connector
        self.capture_deadline_ms = capture_deadline_ms
        self._recovery_authorization_available = recover_quarantined
        self._journal_failed = False
        self.validator = Draft202012Validator(
            json.loads(schema_path().read_text(encoding="utf-8"))
        )

    def recover_legacy_only_transaction(self) -> None:
        """Clean up a quarantined development-v1 journal, then exit.

        This deliberately has no capture path and is called only by the CLI
        before the MCP stdio server is created.
        """
        if not self.recover_legacy_only or not self._recovery_authorization_available:
            raise InputError(
                "legacy recovery requires --recover-legacy-only and --recover-quarantined"
            )
        if (
            self.expected_endpoint_fingerprint is None
            or self.legacy_endpoint_fingerprint is None
        ):
            raise InputError(
                "legacy recovery requires current and legacy endpoint fingerprints"
            )
        with ExecutionLease(self.artifact_root):
            # Validate the historical root before opening RCL. Legacy recovery
            # must not synthesize a binding or reach PERF for an unbound root.
            journal = SamplingJournal(
                self.artifact_root,
                self.legacy_endpoint_fingerprint,
                legacy_v1=True,
            )
            with self._debugger() as debugger:
                software = self._software(debugger)
                observed_probe_fingerprint = self._probe_fingerprint(debugger)
                if observed_probe_fingerprint == "unknown":
                    raise SamplingError(
                        "legacy recovery requires a readable TRACE32 probe fingerprint"
                    )
                current = endpoint_fingerprint(
                    self.host,
                    self.port,
                    self.protocol,
                    software,
                    observed_probe_fingerprint,
                )
                if current != self.expected_endpoint_fingerprint:
                    raise SamplingError(
                        "observed TRACE32 endpoint does not match the pinned fingerprint"
                    )
                legacy = calculate_legacy_endpoint_fingerprint(
                    self.host, self.port, self.protocol, software
                )
                if legacy != self.legacy_endpoint_fingerprint:
                    raise SamplingError(
                        "observed TRACE32 endpoint does not match the legacy fingerprint"
                    )
                journal.require_healthy(recover_journal_failure=True)
                journal.recover(
                    lambda: self._cleanup_and_verify(debugger), recover_quarantined=True
                )

    def capabilities(self) -> dict[str, Any]:
        with ExecutionLease(self.artifact_root), self._debugger() as debugger:
            return self._capabilities(debugger)

    def capture(self, request: CaptureRequest) -> dict[str, Any]:
        if self.recover_legacy_only:
            raise SamplingError(
                "legacy recovery-only service cannot perform sampling_capture"
            )
        if self.expected_endpoint_fingerprint is None:
            raise SamplingError(
                "sampling_capture requires a pinned expected endpoint fingerprint"
            )
        with ExecutionLease(self.artifact_root):  # noqa: SIM117 - lease must outlive socket cleanup
            with SessionCaptureLease(self.artifact_root, request):
                with self._debugger() as debugger:
                    software = self._software(debugger)
                    observed_probe_fingerprint = self._probe_fingerprint(debugger)
                    if observed_probe_fingerprint == "unknown":
                        raise SamplingError(
                            "sampling_capture requires a readable TRACE32 probe fingerprint"
                        )
                    fingerprint = endpoint_fingerprint(
                        self.host,
                        self.port,
                        self.protocol,
                        software,
                        observed_probe_fingerprint,
                    )
                    if fingerprint != self.expected_endpoint_fingerprint:
                        raise SamplingError(
                            "observed TRACE32 endpoint does not match the pinned fingerprint"
                        )
                    journal = SamplingJournal(self.artifact_root, fingerprint)
                    recovery_authorized = self._recovery_authorization_available
                    self._recovery_authorization_available = False
                    if self._journal_failed and not recovery_authorized:
                        raise SamplingError(
                            "sampling journal previously failed; restart with --recover-quarantined"
                        )
                    journal.require_healthy(recover_journal_failure=recovery_authorized)
                    try:
                        journal.recover(
                            lambda: self._cleanup_and_verify(debugger),
                            recover_quarantined=recovery_authorized,
                        )
                    except (OSError, StorageError) as error:
                        self._mark_journal_failure(journal, error)
                        raise
                    if recovery_authorized:
                        self._journal_failed = False
                    if debugger.fnc.perf_state() != 0:
                        raise SamplingError(
                            "PERF is already active; refusing a non-owned cleanup"
                        )
                    before = self._state_required(debugger)
                    if (
                        not before["powered"]
                        or not before["running"]
                        or before["halted"]
                    ):
                        raise SamplingError(
                            "sampling_capture requires an already powered, running, non-halted target"
                        )
                    method = self._select_method(
                        self._capabilities(debugger), request.method_policy
                    )
                    transaction_id = str(uuid.uuid4())
                    try:
                        journal.reserve_transaction(transaction_id)
                    except (OSError, StorageError) as error:
                        self._mark_journal_failure(journal, error)
                        raise
                    cleanup_required = False
                    cleanup_done = False
                    cleanup_intent_durable = False
                    cleanup_attempted = False
                    cleanup_attempt_error: Exception | None = None
                    primary_error: Exception | None = None
                    started_ns = time.monotonic_ns()
                    try:
                        self._append_journal(
                            journal,
                            transaction_id,
                            "configure_intent",
                            {"method": method},
                        )
                        cleanup_required = True
                        self._configure(debugger, method)
                        self._append_journal(
                            journal,
                            transaction_id,
                            "configure_observed",
                            {"method": method},
                        )
                        self._append_journal(
                            journal,
                            transaction_id,
                            "start_intent",
                            {"duration_ms": request.duration_ms},
                        )
                        arm_started_ns = time.monotonic_ns()
                        self._arm(debugger)
                        self._append_journal(journal, transaction_id, "start_observed")
                        time.sleep(request.duration_ms / 1000)
                        self._deadline(started_ns)
                        self._append_journal(journal, transaction_id, "stop_intent")
                        debugger.cmd("PERF.OFF")
                        observed_duration_ns = max(
                            1, time.monotonic_ns() - arm_started_ns
                        )
                        self._append_journal(journal, transaction_id, "stop_observed")
                        if debugger.fnc.perf_state() != 1:
                            raise SamplingError(
                                "TRACE32 PERF did not enter stopped result state"
                            )
                        draft = self._histogram(
                            debugger,
                            request,
                            before,
                            method,
                            observed_duration_ns,
                            started_ns,
                            fingerprint,
                            software,
                        )
                        self._append_journal(journal, transaction_id, "cleanup_intent")
                        cleanup_intent_durable = True
                        cleanup_attempted = True
                        try:
                            self._cleanup_and_verify(debugger)
                        except Exception as error:
                            cleanup_attempt_error = error
                            raise
                        self._append_journal(
                            journal, transaction_id, "cleanup_observed"
                        )
                        cleanup_done = True
                        result = {**draft, "cleanup_complete": True}
                        errors = list(self.validator.iter_errors(result))
                        if errors:
                            raise SamplingError(
                                f"histogram schema validation failed: {errors[0].message}"
                            )
                        self._append_journal(journal, transaction_id, "export_intent")
                        staged = publish_histogram(
                            staging_directory(self.artifact_root, request.session_id),
                            request.session_id,
                            canonical_json(result),
                        )
                        self._append_journal(
                            journal, transaction_id, "export_observed", staged
                        )
                        return {"histogram": result, "artifact": staged}
                    except Exception as error:
                        primary_error = error
                        raise
                    finally:
                        if cleanup_required and not cleanup_done:
                            cleanup_intent_error: OSError | StorageError | None = None
                            if not cleanup_intent_durable:
                                cleanup_intent_error = self._try_append_journal(
                                    journal, transaction_id, "cleanup_intent"
                                )
                                cleanup_intent_durable = cleanup_intent_error is None
                            journal_error = cleanup_intent_error
                            cleanup_error = cleanup_attempt_error
                            attempted_before_finally = cleanup_attempted
                            if not attempted_before_finally:
                                cleanup_attempted = True
                                try:
                                    self._cleanup_and_verify(debugger)
                                    cleanup_done = True
                                except Exception as error:  # noqa: BLE001 - cleanup boundary
                                    cleanup_error = error
                            if (
                                not attempted_before_finally
                                and cleanup_error is None
                                and cleanup_intent_error is None
                            ):
                                observed_error = self._try_append_journal(
                                    journal, transaction_id, "cleanup_observed"
                                )
                                journal_error = journal_error or observed_error
                            elif (
                                cleanup_error is not None
                                and cleanup_intent_error is None
                            ):
                                failed_error = self._try_append_journal(
                                    journal,
                                    transaction_id,
                                    "cleanup_failed",
                                    {"error": type(cleanup_error).__name__},
                                )
                                journal_error = journal_error or failed_error
                            if journal_error is not None or cleanup_error is not None:
                                if primary_error is not None:
                                    raise SamplingError(
                                        "sampling capture failed and cleanup requires recovery"
                                    ) from (cleanup_error or journal_error)
                                raise SamplingError(
                                    "PERF cleanup failed; capture remains blocked until --recover-quarantined"
                                ) from (cleanup_error or journal_error)
                        journal.release_transaction(transaction_id)

    def _mark_journal_failure(self, journal: SamplingJournal, error: Exception) -> None:
        self._journal_failed = True
        try:
            journal.mark_failure(error)
        except (OSError, StorageError):
            # The original journal error remains authoritative; cleanup still runs.
            pass

    def _append_journal(
        self,
        journal: SamplingJournal,
        transaction_id: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        try:
            journal.append(transaction_id, event, details)
        except (OSError, StorageError) as error:
            self._mark_journal_failure(journal, error)
            raise

    def _try_append_journal(
        self,
        journal: SamplingJournal,
        transaction_id: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> OSError | StorageError | None:
        try:
            journal.append(transaction_id, event, details)
        except (OSError, StorageError) as error:
            self._mark_journal_failure(journal, error)
            return error
        return None

    def _debugger(self) -> Any:
        return self.connector(
            node=self.host,
            port=str(self.port),
            protocol=self.protocol,
            timeout=self.timeout,
        )

    def _capabilities(self, debugger: Any) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for name, fn in {
            "powered": debugger.fnc.state_power,
            "running": debugger.fnc.state_run,
            "halted": debugger.fnc.state_halt,
            "cpu": debugger.fnc.state_processor,
            "pcsnoop": lambda: debugger.fnc.cpu_feature("PCSNOOP"),
            "perf_method_code": debugger.fnc.perf_method,
            "perf_mode_code": debugger.fnc.perf_mode,
            "perf_state_code": debugger.fnc.perf_state,
            "trace32": lambda: self._software(debugger),
        }.items():
            try:
                values[name] = fn()
            except (OSError, RuntimeError, t32.FunctionError):
                values[name] = "unknown"
        readable = values["powered"] is True
        pcsnoop = values["pcsnoop"] if readable else "unknown"
        software = values["trace32"]
        if not isinstance(software, str) or not software.strip():
            software = "unknown"
        observed_probe_fingerprint = self._probe_fingerprint(debugger)
        symbols_loaded = self._symbols_loaded(debugger)
        fingerprint = (
            endpoint_fingerprint(
                self.host,
                self.port,
                self.protocol,
                software,
                observed_probe_fingerprint,
            )
            if observed_probe_fingerprint != "unknown"
            else "unknown"
        )
        return {
            "schema": "t32perf.sampling-capabilities/v1",
            "target": {
                "powered": values["powered"],
                "running": values["running"],
                "halted": values["halted"],
            },
            "cpu": values["cpu"] if readable else "unknown",
            "pcsnoop": pcsnoop,
            "perf": {
                "method_code": values["perf_method_code"],
                "mode_code": values["perf_mode_code"],
                "state_code": values["perf_state_code"],
            },
            "trace32": software,
            "probe_fingerprint": observed_probe_fingerprint,
            "endpoint_fingerprint": fingerprint,
            "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
            "supported_methods": ["realtime", "stop_and_go"]
            if pcsnoop is True
            else (["stop_and_go"] if pcsnoop is False else []),
            "code_labels": {
                "supported": True,
                "source": "trace32_symbol_table",
                "trust": "debugger_reported",
                "symbols_loaded": symbols_loaded,
            },
        }

    @staticmethod
    def _symbols_loaded(debugger: Any) -> bool | str:
        try:
            value = debugger.fnc("sYmbol.List.PROGRAM.COUNT()>0")
        except Exception:  # noqa: BLE001 - read-only optional capability probe
            return "unknown"
        if type(value) is bool:
            return value
        if type(value) is int:
            return value > 0
        return "unknown"

    @staticmethod
    def _probe_fingerprint(debugger: Any) -> str:
        values: list[str] = []
        for expression in (
            "VERSION.SERIAL.DEBUG()",
            "VERSION.SERIAL.CABLE()",
            "SYStem.CONFIG.DEBUGPORT()",
        ):
            try:
                value = debugger.fnc(expression)
            except (OSError, RuntimeError, t32.FunctionError):
                return "unknown"
            if not isinstance(value, str):
                return "unknown"
            values.append(value)
        try:
            return probe_fingerprint(*values)
        except InputError:
            return "unknown"

    @staticmethod
    def _select_method(capability: dict[str, Any], policy: str) -> str:
        if capability["pcsnoop"] is True:
            return "realtime"
        if policy == "allow_stop_and_go" and capability["pcsnoop"] is False:
            return "stop_and_go"
        raise SamplingError(
            "RealTime PC snooping is unavailable; StopAndGo requires explicit allow_stop_and_go"
        )

    def _state_required(self, debugger: Any) -> dict[str, bool]:
        result = self._capabilities(debugger)["target"]
        if not all(
            isinstance(result[name], bool) for name in ("powered", "running", "halted")
        ):
            raise SamplingError("target execution state is unreadable")
        return result

    def _configure(self, debugger: Any, method: str) -> None:
        if debugger.fnc.perf_state() != 0:
            raise SamplingError("PERF must be disabled before capture")
        commands = [
            "PERF.RESet",
            "PERF.AutoArm OFF",
            "PERF.AutoInit OFF",
            "PERF.Mode PC",
            f"PERF.METHOD {'RealTime' if method == 'realtime' else 'StopAndGo'}",
        ]
        if method == "stop_and_go":
            commands.append("PERF.RunTimeLimit 99.")
        commands.append("PERF.Init")
        for command in commands:
            debugger.cmd(command)
        if debugger.fnc.perf_mode() != 1:
            raise SamplingError("TRACE32 did not select PERF PC mode")
        if debugger.fnc.perf_method() != (4 if method == "realtime" else 2):
            raise SamplingError("TRACE32 did not select the requested PERF method")

    @staticmethod
    def _arm(debugger: Any) -> None:
        debugger.cmd("PERF.Arm")

    def _histogram(
        self,
        debugger: Any,
        request: CaptureRequest,
        before: dict[str, bool],
        method: str,
        observed_duration_ns: int,
        capture_started_ns: int,
        fingerprint: str,
        software: str,
    ) -> dict[str, Any]:
        after = self._state_required(debugger)
        if after != before:
            raise SamplingError("target execution state drifted during sampling")
        rate = debugger.fnc.perf_rate()
        if not isinstance(rate, int) or rate <= 0:
            raise SamplingError("TRACE32 reported no usable PC sampling rate")
        buckets: list[dict[str, int]] = []
        for start, end in request.buckets():
            self._deadline(capture_started_ns)
            hits = debugger.fnc(
                f"PERF.PC.HITS(P:0x{start:x}--0x{end - 1:x}, {request.core_id}.)"
            )
            if not isinstance(hits, int) or hits < 0:
                raise SamplingError("TRACE32 returned an invalid PC hit count")
            buckets.append({"start_address": start, "end_address": end, "hits": hits})
        method_value: dict[str, Any] = {"kind": "realtime"}
        if method == "stop_and_go":
            observed_runtime = self._runtime_percent(debugger.fnc.perf_runtime())
            method_value = {
                "kind": "stop_and_go",
                "configured_retained_runtime_percent": 99.0,
                "observed_retained_runtime_percent": observed_runtime,
            }
        result = {
            "schema": "t32perf.pc-hit-histogram/v1",
            "session_id": request.session_id,
            "endpoint_fingerprint": fingerprint,
            "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
            "trace32": software,
            "cpu": str(debugger.fnc.state_processor()),
            "address_space": request.address_space,
            "core_id": request.core_id,
            "method": method_value,
            "intrusive": method == "stop_and_go",
            "requested_duration_ns": request.duration_ms * 1_000_000,
            "observed_duration_ns": observed_duration_ns,
            "last_sample_rate_hz": rate,
            "snoop_failures": debugger.fnc.perf_snoopfails(),
            "target_state_before": before,
            "target_state_after": after,
            "firmware": {"status": "unverified"},
            "in_scope_hits": sum(bucket["hits"] for bucket in buckets),
            "buckets": buckets,
        }
        debugger_symbolization = self._debugger_symbolization(
            debugger, request, buckets, capture_started_ns
        )
        if debugger_symbolization is not None:
            result["debugger_symbolization"] = debugger_symbolization
        return result

    def _debugger_symbolization(
        self,
        debugger: Any,
        request: CaptureRequest,
        buckets: list[dict[str, int]],
        capture_started_ns: int,
    ) -> dict[str, Any] | None:
        """Best-effort, debugger-reported labels for the hottest original buckets.

        PERF remains in its stopped result state throughout this work.  The
        histogram is authoritative; a failed refinement or symbol lookup only
        omits that optional label.
        """
        locations: list[dict[str, Any]] = []
        global_query_budget = [SYMBOLIZATION_GLOBAL_QUERY_BUDGET]
        candidates = sorted(
            (bucket for bucket in buckets if bucket["hits"] > 0),
            key=lambda bucket: (-bucket["hits"], bucket["start_address"]),
        )[:10]
        for bucket in candidates:
            try:
                location = self._symbolize_bucket(
                    debugger,
                    request.core_id,
                    bucket,
                    capture_started_ns,
                    global_query_budget,
                )
            except Exception:  # noqa: BLE001 - optional debugger enrichment
                location = None
            if location is not None:
                locations.append(location)
        if not locations:
            return None
        return {
            "source": "trace32_symbol_table",
            "trust": "debugger_reported",
            "refinement_granularity_bytes": 4,
            "locations": locations,
        }

    def _symbolize_bucket(
        self,
        debugger: Any,
        core_id: int,
        bucket: dict[str, int],
        capture_started_ns: int,
        global_query_budget: list[int],
    ) -> dict[str, Any] | None:
        start, end, hits = (
            bucket["start_address"],
            bucket["end_address"],
            bucket["hits"],
        )
        per_bucket_query_budget = [SYMBOLIZATION_PER_BUCKET_QUERY_BUDGET]
        pending: list[tuple[int, int, int]] = [(-hits, start, end)]
        best_leaf: tuple[int, int, int] | None = None
        while pending:
            next_negative_hits, next_start, _ = pending[0]
            if best_leaf is not None and self._is_better_location(
                best_leaf[0], best_leaf[1], -next_negative_hits, next_start
            ):
                break
            negative_hits, segment_start, segment_end = heapq.heappop(pending)
            segment_hits = -negative_hits
            if segment_end - segment_start <= 4:
                if best_leaf is None or self._is_better_location(
                    segment_hits, segment_start, best_leaf[0], best_leaf[1]
                ):
                    best_leaf = (segment_hits, segment_start, segment_end)
                continue
            midpoint = segment_start + (segment_end - segment_start) // 2
            left_hits = self._perf_pc_hits(
                debugger,
                segment_start,
                midpoint,
                core_id,
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            right_hits = self._perf_pc_hits(
                debugger,
                midpoint,
                segment_end,
                core_id,
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            if left_hits + right_hits != segment_hits:
                raise SamplingError(
                    "TRACE32 refinement does not partition parent PC hits"
                )
            heapq.heappush(pending, (-left_hits, segment_start, midpoint))
            heapq.heappush(pending, (-right_hits, midpoint, segment_end))

        if best_leaf is None or best_leaf[0] <= 0:
            return None
        dominant_hits, dominant_start, dominant_end = best_leaf
        function_name = self._function_label(
            debugger,
            dominant_start,
            dominant_end,
            capture_started_ns,
            global_query_budget,
            per_bucket_query_budget,
        )
        source_file, source_line = self._source_label(
            debugger,
            dominant_start,
            dominant_end,
            capture_started_ns,
            global_query_budget,
            per_bucket_query_budget,
        )
        if function_name is None and source_file is None:
            return None
        result: dict[str, Any] = {
            "bucket_start_address": start,
            "bucket_end_address": end,
            "hits": hits,
            "dominant_start_address": dominant_start,
            "dominant_end_address": dominant_end,
            "dominant_hits": dominant_hits,
        }
        if function_name is not None:
            result["function_name"] = function_name
        if source_file is not None:
            result["source_file"] = source_file
            result["source_line"] = source_line
        return result

    @staticmethod
    def _is_better_location(
        candidate_hits: int,
        candidate_start: int,
        other_hits: int,
        other_start: int,
    ) -> bool:
        return (candidate_hits, -candidate_start) > (other_hits, -other_start)

    def _function_label(
        self,
        debugger: Any,
        start: int,
        end: int,
        capture_started_ns: int,
        global_query_budget: list[int],
        per_bucket_query_budget: list[int],
    ) -> str | None:
        try:
            start_function = self._symbol_query(
                debugger,
                f"sYmbol.FUNCTION(P:0x{start:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            end_function = self._symbol_query(
                debugger,
                f"sYmbol.FUNCTION(P:0x{end - 1:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
        except Exception:  # noqa: BLE001 - optional TRACE32 symbol label
            return None
        if not isinstance(start_function, str) or start_function != end_function:
            return None
        return self._safe_symbol_component(start_function)

    def _source_label(
        self,
        debugger: Any,
        start: int,
        end: int,
        capture_started_ns: int,
        global_query_budget: list[int],
        per_bucket_query_budget: list[int],
    ) -> tuple[str | None, int | None]:
        try:
            start_file = self._symbol_query(
                debugger,
                f"sYmbol.SOURCEFILE(P:0x{start:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            end_file = self._symbol_query(
                debugger,
                f"sYmbol.SOURCEFILE(P:0x{end - 1:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            start_line = self._symbol_query(
                debugger,
                f"sYmbol.SOURCELINE(P:0x{start:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
            end_line = self._symbol_query(
                debugger,
                f"sYmbol.SOURCELINE(P:0x{end - 1:x})",
                capture_started_ns,
                global_query_budget,
                per_bucket_query_budget,
            )
        except Exception:  # noqa: BLE001 - optional TRACE32 source label
            return None, None
        if (
            not isinstance(start_file, str)
            or start_file != end_file
            or type(start_line) is not int
            or start_line != end_line
            or start_line < 1
        ):
            return None, None
        source_file = self._safe_symbol_component(start_file)
        if source_file is None:
            return None, None
        return source_file, start_line

    def _perf_pc_hits(
        self,
        debugger: Any,
        start: int,
        end: int,
        core_id: int,
        capture_started_ns: int,
        global_query_budget: list[int],
        per_bucket_query_budget: list[int],
    ) -> int:
        value = self._symbol_query(
            debugger,
            f"PERF.PC.HITS(P:0x{start:x}--0x{end - 1:x}, {core_id}.)",
            capture_started_ns,
            global_query_budget,
            per_bucket_query_budget,
        )
        if type(value) is not int or value < 0:
            raise SamplingError("TRACE32 returned an invalid refined PC hit count")
        return value

    def _symbol_query(
        self,
        debugger: Any,
        expression: str,
        capture_started_ns: int,
        global_query_budget: list[int],
        per_bucket_query_budget: list[int],
    ) -> Any:
        if global_query_budget[0] <= 0 or per_bucket_query_budget[0] <= 0:
            raise SamplingError("TRACE32 symbolization query budget exhausted")
        self._deadline(capture_started_ns)
        global_query_budget[0] -= 1
        per_bucket_query_budget[0] -= 1
        return debugger.fnc(expression)

    @staticmethod
    def _safe_symbol_component(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        # TRACE32 can return a qualified name or an absolute source path.  Keep
        # only the final path component before publication and reject controls.
        component = re.split(r"[\\\\/]+", value)[-1]
        if not component or any(
            ord(character) < 32 or 127 <= ord(character) <= 159
            for character in component
        ):
            return None
        return component.encode("utf-8")[:256].decode("utf-8", errors="ignore") or None

    @staticmethod
    def _runtime_percent(value: Any) -> float:
        try:
            result = float(str(value).strip().rstrip("%"))
        except ValueError as error:
            raise SamplingError(
                "TRACE32 returned an invalid retained runtime"
            ) from error
        if not 0 <= result <= 100:
            raise SamplingError("TRACE32 retained runtime is outside 0..100")
        return result

    @staticmethod
    def _disable(debugger: Any) -> None:
        debugger.cmd("PERF.DISable")
        if debugger.fnc.perf_state() != 0:
            raise SamplingError("TRACE32 PERF remains enabled after cleanup")

    def _cleanup_and_verify(self, debugger: Any) -> None:
        self._disable(debugger)
        after = self._state_required(debugger)
        if not after["powered"] or not after["running"] or after["halted"]:
            raise SamplingError("target state is unsafe after PERF cleanup")
        if debugger.fnc.perf_state() != 0:
            raise SamplingError("TRACE32 PERF remains enabled after cleanup")

    @staticmethod
    def _software(debugger: Any) -> str:
        version = str(debugger.fnc.software_version())
        try:
            return f"{version}+{int(debugger.fnc.software_build())}"
        except (OSError, RuntimeError, t32.FunctionError):
            return version

    def _deadline(self, started_ns: int) -> None:
        if time.monotonic_ns() - started_ns > self.capture_deadline_ms * 1_000_000:
            raise SamplingError("sampling capture exceeded its total deadline")
