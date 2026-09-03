"""Exclusive artifact-root ownership, journal, and atomic publication."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from jsonschema import Draft202012Validator
from typing_extensions import Self

from .model import (
    ENDPOINT_FINGERPRINT_SCHEME_V2,
    SESSION_ID_RE,
    CaptureRequest,
    canonical_json,
    control_schema_path,
)

MAX_EVENT_BYTES = 64 * 1024
MAX_JOURNAL_EVENTS = 16_384
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
TRANSACTION_RESERVATION_EVENTS = 12
TRANSACTION_RESERVATION_BYTES = TRANSACTION_RESERVATION_EVENTS * MAX_EVENT_BYTES
MAX_SESSION_JSON_BYTES = 16 * 1024 * 1024
EVENT_FILE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[0-9]{8}\.json$"
)
EVENTS = frozenset(
    {
        "configure_intent",
        "configure_observed",
        "start_intent",
        "start_observed",
        "stop_intent",
        "stop_observed",
        "export_intent",
        "export_observed",
        "cleanup_intent",
        "cleanup_observed",
        "cleanup_failed",
        "recovery_observed",
    }
)
TERMINAL_EVENTS = frozenset({"cleanup_observed", "recovery_observed"})


class StorageError(RuntimeError):
    pass


_held_roots: set[Path] = set()
_held_roots_lock = threading.Lock()


def _is_link_like(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def _require_plain_directory(path: Path) -> None:
    if _is_link_like(path) or not path.is_dir():
        raise StorageError(f"not a plain directory: {path}")


def _require_plain_file(path: Path) -> None:
    if _is_link_like(path) or not path.is_file():
        raise StorageError(f"not a plain file: {path}")


def _read_strict_json(path: Path, *, document: str) -> dict[str, Any]:
    _require_plain_file(path)
    if path.stat().st_size > MAX_SESSION_JSON_BYTES:
        raise StorageError(f"{document} exceeds size limit")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    except (OSError, json.JSONDecodeError) as error:
        raise StorageError(f"{document} is unreadable") from error
    if not isinstance(value, dict):
        raise StorageError(f"{document} must be a JSON object")
    return value


class ExecutionLease:
    def __init__(self, artifact_root: Path) -> None:
        if _is_link_like(artifact_root):
            raise StorageError("artifact root must not be a link or reparse point")
        self.root = artifact_root.resolve(strict=True)
        _require_plain_directory(self.root)
        self.file: Any | None = None

    def __enter__(self) -> Self:
        with _held_roots_lock:
            if self.root in _held_roots:
                raise StorageError(
                    "TRACE32 driver execution lease is already active in this process"
                )
            _held_roots.add(self.root)
        try:
            control = self.root / ".t32perf-control"
            controller = control / "controller"
            for directory in (control, controller):
                directory.mkdir(exist_ok=True)
                _require_plain_directory(directory)
            path = controller / "trace32-driver-execution.lock"
            if _is_link_like(path):
                raise StorageError(
                    "TRACE32 driver execution lease must be a plain file"
                )
            self.file = open(path, "a+b")
            path_stat, opened_stat = path.stat(), os.fstat(self.file.fileno())
            if (
                _is_link_like(path)
                or not stat.S_ISREG(opened_stat.st_mode)
                or path_stat.st_ino != opened_stat.st_ino
                or path_stat.st_dev != opened_stat.st_dev
                or opened_stat.st_size != 0
            ):
                raise StorageError(
                    "TRACE32 driver execution lease changed or is not empty"
                )
            self._lock()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _lock(self) -> None:
        assert self.file is not None
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise StorageError(
                "TRACE32 driver execution lease is held by another process"
            ) from error

    def __exit__(self, *_: object) -> None:
        if self.file is not None:
            with contextlib.suppress(OSError):
                if os.name == "nt":
                    import msvcrt

                    self.file.seek(0)
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            self.file.close()
            self.file = None
        with _held_roots_lock:
            _held_roots.discard(self.root)


class SessionCaptureLease:
    """Host-created, still-created Session ownership held through publication."""

    _directories = (
        "capture",
        "capture/raw",
        "capture/staging",
        "normalized",
        "analysis",
        "report",
        "logs",
        "artifact-index",
        "ingest-intents",
        "committed-staging-sources",
    )

    def __init__(self, artifact_root: Path, request: CaptureRequest) -> None:
        if not SESSION_ID_RE.fullmatch(request.session_id):
            raise StorageError("invalid session identifier")
        self.request = request
        self.session = artifact_root / request.session_id
        self.file: Any | None = None
        self._request_validator = Draft202012Validator(
            json.loads(
                control_schema_path("sampling-capture-request.schema.json").read_text(
                    encoding="utf-8"
                )
            )
        )

    def __enter__(self) -> Self:
        _require_plain_directory(self.session)
        for relative in self._directories:
            _require_plain_directory(self.session / relative)
        self._verify_created_lifecycle()
        lock_path = self.session / ".session.lock"
        _require_plain_file(lock_path)
        self.file = open(lock_path, "r+b")
        path_stat, opened_stat = lock_path.stat(), os.fstat(self.file.fileno())
        if (
            _is_link_like(lock_path)
            or not stat.S_ISREG(opened_stat.st_mode)
            or path_stat.st_ino != opened_stat.st_ino
            or path_stat.st_dev != opened_stat.st_dev
            or opened_stat.st_size != 0
        ):
            self.__exit__(None, None, None)
            raise StorageError("Session lock changed or is not empty")
        try:
            self._lock()
            # Recheck lifecycle after acquiring the same cross-process lock Host uses.
            self._verify_created_lifecycle()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _lock(self) -> None:
        assert self.file is not None
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise StorageError(
                "Session is locked by the Host or another process"
            ) from error

    def _verify_created_lifecycle(self) -> None:
        state = _read_strict_json(self.session / "state.json", document="Session state")
        required_state = {
            "schema",
            "created_at",
            "state",
            "operation_id",
            "revision",
            "updated_at",
        }
        if (
            set(state) != required_state
            or state.get("schema") != "t32perf.state/v1"
            or state.get("state") != "created"
            or not isinstance(state.get("created_at"), str)
            or not state["created_at"]
            or not isinstance(state.get("operation_id"), str)
            or state["operation_id"] != self.request.operation_id
            or not isinstance(state.get("revision"), int)
            or isinstance(state["revision"], bool)
            or state["revision"] < 0
            or not isinstance(state.get("updated_at"), str)
            or not state["updated_at"]
        ):
            raise StorageError(
                "sampling_capture requires a Host-created Session in state created"
            )
        request = _read_strict_json(
            self.session / "request.json", document="Session request"
        )
        if (
            list(self._request_validator.iter_errors(request))
            or request != self.request.authorization_document()
        ):
            raise StorageError(
                "sampling_capture request does not match the Host-created Session authorization"
            )
        manifest = self.session / "manifest.json"
        if manifest.exists() or _is_link_like(manifest):
            raise StorageError("sampling_capture rejects Sessions with a manifest")
        for relative in (
            "artifact-index",
            "ingest-intents",
            "committed-staging-sources",
        ):
            if any((self.session / relative).iterdir()):
                raise StorageError(f"sampling_capture requires empty {relative}")
        staging = self.session / "capture" / "staging"
        for path in staging.rglob("*"):
            if _is_link_like(path):
                raise StorageError("Session staging contains a link or reparse point")
            if path.is_file() and path.name.startswith("pc-hit-histogram-"):
                raise StorageError(
                    "each Created Session permits one sidecar histogram export"
                )

    def __exit__(self, *_: object) -> None:
        if self.file is None:
            return
        with contextlib.suppress(OSError):
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        self.file.close()
        self.file = None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StorageError("sampling journal contains duplicate object members")
        result[key] = value
    return result


def _is_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


class SamplingJournal:
    schema: ClassVar[str] = "t32perf.sampling-driver-event/v1"
    fields: ClassVar[frozenset[str]] = frozenset(
        {
            "schema",
            "transaction_id",
            "endpoint_fingerprint",
            "endpoint_fingerprint_scheme",
            "owner",
            "event",
            "sequence",
            "observed_at",
            "details",
        }
    )

    def __init__(
        self, artifact_root: Path, endpoint_fingerprint: str, *, legacy_v1: bool = False
    ) -> None:
        self.directory = artifact_root / ".t32perf-control" / "sampling-driver-events"
        self.legacy_v1 = legacy_v1
        self._fields = self.fields
        if legacy_v1:
            _require_plain_directory(self.directory)
        else:
            self.directory.mkdir(parents=True, exist_ok=True)
        _require_plain_directory(self.directory)
        self.endpoint_fingerprint = endpoint_fingerprint
        schema_name = (
            "sampling-driver-event.legacy-v1.schema.json"
            if legacy_v1
            else "sampling-driver-event.schema.json"
        )
        schema = json.loads(
            control_schema_path(schema_name).read_text(encoding="utf-8")
        )
        if legacy_v1:
            # This immutable asset was recovered from jj operation 5d4aadee9480.
            # It is never regenerated from the current contract.
            self._fields = frozenset(self.fields - {"endpoint_fingerprint_scheme"})
        self._validator = Draft202012Validator(schema)
        self._bind(artifact_root)
        self._records = self._load_events()
        self._sequences = {
            transaction_id: max(record["sequence"] for record in records)
            for transaction_id, records in self._grouped_records().items()
        }
        self._journal_bytes = sum(record["_size_bytes"] for record in self._records)
        self._reservations: dict[str, int] = {}
        self._failure_marker = (
            artifact_root / ".t32perf-control" / "sampling-journal-failure.json"
        )

    def reserve_transaction(self, transaction_id: str) -> None:
        """Reserve durable space for all normal and cleanup journal outcomes."""
        if not _is_uuid(transaction_id) or transaction_id in self._reservations:
            raise StorageError("invalid or already reserved sampling transaction")
        reserved_events = sum(self._reservations.values())
        if (
            len(self._records) + reserved_events + TRANSACTION_RESERVATION_EVENTS
            > MAX_JOURNAL_EVENTS
        ):
            raise StorageError("sampling journal lacks transaction entry headroom")
        if (
            self._journal_bytes
            + reserved_events * MAX_EVENT_BYTES
            + TRANSACTION_RESERVATION_BYTES
            > MAX_JOURNAL_BYTES
        ):
            raise StorageError("sampling journal lacks transaction byte headroom")
        self._reservations[transaction_id] = TRANSACTION_RESERVATION_EVENTS

    def release_transaction(self, transaction_id: str) -> None:
        self._reservations.pop(transaction_id, None)

    def require_healthy(self, *, recover_journal_failure: bool) -> None:
        if self._failure_marker.exists() or _is_link_like(self._failure_marker):
            _require_plain_file(self._failure_marker)
            if not recover_journal_failure:
                raise StorageError(
                    "sampling journal previously failed; restart with --recover-quarantined"
                )

    def clear_failure_marker(self) -> None:
        if self._failure_marker.exists():
            _require_plain_file(self._failure_marker)
            self._failure_marker.unlink()

    def mark_failure(self, error: Exception) -> None:
        if self._failure_marker.exists() or _is_link_like(self._failure_marker):
            _require_plain_file(self._failure_marker)
            return
        _publish_new(
            self._failure_marker,
            canonical_json(
                {
                    "schema": "t32perf.sampling-journal-failure/v1",
                    "error": type(error).__name__,
                }
            ),
        )

    def _mark_failure_safely(self, error: Exception) -> None:
        try:
            self.mark_failure(error)
        except (OSError, StorageError):
            pass

    def _bind(self, root: Path) -> None:
        path = root / ".t32perf-control" / "sampling-endpoint-binding.json"
        value: dict[str, str] = {
            "schema": "t32perf.sampling-endpoint-binding/v1",
            "endpoint_fingerprint": self.endpoint_fingerprint,
        }
        if not self.legacy_v1:
            value["endpoint_fingerprint_scheme"] = ENDPOINT_FINGERPRINT_SCHEME_V2
        if path.exists() or _is_link_like(path):
            try:
                actual = _read_strict_json(path, document="endpoint binding")
            except StorageError as error:
                raise StorageError("endpoint binding is unreadable") from error
            if actual != value:
                raise StorageError(
                    "artifact root is bound to a different TRACE32 endpoint"
                )
        elif self.legacy_v1:
            raise StorageError("legacy recovery requires an existing endpoint binding")
        else:
            _publish_new(path, canonical_json(value))

    def _load_events(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        total_bytes = 0
        paths = list(self.directory.iterdir())
        if len(paths) > MAX_JOURNAL_EVENTS:
            raise StorageError("sampling journal entry limit exceeded")
        for path in paths:
            if (
                not EVENT_FILE_RE.fullmatch(path.name)
                or _is_link_like(path)
                or not path.is_file()
                or path.stat().st_size > MAX_EVENT_BYTES
            ):
                raise StorageError("sampling journal contains an unsafe event")
            size = path.stat().st_size
            total_bytes += size
            if total_bytes > MAX_JOURNAL_BYTES:
                raise StorageError("sampling journal byte limit exceeded")
            try:
                record = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
            except (OSError, json.JSONDecodeError) as error:
                raise StorageError("sampling journal is unreadable") from error
            if (
                not isinstance(record, dict)
                or set(record) != self._fields
                or record.get("schema") != self.schema
                or record.get("owner") != "lauterbach-sampling-mcp/v1"
                or record.get("endpoint_fingerprint") != self.endpoint_fingerprint
                or (
                    not self.legacy_v1
                    and record.get("endpoint_fingerprint_scheme")
                    != ENDPOINT_FINGERPRINT_SCHEME_V2
                )
                or record.get("event") not in EVENTS
                or not _is_uuid(record.get("transaction_id"))
                or not isinstance(record.get("sequence"), int)
                or isinstance(record["sequence"], bool)
                or record["sequence"] < 1
                or not isinstance(record.get("observed_at"), str)
                or not isinstance(record.get("details"), dict)
            ):
                raise StorageError(
                    "sampling journal event violates the sidecar contract"
                )
            if list(self._validator.iter_errors(record)):
                raise StorageError(
                    "sampling journal event violates the generated contract"
                )
            record["_size_bytes"] = size
            records.append(record)
        return records

    def _grouped_records(self) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for event in self._records:
            grouped.setdefault(event["transaction_id"], []).append(event)
        return grouped

    def recover(self, disable: Any, *, recover_quarantined: bool = False) -> None:
        for transaction_id, records in self._grouped_records().items():
            records.sort(key=lambda item: item["sequence"])
            if [item["sequence"] for item in records] != list(
                range(1, len(records) + 1)
            ):
                raise StorageError("sampling journal sequence is ambiguous")
            self._validate_order(records)
            cleanup_outcome = next(
                (
                    record["event"]
                    for record in reversed(records)
                    if record["event"] in TERMINAL_EVENTS | {"cleanup_failed"}
                ),
                None,
            )
            if cleanup_outcome in TERMINAL_EVENTS:
                continue
            if cleanup_outcome == "cleanup_failed" and not recover_quarantined:
                raise StorageError(
                    "sidecar cleanup previously failed; restart with --recover-quarantined"
                )
            self.reserve_transaction(transaction_id)
            intent_error: OSError | StorageError | None = None
            try:
                self.append(transaction_id, "cleanup_intent", {"recovery": True})
            except (OSError, StorageError) as error:
                intent_error = error
                self._mark_failure_safely(error)
            try:
                disable()
            except Exception as error:
                try:
                    self.append(
                        transaction_id,
                        "cleanup_failed",
                        {"recovery": True, "error": type(error).__name__},
                    )
                except (OSError, StorageError) as journal_error:
                    self._mark_failure_safely(journal_error)
                self.release_transaction(transaction_id)
                raise StorageError(
                    "sidecar recovery cleanup failed; capture remains blocked"
                ) from error
            if intent_error is not None:
                self.release_transaction(transaction_id)
                raise intent_error
            try:
                self.append(transaction_id, "recovery_observed", {"recovery": True})
            except (OSError, StorageError) as error:
                self._mark_failure_safely(error)
                raise
            finally:
                self.release_transaction(transaction_id)
        if recover_quarantined:
            self.clear_failure_marker()

    @staticmethod
    def _validate_order(records: list[dict[str, Any]]) -> None:
        if records[0]["event"] != "configure_intent":
            raise StorageError("sampling journal must start with configure_intent")
        method = records[0]["details"]["method"]
        phase = "configure_intent"
        for record in records[1:]:
            event = record["event"]
            recovery = record["details"].get("recovery") is True
            if phase == "configure_intent":
                if (
                    event == "configure_observed"
                    and record["details"]["method"] == method
                ):
                    phase = "configured"
                elif event == "cleanup_intent":
                    phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid event after configure intent"
                    )
            elif phase == "configured":
                if event == "start_intent":
                    phase = "start_intent"
                elif event == "cleanup_intent":
                    phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid event after configuration"
                    )
            elif phase == "start_intent":
                if event == "start_observed":
                    phase = "started"
                elif event == "cleanup_intent":
                    phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid event after start intent"
                    )
            elif phase == "started":
                if event == "stop_intent":
                    phase = "stop_intent"
                elif event == "cleanup_intent":
                    phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
                else:
                    raise StorageError("sampling journal invalid event while started")
            elif phase == "stop_intent":
                if event == "stop_observed":
                    phase = "stopped"
                elif event == "cleanup_intent":
                    phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid event after stop intent"
                    )
            elif phase == "stopped":
                if event != "cleanup_intent":
                    raise StorageError("sampling journal requires cleanup after stop")
                phase = "recovery_cleanup_intent" if recovery else "cleanup_intent"
            elif phase == "cleanup_intent":
                if event == "cleanup_observed":
                    phase = "cleanup_observed"
                elif event == "cleanup_failed":
                    phase = "cleanup_failed"
                elif event == "cleanup_intent" and recovery:
                    phase = "recovery_cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid normal cleanup outcome"
                    )
            elif phase == "recovery_cleanup_intent":
                if event == "recovery_observed":
                    phase = "recovery_observed"
                elif event == "cleanup_failed":
                    phase = "cleanup_failed"
                elif event == "cleanup_intent" and recovery:
                    phase = "recovery_cleanup_intent"
                else:
                    raise StorageError(
                        "sampling journal invalid recovery cleanup outcome"
                    )
            elif phase == "cleanup_failed":
                if event == "cleanup_intent" and recovery:
                    phase = "recovery_cleanup_intent"
                else:
                    raise StorageError("sampling journal requires explicit recovery")
            elif phase == "cleanup_observed":
                if event == "export_intent":
                    phase = "export_intent"
                else:
                    raise StorageError("sampling journal mutation after cleanup")
            elif phase == "export_intent":
                if event == "export_observed":
                    phase = "export_observed"
                else:
                    raise StorageError("sampling journal invalid export outcome")
            else:
                raise StorageError("sampling journal mutation after terminal outcome")

    def append(
        self, transaction_id: str, event: str, details: dict[str, Any] | None = None
    ) -> None:
        if not _is_uuid(transaction_id) or event not in EVENTS:
            raise StorageError("invalid sampling journal event")
        sequence = self._sequences.get(transaction_id, 0) + 1
        record = {
            "schema": self.schema,
            "transaction_id": transaction_id,
            "endpoint_fingerprint": self.endpoint_fingerprint,
            "owner": "lauterbach-sampling-mcp/v1",
            "event": event,
            "sequence": sequence,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }
        if not self.legacy_v1:
            record["endpoint_fingerprint_scheme"] = ENDPOINT_FINGERPRINT_SCHEME_V2
        payload = canonical_json(record)
        if len(payload) > MAX_EVENT_BYTES:
            raise StorageError("sampling journal event exceeds size limit")
        reserved = self._reservations.get(transaction_id, 0)
        if reserved:
            self._reservations[transaction_id] = reserved - 1
        else:
            reserved_events = sum(self._reservations.values())
            if len(self._records) + reserved_events >= MAX_JOURNAL_EVENTS:
                raise StorageError("sampling journal entry limit exceeded")
            if (
                self._journal_bytes + reserved_events * MAX_EVENT_BYTES + len(payload)
                > MAX_JOURNAL_BYTES
            ):
                raise StorageError("sampling journal byte limit exceeded")
        if list(self._validator.iter_errors(record)):
            raise StorageError("sampling journal event violates the generated contract")
        _publish_new(self.directory / f"{transaction_id}-{sequence:08d}.json", payload)
        record["_size_bytes"] = len(payload)
        self._records.append(record)
        self._sequences[transaction_id] = sequence
        self._journal_bytes += len(payload)


def staging_directory(artifact_root: Path, session_id: str) -> Path:
    if not SESSION_ID_RE.fullmatch(session_id):
        raise StorageError("invalid session identifier")
    session = artifact_root / session_id
    _require_plain_directory(session)
    _require_plain_directory(session / "capture")
    staging = session / "capture" / "staging"
    _require_plain_directory(staging)
    return staging


def publish_histogram(staging: Path, session_id: str, payload: bytes) -> dict[str, Any]:
    digest = hashlib.sha256(payload).hexdigest()
    name = f"pc-hit-histogram-{session_id}-{uuid.uuid4().hex}.json"
    _publish_new(staging / name, payload)
    return {
        "relative_path": f"capture/staging/{name}",
        "sha256": digest,
        "size_bytes": len(payload),
    }


def _publish_new(destination: Path, payload: bytes) -> None:
    if (
        destination.exists()
        or _is_link_like(destination)
        or _is_link_like(destination.parent)
    ):
        raise StorageError("artifact destination already exists or is unsafe")
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    try:
        with open(temporary, "xb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary, destination)
        if (
            _is_link_like(destination)
            or not destination.is_file()
            or destination.read_bytes() != payload
        ):
            raise StorageError("published artifact failed exact-byte verification")
    except FileExistsError as error:
        raise StorageError("artifact destination already exists") from error
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
