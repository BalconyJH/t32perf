"""Hostile-filesystem-safe durable journal for intrusive stack sampling."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from typing_extensions import Self

from .model import ENDPOINT_FINGERPRINT_SCHEME_V2, SESSION_ID_RE, canonical_json
from .storage import (
    MAX_JOURNAL_BYTES,
    StorageError,
    _is_link_like,
    _is_uuid,
    _publish_new,
    _read_strict_json,
    _require_plain_directory,
    _require_plain_file,
    _strict_object,
)

MAX_STACK_SAMPLES = 512
MAX_STACK_DRIVER_EVENTS = MAX_STACK_SAMPLES * 4 + 6
MAX_STACK_JOURNAL_EVENTS = 16_384
MAX_STACK_CAPTURE_ATTEMPTS = 16_384
# Stack-driver events have a closed, small schema. Keeping their separate
# ceiling avoids reserving the generic sampling event maximum (64 KiB) for
# every Break/Go record while retaining a finite, independently enforced bound.
MAX_STACK_EVENT_BYTES = 4 * 1024
SCHEMA = "t32perf.stack-driver-event/v1"
OWNER = "lauterbach-stack-sampling-mcp/v1"
ATTEMPT_SCHEMA = "t32perf.stack-capture-attempt/v1"
EVENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[0-9]{8}\.json$"
)
EVENTS = frozenset(
    {
        "capture_intent",
        "break_intent",
        "break_observed",
        "go_intent",
        "go_observed",
        "capture_observed",
        "cleanup_intent",
        "cleanup_observed",
        "cleanup_failed",
        "recovery_observed",
        "export_intent",
        "export_observed",
    }
)
FIELDS = frozenset(
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


def _label(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= maximum
        and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
    )


def _details(event: str, d: object) -> bool:
    if not isinstance(d, dict):
        return False
    fixed = {
        "capture_intent": {
            "initial_running",
            "duration_ms",
            "sample_period_ms",
            "max_samples",
            "max_frames",
        },
        "break_intent": {"sample_index"},
        "break_observed": {"sample_index"},
        "go_intent": {"sample_index"},
        "go_observed": {"sample_index"},
        "capture_observed": {"attempted_samples", "collected_samples"},
        "cleanup_intent": set(),
        "cleanup_observed": set(),
        "export_intent": set(),
        "recovery_observed": {"recovery", "running"},
        "export_observed": {"relative_path", "sha256", "size_bytes"},
    }
    if event == "cleanup_intent":
        return set(d) in (set(), {"recovery"}) and d.get("recovery", True) is True
    if event == "cleanup_failed":
        return (
            set(d) in ({"error"}, {"recovery", "error"})
            and d.get("recovery", True) is True
            and _label(d.get("error"), 1024)
        )
    if set(d) != fixed[event]:
        return False
    if event == "capture_intent":
        return (
            d["initial_running"] is True
            and all(type(d[x]) is int for x in fixed[event] - {"initial_running"})
            and 100 <= d["duration_ms"] <= 60000
            and 10 <= d["sample_period_ms"] <= 1000
            and 1 <= d["max_samples"] <= 512
            and 1 <= d["max_frames"] <= 8
        )
    if event in {"break_intent", "break_observed", "go_intent", "go_observed"}:
        return type(d["sample_index"]) is int and 1 <= d["sample_index"] <= 512
    if event == "capture_observed":
        return (
            all(type(d[x]) is int and 0 <= d[x] <= 512 for x in d)
            and d["collected_samples"] <= d["attempted_samples"]
        )
    if event == "recovery_observed":
        return d["recovery"] is True and d["running"] is True
    if event == "export_observed":
        return (
            isinstance(d["relative_path"], str)
            and re.fullmatch(
                r"capture/staging/stack-samples-[A-Za-z0-9_-]{1,64}-[0-9a-f]{32}\.json",
                d["relative_path"],
            )
            is not None
            and isinstance(d["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", d["sha256"]) is not None
            and type(d["size_bytes"]) is int
            and d["size_bytes"] > 0
        )
    return True


class StackSessionLease:
    directories = (
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

    def __init__(self, root: Path, request: Any) -> None:
        if not SESSION_ID_RE.fullmatch(request.session_id):
            raise StorageError("invalid session identifier")
        self.root = root
        self.request, self.session, self.file = request, root / request.session_id, None
        schema = (
            Path(__file__).with_name("schemas") / "stack-capture-request.schema.json"
        )
        self.validator = Draft202012Validator(
            json.loads(schema.read_bytes(), object_pairs_hook=_strict_object)
        )
        attempt_schema = (
            Path(__file__).with_name("schemas") / "stack-capture-attempt.schema.json"
        )
        self.attempt_validator = Draft202012Validator(
            json.loads(attempt_schema.read_bytes(), object_pairs_hook=_strict_object)
        )

    def __enter__(self) -> Self:
        _require_plain_directory(self.session)
        for path in self.directories:
            _require_plain_directory(self.session / path)
        self._verify()
        lock = self.session / ".session.lock"
        _require_plain_file(lock)
        self.file = open(lock, "r+b")
        ps, fs = lock.stat(), os.fstat(self.file.fileno())
        if (
            _is_link_like(lock)
            or not stat.S_ISREG(fs.st_mode)
            or (ps.st_ino, ps.st_dev) != (fs.st_ino, fs.st_dev)
            or fs.st_size
        ):
            self.__exit__()
            raise StorageError("Session lock changed or is not empty")
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._verify()
            return self
        except OSError as e:
            self.__exit__()
            raise StorageError(
                "Session is locked by the Host or another process"
            ) from e
        except Exception:
            self.__exit__()
            raise

    def _verify(self) -> None:
        state = _read_strict_json(self.session / "state.json", document="Session state")
        if (
            set(state)
            != {
                "schema",
                "created_at",
                "state",
                "operation_id",
                "revision",
                "updated_at",
            }
            or state.get("schema") != "t32perf.state/v1"
            or state.get("state") != "created"
            or state.get("operation_id") != self.request.operation_id
            or type(state.get("revision")) is not int
            or state["revision"] < 0
            or not _label(state.get("created_at"), 256)
            or not _label(state.get("updated_at"), 256)
        ):
            raise StorageError(
                "stack_sampling_capture requires a Host-created Session in state created"
            )
        req = _read_strict_json(
            self.session / "request.json", document="Session request"
        )
        if (
            list(self.validator.iter_errors(req))
            or req != self.request.authorization_document()
        ):
            raise StorageError(
                "stack capture request does not match the Host-created Session authorization"
            )
        manifest = self.session / "manifest.json"
        if manifest.exists() or _is_link_like(manifest):
            raise StorageError("stack capture rejects Sessions with a manifest")
        for name in ("artifact-index", "ingest-intents", "committed-staging-sources"):
            if any((self.session / name).iterdir()):
                raise StorageError(f"stack capture requires empty {name}")
        for path in (self.session / "capture" / "staging").rglob("*"):
            if _is_link_like(path) or (
                path.is_file() and path.name.startswith("stack-samples-")
            ):
                raise StorageError("each Created Session permits one safe stack export")
        attempt = (
            self.root
            / ".t32perf-control"
            / "stack-capture-attempts"
            / f"{self.request.session_id}.json"
        )
        if attempt.exists() or _is_link_like(attempt):
            _require_plain_file(attempt)
            document = _read_strict_json(attempt, document="Stack capture attempt")
            if (
                list(self.attempt_validator.iter_errors(document))
                or document.get("session_id") != self.request.session_id
                or document.get("operation_id") != self.request.operation_id
                or document["request_sha256"]
                != hashlib.sha256(
                    (self.session / "request.json").read_bytes()
                ).hexdigest()
                or not _label(document.get("created_at"), 64)
            ):
                raise StorageError("stack capture attempt marker is invalid")
            raise StorageError("stack capture Session operation was already consumed")

    def consume(self, endpoint_fingerprint: str) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", endpoint_fingerprint) is None:
            raise StorageError("invalid stack capture endpoint fingerprint")
        payload = canonical_json(
            {
                "schema": ATTEMPT_SCHEMA,
                "session_id": self.request.session_id,
                "operation_id": self.request.operation_id,
                "request_sha256": hashlib.sha256(
                    (self.session / "request.json").read_bytes()
                ).hexdigest(),
                "endpoint_fingerprint": endpoint_fingerprint,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        control = self.root / ".t32perf-control"
        _require_plain_directory(control)
        directory = control / "stack-capture-attempts"
        directory.mkdir(exist_ok=True)
        _require_plain_directory(directory)
        entries = list(directory.iterdir())
        if len(entries) >= MAX_STACK_CAPTURE_ATTEMPTS:
            raise StorageError("stack capture attempt limit exceeded")
        for entry in entries:
            if (
                _is_link_like(entry)
                or not entry.is_file()
                or entry.suffix != ".json"
                or SESSION_ID_RE.fullmatch(entry.stem) is None
            ):
                raise StorageError("stack capture attempt directory is unsafe")
        _publish_new(directory / f"{self.request.session_id}.json", payload)

    @property
    def staging(self) -> Path:
        return self.session / "capture" / "staging"

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


class StackJournal:
    def __init__(self, root: Path, endpoint: str) -> None:
        self.root, self.endpoint = root, endpoint
        control = root / ".t32perf-control"
        control.mkdir(exist_ok=True)
        _require_plain_directory(control)
        self.directory = control / "stack-driver-events"
        self.directory.mkdir(exist_ok=True)
        _require_plain_directory(self.directory)
        self.failure = control / "stack-journal-failure.json"
        schema = Path(__file__).with_name("schemas") / "stack-driver-event.schema.json"
        self.validator = Draft202012Validator(
            json.loads(schema.read_bytes(), object_pairs_hook=_strict_object)
        )
        self._bind(control)
        self.records = self._load()
        self.bytes = sum(x["_size_bytes"] for x in self.records)
        self.seq = {
            tx: max(x["sequence"] for x in xs) for tx, xs in self._groups().items()
        }
        self.reserved: dict[str, int] = {}

    def _bind(self, control: Path) -> None:
        p = control / "sampling-endpoint-binding.json"
        expected = {
            "schema": "t32perf.sampling-endpoint-binding/v1",
            "endpoint_fingerprint": self.endpoint,
            "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
        }
        if p.exists() or _is_link_like(p):
            if _read_strict_json(p, document="endpoint binding") != expected:
                raise StorageError(
                    "artifact root is bound to a different TRACE32 endpoint"
                )
        else:
            _publish_new(p, canonical_json(expected))

    def _groups(
        self, records: list[dict[str, Any]] | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        ans: dict[str, list[dict[str, Any]]] = {}
        for x in self.records if records is None else records:
            ans.setdefault(x["transaction_id"], []).append(x)
        return ans

    def _load(self) -> list[dict[str, Any]]:
        paths = list(self.directory.iterdir())
        total = 0
        ans = []
        if len(paths) > MAX_STACK_JOURNAL_EVENTS:
            raise StorageError("stack journal entry limit exceeded")
        for p in paths:
            if not EVENT_RE.fullmatch(p.name) or _is_link_like(p) or not p.is_file():
                raise StorageError("stack journal contains an unsafe event")
            try:
                with open(p, "rb") as opened:
                    path_stat, opened_stat = p.stat(), os.fstat(opened.fileno())
                    if (
                        _is_link_like(p)
                        or not stat.S_ISREG(opened_stat.st_mode)
                        or (path_stat.st_ino, path_stat.st_dev)
                        != (opened_stat.st_ino, opened_stat.st_dev)
                        or opened_stat.st_size > MAX_STACK_EVENT_BYTES
                    ):
                        raise StorageError("stack journal event changed or is unsafe")
                    payload = opened.read(MAX_STACK_EVENT_BYTES + 1)
            except OSError as e:
                raise StorageError("stack journal is unreadable") from e
            size = len(payload)
            if size > MAX_STACK_EVENT_BYTES:
                raise StorageError("stack journal event exceeds size limit")
            total += size
            if total > MAX_JOURNAL_BYTES:
                raise StorageError("stack journal byte limit exceeded")
            try:
                x = json.loads(payload, object_pairs_hook=_strict_object)
            except (OSError, json.JSONDecodeError) as e:
                raise StorageError("stack journal is unreadable") from e
            if (
                not isinstance(x, dict)
                or set(x) != FIELDS
                or x.get("schema") != SCHEMA
                or x.get("endpoint_fingerprint") != self.endpoint
                or x.get("endpoint_fingerprint_scheme")
                != ENDPOINT_FINGERPRINT_SCHEME_V2
                or x.get("owner") != OWNER
                or x.get("event") not in EVENTS
                or not _is_uuid(x.get("transaction_id"))
                or type(x.get("sequence")) is not int
                or not 1 <= x["sequence"] <= MAX_STACK_DRIVER_EVENTS
                or not _label(x.get("observed_at"), 64)
                or not _details(x["event"], x.get("details"))
                or list(self.validator.iter_errors(x))
            ):
                raise StorageError(
                    "stack journal event violates the generated contract"
                )
            x["_size_bytes"] = size
            filename = f"{x['transaction_id']}-{x['sequence']:08d}.json"
            if p.name != filename:
                raise StorageError("stack journal filename does not bind its event")
            ans.append(x)
        for xs in self._groups(ans).values():
            self._validate(sorted(xs, key=lambda x: x["sequence"]))
        return ans

    @staticmethod
    def _validate(xs: list[dict[str, Any]]) -> None:
        if (
            not xs
            or [x["sequence"] for x in xs] != list(range(1, len(xs) + 1))
            or xs[0]["event"] != "capture_intent"
        ):
            raise StorageError("stack journal sequence is ambiguous")
        phase = "capture"
        index = 0
        completed = 0
        for x in xs[1:]:
            e, d = x["event"], x["details"]
            if phase == "capture" and e == "break_intent":
                index = d["sample_index"]
                if index != completed + 1:
                    raise StorageError("stack journal sample index is ambiguous")
                phase = "break_i"
            elif (
                phase == "break_i"
                and e == "break_observed"
                and d["sample_index"] == index
            ):
                phase = "break_o"
            elif phase == "break_o" and e == "go_intent" and d["sample_index"] == index:
                phase = "go_i"
            elif phase == "go_i" and e == "go_observed" and d["sample_index"] == index:
                completed += 1
                phase = "capture"
            elif phase == "capture" and e == "capture_observed":
                if (
                    d["attempted_samples"] != completed
                    or d["collected_samples"] > completed
                ):
                    raise StorageError("stack journal capture counts are ambiguous")
                phase = "captured"
            elif (
                phase in {"capture", "break_i", "break_o", "go_i", "captured"}
                and e == "cleanup_intent"
            ):
                phase = "recovery" if d else "cleanup"
            elif (
                phase == "cleanup" and e in {"cleanup_observed", "cleanup_failed"}
            ) or (phase == "recovery" and e in {"recovery_observed", "cleanup_failed"}):
                phase = e
            elif (
                phase == "cleanup_failed"
                and e == "cleanup_intent"
                and d == {"recovery": True}
            ):
                phase = "recovery"
            elif phase == "cleanup_observed" and e == "export_intent":
                phase = "export_i"
            elif phase == "export_i" and e == "export_observed":
                phase = "exported"
            else:
                raise StorageError("stack journal has an invalid state transition")
        if index > xs[0]["details"]["max_samples"]:
            raise StorageError("stack journal exceeds requested sample bound")

    def reserve_transaction(self, tx: str, max_samples: int) -> None:
        n = 4 * max_samples + 6
        if not _is_uuid(tx) or tx in self.reserved or n > MAX_STACK_DRIVER_EVENTS:
            raise StorageError("invalid stack journal transaction")
        if (
            len(self.records) + sum(self.reserved.values()) + n
            > MAX_STACK_JOURNAL_EVENTS
            or self.bytes + (sum(self.reserved.values()) + n) * MAX_STACK_EVENT_BYTES
            > MAX_JOURNAL_BYTES
        ):
            raise StorageError("stack journal lacks transaction headroom")
        self.reserved[tx] = n

    def release_transaction(self, tx: str) -> None:
        self.reserved.pop(tx, None)

    def append(
        self, tx: str, event: str, details: dict[str, Any] | None = None
    ) -> None:
        if not _is_uuid(tx) or event not in EVENTS:
            raise StorageError("invalid stack journal event")
        x = {
            "schema": SCHEMA,
            "transaction_id": tx,
            "endpoint_fingerprint": self.endpoint,
            "endpoint_fingerprint_scheme": ENDPOINT_FINGERPRINT_SCHEME_V2,
            "owner": OWNER,
            "event": event,
            "sequence": self.seq.get(tx, 0) + 1,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }
        if x["sequence"] > MAX_STACK_DRIVER_EVENTS or not _details(event, x["details"]):
            raise StorageError("stack journal event violates the generated contract")
        payload = canonical_json(x)
        if len(payload) > MAX_STACK_EVENT_BYTES:
            raise StorageError("stack journal event exceeds size limit")
        r = self.reserved.get(tx, 0)
        if r:
            self.reserved[tx] = r - 1
        elif (
            len(self.records) + sum(self.reserved.values()) >= MAX_STACK_JOURNAL_EVENTS
            or self.bytes
            + sum(self.reserved.values()) * MAX_STACK_EVENT_BYTES
            + len(payload)
            > MAX_JOURNAL_BYTES
        ):
            raise StorageError("stack journal limit exceeded")
        _publish_new(self.directory / f"{tx}-{x['sequence']:08d}.json", payload)
        x["_size_bytes"] = len(payload)
        self.records.append(x)
        self.seq[tx] = x["sequence"]
        self.bytes += len(payload)

    def require_recovered(
        self, debugger: Any, *, authorized: bool, running: Any
    ) -> None:
        if self.failure.exists() or _is_link_like(self.failure):
            _require_plain_file(self.failure)
            if not authorized:
                raise StorageError(
                    "stack journal previously failed; restart with --recover-quarantined"
                )
        for tx, xs in self._groups().items():
            xs.sort(key=lambda x: x["sequence"])
            self._validate(xs)
            final = xs[-1]["event"]
            owns_halt = False
            for record in xs:
                event = record["event"]
                if event == "break_intent":
                    owns_halt = True
                elif event in {
                    "go_observed",
                    "cleanup_observed",
                    "recovery_observed",
                }:
                    owns_halt = False
            if not owns_halt:
                # A post-Go cleanup marker may be unfinished, but it cannot
                # authorize resuming a later, externally stopped target.
                continue
            if not authorized:
                raise StorageError(
                    "unfinished intrusive stack capture requires --recover-quarantined"
                )
            if xs[0]["details"]["initial_running"] is not True:
                raise StorageError("ambiguous stack recovery is quarantined")
            if (
                final in {"break_intent", "break_observed", "go_intent"}
                or final == "cleanup_failed"
            ):
                self.append(tx, "cleanup_intent", {"recovery": True})
            if not running():
                debugger.go()
            if not running():
                self.mark_failure(StorageError("target did not restart"))
                raise StorageError("stack recovery could not verify target running")
            if final == "cleanup_intent" and not xs[-1]["details"]:
                self.append(tx, "cleanup_observed", {})
            else:
                self.append(
                    tx, "recovery_observed", {"recovery": True, "running": True}
                )
        if authorized and self.failure.exists():
            _require_plain_file(self.failure)
            self.failure.unlink()

    def mark_failure(self, error: Exception) -> None:
        if self.failure.exists() or _is_link_like(self.failure):
            _require_plain_file(self.failure)
            return
        _publish_new(
            self.failure,
            canonical_json(
                {
                    "schema": "t32perf.stack-journal-failure/v1",
                    "error": type(error).__name__,
                }
            ),
        )


def publish_stack_samples(
    staging: Path, session_id: str, payload: bytes
) -> dict[str, Any]:
    digest = hashlib.sha256(payload).hexdigest()
    name = f"stack-samples-{session_id}-{uuid.uuid4().hex}.json"
    _publish_new(staging / name, payload)
    return {
        "relative_path": f"capture/staging/{name}",
        "sha256": digest,
        "size_bytes": len(payload),
    }
