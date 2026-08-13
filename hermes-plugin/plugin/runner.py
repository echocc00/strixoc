"""ScanManager: owns the scan lifecycle on the hermes side.

- Authorization gate (allowlist + confirm flag) before anything starts.
- Runs the scan in a background task via a StrixBackend, streaming events
  (phase / vuln / finished) to per-scan subscribers and to the in-memory
  record; every state change is persisted to ``scans_db``.
- Cancellation, history, per-scan report accessors for the tools layer.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from authz import AuthDecision, audit, check_authorization
from backends import (
    BackendConfigError,
    InProcessBackend,
    WorkerBackend,
    build_scan_config,
)

Listener = Callable[[str, Any], None]  # (kind, payload)

DEFAULT_MAX_BUDGET = 5.0


class AuthError(Exception):
    def __init__(self, decision: AuthDecision, message: str) -> None:
        super().__init__(message)
        self.decision = decision
        self.message = message


@dataclass
class ScanRecord:
    scan_id: str
    status: str  # running | finished | failed | cancelled
    target: str
    scan_mode: str
    budget: float | None
    chat_id: str
    user_id: str
    created_at: str
    updated_at: str = ""
    run_dir: str | None = None
    error: str | None = None
    phase: str = ""
    vuln_count: int = 0
    report_head: str = ""
    by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanRecord":
        kwargs = {k: d.get(k) for k in cls.__dataclass_fields__}
        return cls(**kwargs)


class ScanManager:
    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        backend=None,
        scans_db: str | None = None,
    ) -> None:
        import config as cfgmod

        self._cfg = cfgmod.load_config(path="auto") if cfg is None else cfg
        self._db_path = Path(scans_db or os.path.expanduser(str(
            self._cfg.get("scans_db") or "~/.hermes/logs/strix-scans.json")))
        wpy = str(self._cfg.get("worker_python") or "")
        self._backend = backend or (
            WorkerBackend(worker_python=wpy, runs_cwd=str(self._cfg.get("runs_cwd") or ""))
            if wpy else _auto_backend(self._cfg)
        )
        self._records: dict[str, ScanRecord] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._listeners: dict[str, list[Listener]] = {}
        self._all_listeners: list[Callable[[str, str, Any], None]] = []
        self._lock = threading.Lock()
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict) and d.get("scan_id"):
                    self._records[d["scan_id"]] = ScanRecord.from_dict(d)

    def _persist(self) -> None:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        with self._lock:
            rows = [r.to_dict() for r in sorted(
                self._records.values(), key=lambda r: r.created_at, reverse=True)]
        tmp = self._db_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self._db_path)
        except OSError:
            pass

    # -- lifecycle -----------------------------------------------------------

    def authorize_or_raise(self, *, target: str, chat_id: str, user_id: str, confirm: bool) -> None:
        """Pure authorization gate for non-scan actions (e.g. delegation)."""
        decision = check_authorization(
            self._cfg, chat_id=chat_id, user_id=user_id, target=target, confirm=confirm
        )
        if not decision.allowed:
            raise AuthError(decision, f"not authorized: {decision.reason}")

    async def start(
        self,
        target: str,
        *,
        scan_mode: str = "quick",
        budget: float | None = None,
        user_instructions: str = "",
        chat_id: str = "cli",
        user_id: str = "",
        confirm: bool = False,
    ) -> ScanRecord:
        if budget is None:
            budget = float(self._cfg.get("max_budget_default") or DEFAULT_MAX_BUDGET)
        cap = float(self._cfg.get("max_budget_cap") or 0) or None
        if cap and budget > cap:
            raise AuthError(
                AuthDecision(False, "budget_over_cap"),
                f"budget ${budget} exceeds max_budget_cap ${cap}",
            )
        decision = check_authorization(
            self._cfg, chat_id=chat_id, user_id=user_id, target=target, confirm=confirm
        )
        if not decision.allowed:
            raise AuthError(decision, f"not authorized: {decision.reason}")
        audit(self._cfg, action="scan_start", chat_id=chat_id, user_id=user_id,
              target=target, scan_mode=scan_mode, budget=budget,
              decision="allowed")

        scan_id = f"strix-{uuid.uuid4().hex[:8]}"
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        record = ScanRecord(
            scan_id=scan_id, status="running", target=target, scan_mode=scan_mode,
            budget=budget, chat_id=chat_id, user_id=user_id,
            created_at=now, updated_at=now,
        )
        self._records[scan_id] = record
        self._persist()

        request = {
            "scan_id": scan_id,
            "scan_config": build_scan_config(
                target=target, scan_mode=scan_mode, user_instructions=user_instructions,
                run_name=scan_id, scan_id=scan_id,
            ),
            "max_budget_usd": budget,
        }
        cancel_event = asyncio.Event()
        self._cancel_events[scan_id] = cancel_event
        self._tasks[scan_id] = asyncio.ensure_future(
            self._run(request, record, cancel_event)
        )
        return record

    async def _run(self, request: dict, record: ScanRecord, cancel_event: asyncio.Event) -> None:
        scan_id = record.scan_id

        def forward(kind: str, payload: Any) -> None:
            if kind == "phase" and isinstance(payload, str):
                self._bump(record, phase=payload)
            elif kind == "vuln" and isinstance(payload, dict):
                sev = str(payload.get("severity", "info")).lower()
                sev_counts = dict(record.by_severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                self._bump(record, by_severity=sev_counts, vuln_count=record.vuln_count + 1)
            for fn in list(self._listeners.get(scan_id, [])):
                try:
                    fn(kind, payload)
                except Exception:  # noqa: BLE001
                    pass
            for fn in list(self._all_listeners):
                try:
                    fn(scan_id, kind, payload)
                except Exception:  # noqa: BLE001
                    pass

        try:
            outcome = await self._backend.start(request, forward, cancel_event)
        except asyncio.CancelledError:
            self._bump(record, status="cancelled", error="cancelled")
            raise
        except BackendConfigError as exc:
            self._bump(record, status="failed", error=f"config: {exc}")
            audit(self._cfg, action="scan_failed", scan_id=scan_id, target=record.target,
                  error=str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self._bump(record, status="failed", error=f"{type(exc).__name__}: {exc}")
            return
        else:
            if outcome.ok and outcome.run_dir:
                self._bump(record, status="finished", run_dir=outcome.run_dir)
            else:
                self._bump(record, status="failed", error=outcome.error or "unknown failure")
            audit(self._cfg, action="scan_end", scan_id=scan_id, target=record.target,
                  status=record.status, run_dir=record.run_dir)
        finally:
            self._cancel_events.pop(scan_id, None)
            self._tasks.pop(scan_id, None)
            done_payload = {"scan_id": scan_id, "status": record.status,
                            "error": record.error, "by_severity": record.by_severity,
                            "vuln_count": record.vuln_count}
            for fn in list(self._listeners.pop(scan_id, [])):
                try:
                    fn("finished", done_payload)
                except Exception:  # noqa: BLE001
                    pass
            for fn in list(self._all_listeners):
                try:
                    fn(scan_id, "finished", done_payload)
                except Exception:  # noqa: BLE001
                    pass

    def _bump(self, record: ScanRecord, **fields: Any) -> None:
        for k, v in fields.items():
            setattr(record, k, v)
        record.updated_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        self._persist()

    # -- accessors -----------------------------------------------------------

    def get(self, scan_id: str) -> dict[str, Any] | None:
        rec = self._records.get(scan_id)
        return rec.to_dict() if rec else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = sorted(self._records.values(), key=lambda r: r.created_at, reverse=True)
        return [r.to_dict() for r in rows[:limit]]

    def history(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.list_scans(limit=limit)

    def cancel(self, scan_id: str) -> bool:
        ev = self._cancel_events.get(scan_id)
        rec = self._records.get(scan_id)
        if ev is None or rec is None or rec.status != "running":
            return False
        ev.set()
        audit(self._cfg, action="scan_cancel", scan_id=scan_id, target=rec.target)
        return True

    def subscribe(self, scan_id: str, fn: Listener) -> bool:
        if scan_id not in self._records:
            return False
        self._listeners.setdefault(scan_id, []).append(fn)
        return True

    def subscribe_all(self, fn: Callable[[str, str, Any], None]) -> None:
        """Listen to every scan's events: fn(scan_id, kind, payload)."""
        if fn not in self._all_listeners:
            self._all_listeners.append(fn)

    async def wait_idle(self, seconds: float = 5.0) -> None:
        deadline = asyncio.get_event_loop().time() + seconds
        while self._tasks and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.05)

    def health(self) -> dict[str, Any]:
        worker_python = os.environ.get("STRIX_WORKER_PYTHON") or str(
            self._cfg.get("worker_python") or "")
        backend_name = getattr(self._backend, "name", type(self._backend).__name__)
        return {
            "backend": backend_name,
            "worker_python_configured": bool(worker_python),
            "allowed_targets": list(self._cfg.get("allowed_targets") or []),
            "require_authorized_flag": bool(self._cfg.get("require_authorized_flag", True)),
            "max_budget_default": self._cfg.get("max_budget_default"),
            "max_budget_cap": self._cfg.get("max_budget_cap"),
            "running_scans": [s for s in self._records.values() if s.status == "running"],
            "total_scans": len(self._records),
            "audit_log": os.path.expanduser(str(self._cfg.get("audit_log") or "")),
        }


def _auto_backend(cfg: dict[str, Any]) -> Any:
    """Pick worker (production) vs in-process (py>=3.12 dev) backend."""
    import sys

    wpy = str(cfg.get("worker_python") or "") or os.environ.get("STRIX_WORKER_PYTHON") or ""
    if wpy:
        return WorkerBackend(worker_python=wpy, runs_cwd=str(cfg.get("runs_cwd") or ""))
    if sys.version_info >= (3, 12):
        try:
            import strix  # noqa: F401
        except ImportError:
            return WorkerBackend(runs_cwd=str(cfg.get("runs_cwd") or ""))
        return InProcessBackend()
    return WorkerBackend(runs_cwd=str(cfg.get("runs_cwd") or ""))


_MANAGER: ScanManager | None = None


def get_manager(cfg: dict[str, Any] | None = None) -> ScanManager:
    """Plugin-wide singleton.  Pass ``cfg`` to (re)build (tests inject fakes
    by replacing this function or passing ``cfg``)."""
    global _MANAGER
    if cfg is not None or _MANAGER is None:
        _MANAGER = ScanManager(cfg)
    return _MANAGER