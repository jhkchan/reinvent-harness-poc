"""
pipeline.py -- Rail 7, the breeching (the brakes): a durable pipeline that
stops fail-closed and resumes from a checkpoint.

Regulator question: "How does it stop, and resume?"

A phase pipeline with checkpoints, heartbeats and brakes:

  PHASES: list of named phases          -> Pipeline(phases=[...])
  shared state across phases            -> PipelineContext dataclass
  idempotency: "already done?"          -> Phase.should_skip(ctx, checkpoint)
  heartbeat + phase log                 -> checkpoint["heartbeat_at"/"phase_log"]
  budget: max run time                  -> max_duration_seconds (fail closed)
  kill switch: a human pulls the brake  -> kill_switch() (fail closed)
  sweeper: reap runs with no heartbeat  -> sweep_stuck() terminal state
  retry (resume the same run)           -> Pipeline.run(resume=True)
  rerun (start fresh)                   -> new run_id, resume=False

A phase that has already produced its output is SKIPPED on resume, so a retry
costs only the work that was lost. Every run reaches a terminal state
(`completed` | `failed`) within `max_duration_seconds + grace`, or the sweeper
reaps it: no run hangs in `in_progress` forever. An error in the brake itself
(the kill switch raising) also fails the run closed.

The budget counts from the start of the current ATTEMPT (`started_at`), so a
resumed run, even one the sweeper reaped, gets a fresh budget;
`first_started_at` keeps the run's first start. A worker whose run was reaped,
or taken over by a newer attempt, stops at its next checkpoint instead of
writing over it. The JSON store checks this with a read before each write;
on DynamoDB, make it one conditional write on `attempt` and `status`.
The heartbeat moves at phase boundaries, so keep each phase shorter than the
budget.

Default executor persists checkpoints to local JSON (checkpoint.py documents
a DynamoDB adapter).

AWS covers: Lambda durable functions (checkpointed steps, long waits), Step
Functions, and Gateway rate limits (which fail open on transient errors). You
still own who may pull the brake, budgets, idempotency and which state is
authoritative. See the README rail table.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol

from .audit import AuditTrail


class RunStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class PipelineContext:
    """Shared state threaded through every phase (tenant_id / run_id /
    analysis_id / settings live here so each phase function takes a single
    argument)."""

    tenant_id: str
    run_id: str
    analysis_id: str
    # arbitrary shared state produced by earlier phases, consumed by later ones
    # (e.g. a requirement checklist or a mapping). Persisted in each checkpoint.
    state: Dict[str, Any] = field(default_factory=dict)
    # injected services (bedrock client, gate, raci gate, ...) -- NOT persisted
    services: Dict[str, Any] = field(default_factory=dict)


class Phase(Protocol):
    """A pipeline phase. ``name`` is its checkpoint key; ``run`` does the work;
    ``should_skip`` is the idempotency predicate -- 'has this phase
    already produced its expected output?' so a resumed run skips it cheaply."""

    name: str

    def should_skip(self, ctx: PipelineContext, checkpoint: Dict[str, Any]) -> bool: ...

    def run(self, ctx: PipelineContext) -> Dict[str, Any]: ...


@dataclass
class FunctionPhase:
    """Concrete Phase built from a name + run callable (+ optional skip predicate).

    The default ``should_skip``: a phase is skipped iff its
    output already exists in the checkpoint's ``phase_outputs`` -- i.e. it ran
    to completion in a previous attempt.
    """

    name: str
    fn: Callable[[PipelineContext], Dict[str, Any]]
    skip_predicate: Optional[Callable[[PipelineContext, Dict[str, Any]], bool]] = None

    def should_skip(self, ctx: PipelineContext, checkpoint: Dict[str, Any]) -> bool:
        if self.skip_predicate is not None:
            return self.skip_predicate(ctx, checkpoint)
        completed = checkpoint.get("completed_phases", [])
        return self.name in completed

    def run(self, ctx: PipelineContext) -> Dict[str, Any]:
        return self.fn(ctx)


class CheckpointStore(Protocol):
    """Where per-run checkpoints (phase_log + heartbeat + status) are persisted.
    JSON-file by default; DynamoDB adapter documented for AWS."""

    def load(self, run_id: str) -> Optional[Dict[str, Any]]: ...
    def save(self, run_id: str, checkpoint: Dict[str, Any]) -> None: ...
    def list_runs(self) -> List[Dict[str, Any]]: ...


class PipelineError(RuntimeError):
    pass


class RunReaped(PipelineError):
    """This attempt no longer owns the run (reaped, or resumed elsewhere)."""


_TERMINAL = (RunStatus.COMPLETED.value, RunStatus.FAILED.value)


class Pipeline:
    """Durable executor: runs phases in order, checkpointing after each, with
    heartbeats and a terminal-state/timeout guarantee.

    Resume semantics (retry): load the existing checkpoint, skip every
    already-completed phase, continue from the crash point.
    Fresh semantics (rerun): a brand-new run_id with an empty checkpoint.

    Brakes: before each phase the run fails closed if it is over budget
    (``max_duration_seconds``) or if ``kill_switch()`` returns True.
    """

    def __init__(
        self,
        phases: List[Phase],
        store: CheckpointStore,
        audit: Optional[AuditTrail] = None,
        max_duration_seconds: float = 300.0,
        grace_seconds: float = 30.0,
        now: Callable[[], float] = time.time,
        kill_switch: Callable[[], bool] = lambda: False,
    ) -> None:
        self.phases = phases
        self.store = store
        self.audit = audit
        self.max_duration_seconds = max_duration_seconds
        self.grace_seconds = grace_seconds
        self._now = now
        self.kill_switch = kill_switch

    # -- checkpoint helpers --------------------------------------------------
    def _new_checkpoint(self, ctx: PipelineContext) -> Dict[str, Any]:
        ts = self._now()
        return {
            "run_id": ctx.run_id,
            "tenant_id": ctx.tenant_id,
            "analysis_id": ctx.analysis_id,
            "status": RunStatus.IN_PROGRESS.value,
            "first_started_at": ts,
            "started_at": ts,         # start of the current attempt
            "heartbeat_at": ts,
            "completed_phases": [],
            "phase_log": [],          # one entry per phase boundary
            "phase_outputs": {},      # name -> output dict
            "state": dict(ctx.state),
            "error_message": None,
        }

    def _heartbeat(self, ckpt: Dict[str, Any]) -> None:
        ckpt["heartbeat_at"] = self._now()

    def _save(self, ctx: PipelineContext, ckpt: Dict[str, Any]) -> None:
        """Save, unless this attempt no longer owns the run: the sweeper ended
        it, or a newer attempt (a resume) took it over."""
        stored = self.store.load(ctx.run_id)
        if stored and (stored.get("attempt") != ckpt.get("attempt")
                       or stored.get("status") in _TERMINAL):
            raise RunReaped(stored.get("error_message") or stored["status"])
        self.store.save(ctx.run_id, ckpt)

    # -- the executor --------------------------------------------------------
    def run(self, ctx: PipelineContext, resume: bool = False) -> Dict[str, Any]:
        ckpt = self.store.load(ctx.run_id)
        if not resume and ckpt is not None:
            # a fresh run must never overwrite a run that already exists
            raise PipelineError("run id already in use; use new_run_id()")
        if ckpt is not None and (ckpt.get("tenant_id") != ctx.tenant_id
                                 or ckpt.get("analysis_id") != ctx.analysis_id):
            # same generic answer as a missing run: never load another
            # tenant's state, and never say whose run it is
            raise PipelineError("no such run for this tenant")
        if ckpt is None:
            ckpt = self._new_checkpoint(ctx)
        else:
            # resuming: rehydrate shared state produced by earlier phases,
            # and start a fresh budget for this attempt
            ctx.state.update(ckpt.get("state", {}))
            ckpt.setdefault("first_started_at", ckpt["started_at"])
            ckpt["started_at"] = self._now()
            ckpt["status"] = RunStatus.IN_PROGRESS.value
            ckpt["error_message"] = None
            self._heartbeat(ckpt)
        ckpt["attempt"] = uuid.uuid4().hex[:8]
        self.store.save(ctx.run_id, ckpt)

        if self.audit:
            self.audit.append(
                event="pipeline_started" if not resume else "pipeline_resumed",
                actor=f"pipeline:{ctx.run_id}",
                tenant_id=ctx.tenant_id,
                inputs={"analysis_id": ctx.analysis_id, "resume": resume},
                outputs={"completed_so_far": list(ckpt["completed_phases"])},
            )

        try:
            for phase in self.phases:
                # Brakes before every phase: an error here fails closed too.
                # [snippet:rail-7]
                spent = self._now() - ckpt["started_at"]
                if spent > self.max_duration_seconds:
                    return self._fail(
                        ctx, ckpt, "exceeded max_duration_seconds="
                        f"{self.max_duration_seconds}")
                if self.kill_switch():  # someone pulled the brake
                    return self._fail(ctx, ckpt, "kill switch pulled")
                # [/snippet]

                if phase.should_skip(ctx, ckpt):
                    self._record_phase(ctx, ckpt, phase.name, status="skipped",
                                       output=ckpt["phase_outputs"].get(phase.name, {}))
                    continue

                output = phase.run(ctx) or {}
                ckpt["phase_outputs"][phase.name] = output
                if phase.name not in ckpt["completed_phases"]:
                    ckpt["completed_phases"].append(phase.name)
                ckpt["state"] = dict(ctx.state)
                self._record_phase(ctx, ckpt, phase.name, status="completed", output=output)

            ckpt["status"] = RunStatus.COMPLETED.value
            ckpt["completed_at"] = self._now()
            self._heartbeat(ckpt)
            self._save(ctx, ckpt)
            if self.audit:
                self.audit.append(
                    event="pipeline_completed", actor=f"pipeline:{ctx.run_id}",
                    tenant_id=ctx.tenant_id,
                    inputs={"analysis_id": ctx.analysis_id},
                    outputs={"completed_phases": list(ckpt["completed_phases"])},
                )
            return ckpt
        except RunReaped:  # the sweeper ended this attempt: keep its verdict
            return self.store.load(ctx.run_id)
        except Exception as e:  # any phase crash -> terminal FAILED (fail-closed)
            return self._fail(ctx, ckpt, f"{type(e).__name__}: {e}")

    def _record_phase(
        self, ctx: PipelineContext, ckpt: Dict[str, Any], name: str,
        status: str, output: Dict[str, Any],
    ) -> None:
        """Append to phase_log + heartbeat."""
        self._heartbeat(ckpt)
        ckpt["phase_log"].append({
            "phase": name,
            "status": status,
            "at": ckpt["heartbeat_at"],
            "output": output,
        })
        self._save(ctx, ckpt)
        if self.audit:
            self.audit.append(
                event="phase_transition", actor=f"pipeline:{ctx.run_id}",
                tenant_id=ctx.tenant_id,
                inputs={"phase": name},
                outputs={"status": status, "metrics": output},
            )

    def _fail(self, ctx: PipelineContext, ckpt: Dict[str, Any], msg: str) -> Dict[str, Any]:
        ckpt["status"] = RunStatus.FAILED.value
        ckpt["error_message"] = msg
        ckpt["completed_at"] = self._now()
        self._heartbeat(ckpt)
        try:
            self._save(ctx, ckpt)
        except RunReaped:
            return self.store.load(ctx.run_id)
        if self.audit:
            self.audit.append(
                event="pipeline_failed", actor=f"pipeline:{ctx.run_id}",
                tenant_id=ctx.tenant_id,
                inputs={"analysis_id": ctx.analysis_id},
                outputs={"error_message": msg,
                         "completed_phases": list(ckpt["completed_phases"])},
            )
        return ckpt


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def sweep_stuck(
    store: CheckpointStore,
    max_duration_seconds: float,
    grace_seconds: float = 30.0,
    now: Callable[[], float] = time.time,
    audit: Optional[AuditTrail] = None,
) -> List[str]:
    """Sweeper: reap runs that stopped sending heartbeats.

    Force any run still `in_progress` past ``max_duration + grace`` -- with NO
    recent heartbeat -- into the terminal `failed` state. This is the rail that
    guarantees a crashed worker can never leave a run hanging forever. A run
    whose worker is still alive (recent heartbeat) is left alone even past
    the nominal budget.
    """
    reaped: List[str] = []
    t = now()
    cutoff = max_duration_seconds + grace_seconds
    for ckpt in store.list_runs():
        if ckpt.get("status") != RunStatus.IN_PROGRESS.value:
            continue
        age = t - ckpt.get("started_at", t)
        if age <= cutoff:
            continue
        # heartbeat guard: still-alive worker is not stuck
        hb_age = t - ckpt.get("heartbeat_at", ckpt.get("started_at", t))
        if hb_age <= max_duration_seconds:
            continue
        ckpt["status"] = RunStatus.FAILED.value
        ckpt["error_message"] = (
            f"Pipeline stalled -- worker may have crashed (exceeded {cutoff:.0f}s)"
        )
        ckpt["completed_at"] = t
        store.save(ckpt["run_id"], ckpt)
        reaped.append(ckpt["run_id"])
        if audit:
            audit.append(
                event="run_reaped", actor="sweeper",
                tenant_id=ckpt.get("tenant_id", ""),
                inputs={"run_id": ckpt["run_id"], "age_seconds": round(age, 1)},
                outputs={"status": "failed", "reason": ckpt["error_message"]},
            )
    return reaped
