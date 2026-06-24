"""
pipeline.py -- DURABLE + RESUMABLE phase pipeline (ComplyKit rail 1).

This is the open-source distillation of ComplyKit's 8-phase gap-analysis
pipeline (`orchestration-api/.../phases/` + `run_multi_agent.PHASES` +
`pipeline_context.PipelineContext` + `phase_idempotency.should_skip_phase` +
`pipeline_helpers._log_pipeline_event` heartbeats + the Beat sweeper's
terminal-state guarantee).

ComplyKit pattern -> harness analogue:

  PHASES: list[(name, run_phase)]            -> PHASES registry here
  PipelineContext (tenant_id, run_id, ...)   -> PipelineContext dataclass
  should_skip_phase(sb, analysis_id, name)   -> Phase.should_skip(ctx)
  _log_pipeline_event(...heartbeat_at...)    -> Checkpoint store + heartbeat
  pipeline_runs.phase_log (JSONB array)      -> checkpoint["phase_log"]
  sweeper: reap in_progress past max+grace   -> sweep_stuck() terminal-state
  /retry  (resume same analysis_id)          -> Pipeline.run(resume=True)
  /rerun  (fresh analysis_id)                -> new run_id, resume=False

A phase that has already produced its output is SKIPPED on resume (exactly
ComplyKit's "cost on retry ~30% of a full run"). Every run reaches a terminal
state (`completed` | `failed`) within `max_duration_seconds + grace` or is
reaped by the sweeper -- the regulator-grade guarantee that no run hangs in
`in_progress` forever.

Default executor persists checkpoints to local JSON. The same ``Checkpoint``
interface is implemented by ``DynamoCheckpointStore`` (see checkpoint.py) for
the documented AWS mapping (Step Functions / SQS+Lambda + DynamoDB).
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
    """Shared state threaded through every phase (mirrors ComplyKit's
    `PipelineContext`: tenant_id / run_id / analysis_id / settings live here so
    each phase function takes a single argument)."""

    tenant_id: str
    run_id: str
    analysis_id: str
    # arbitrary shared state produced by earlier phases, consumed by later ones
    # (ComplyKit's req_checklist / mapping). Persisted in each checkpoint.
    state: Dict[str, Any] = field(default_factory=dict)
    # injected services (bedrock client, gate, raci gate, ...) -- NOT persisted
    services: Dict[str, Any] = field(default_factory=dict)


class Phase(Protocol):
    """A pipeline phase. ``name`` is its checkpoint key; ``run`` does the work;
    ``should_skip`` is ComplyKit's idempotency predicate -- 'has this phase
    already produced its expected output?' so a resumed run skips it cheaply."""

    name: str

    def should_skip(self, ctx: PipelineContext, checkpoint: Dict[str, Any]) -> bool: ...

    def run(self, ctx: PipelineContext) -> Dict[str, Any]: ...


@dataclass
class FunctionPhase:
    """Concrete Phase built from a name + run callable (+ optional skip predicate).

    The default ``should_skip`` mirrors ComplyKit: a phase is skipped iff its
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


class Pipeline:
    """Durable executor: runs phases in order, checkpointing after each, with
    heartbeats and a terminal-state/timeout guarantee.

    Resume semantics (ComplyKit /retry): load the existing checkpoint, skip
    every already-completed phase, continue from the crash point.
    Fresh semantics (ComplyKit /rerun): a brand-new run_id with an empty
    checkpoint.
    """

    def __init__(
        self,
        phases: List[Phase],
        store: CheckpointStore,
        audit: Optional[AuditTrail] = None,
        max_duration_seconds: float = 300.0,
        grace_seconds: float = 30.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.phases = phases
        self.store = store
        self.audit = audit
        self.max_duration_seconds = max_duration_seconds
        self.grace_seconds = grace_seconds
        self._now = now

    # -- checkpoint helpers --------------------------------------------------
    def _new_checkpoint(self, ctx: PipelineContext) -> Dict[str, Any]:
        ts = self._now()
        return {
            "run_id": ctx.run_id,
            "tenant_id": ctx.tenant_id,
            "analysis_id": ctx.analysis_id,
            "status": RunStatus.IN_PROGRESS.value,
            "started_at": ts,
            "heartbeat_at": ts,
            "completed_phases": [],
            "phase_log": [],          # one entry per phase boundary (ComplyKit phase_log)
            "phase_outputs": {},      # name -> output dict
            "state": dict(ctx.state),
            "error_message": None,
        }

    def _heartbeat(self, ckpt: Dict[str, Any]) -> None:
        ckpt["heartbeat_at"] = self._now()

    # -- the executor --------------------------------------------------------
    def run(self, ctx: PipelineContext, resume: bool = False) -> Dict[str, Any]:
        ckpt = self.store.load(ctx.run_id) if resume else None
        if ckpt is None:
            ckpt = self._new_checkpoint(ctx)
        else:
            # resuming: rehydrate shared state produced by earlier phases
            ctx.state.update(ckpt.get("state", {}))
            ckpt["status"] = RunStatus.IN_PROGRESS.value
            self._heartbeat(ckpt)
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
                # terminal-state guarantee: if we have blown past the budget,
                # fail closed rather than running another phase.
                if self._now() - ckpt["started_at"] > self.max_duration_seconds:
                    return self._fail(
                        ctx, ckpt,
                        f"exceeded max_duration_seconds={self.max_duration_seconds}",
                    )

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
            self.store.save(ctx.run_id, ckpt)
            if self.audit:
                self.audit.append(
                    event="pipeline_completed", actor=f"pipeline:{ctx.run_id}",
                    tenant_id=ctx.tenant_id,
                    inputs={"analysis_id": ctx.analysis_id},
                    outputs={"completed_phases": list(ckpt["completed_phases"])},
                )
            return ckpt
        except Exception as e:  # any phase crash -> terminal FAILED (fail-closed)
            return self._fail(ctx, ckpt, f"{type(e).__name__}: {e}")

    def _record_phase(
        self, ctx: PipelineContext, ckpt: Dict[str, Any], name: str,
        status: str, output: Dict[str, Any],
    ) -> None:
        """Append to phase_log + heartbeat (ComplyKit _log_pipeline_event)."""
        self._heartbeat(ckpt)
        ckpt["phase_log"].append({
            "phase": name,
            "status": status,
            "at": ckpt["heartbeat_at"],
            "output": output,
        })
        self.store.save(ctx.run_id, ckpt)
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
        self.store.save(ctx.run_id, ckpt)
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
    """Beat-sweeper analogue (ComplyKit `sweep_stuck_gap_analyses`).

    Force any run still `in_progress` past ``max_duration + grace`` -- with NO
    recent heartbeat -- into the terminal `failed` state. This is the rail that
    guarantees a crashed worker can never leave a run hanging forever. The
    heartbeat check mirrors ComplyKit: a run whose worker is still alive (recent
    heartbeat) is left alone even past the nominal budget.
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
