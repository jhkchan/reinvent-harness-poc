"""Tests for RAIL 1: durable + resumable pipeline (ComplyKit phases/idempotency/sweeper)."""

import os
import tempfile

import pytest

from harness.audit import AuditTrail
from harness.checkpoint import JsonCheckpointStore
from harness.pipeline import (
    FunctionPhase,
    Pipeline,
    PipelineContext,
    RunStatus,
    new_run_id,
    sweep_stuck,
)


def _store(tmp_path):
    return JsonCheckpointStore(os.path.join(tmp_path, "ck.json"))


def _phases(crash_box):
    def reader(ctx):
        ctx.state["req"] = ["R1", "R2"]
        return {"requirements": 2}

    def mapper(ctx):
        ctx.state["map"] = {"R1": "p1"}
        return {"mapped": 1}

    def assessor(ctx):
        crash_box["n"] += 1
        if crash_box["n"] == 1:
            raise RuntimeError("simulated crash")
        ctx.state["gaps"] = 1
        return {"gaps": 1}

    def reviewer(ctx):
        return {"validated": True}

    return [
        FunctionPhase("1_reader", reader),
        FunctionPhase("2_mapper", mapper),
        FunctionPhase("3_assessor", assessor),
        FunctionPhase("5_reviewer", reviewer),
    ]


def test_crash_then_resume_skips_completed_phases(tmp_path):
    store = _store(tmp_path)
    crash = {"n": 0}
    pipe = Pipeline(_phases(crash), store=store)
    rid = new_run_id()

    ctx = PipelineContext(tenant_id="t1", run_id=rid, analysis_id="a1")
    ck1 = pipe.run(ctx)
    assert ck1["status"] == RunStatus.FAILED.value
    assert ck1["completed_phases"] == ["1_reader", "2_mapper"]

    ctx2 = PipelineContext(tenant_id="t1", run_id=rid, analysis_id="a1")
    ck2 = pipe.run(ctx2, resume=True)
    assert ck2["status"] == RunStatus.COMPLETED.value
    assert ck2["completed_phases"] == ["1_reader", "2_mapper", "3_assessor", "5_reviewer"]
    skipped = [e["phase"] for e in ck2["phase_log"] if e["status"] == "skipped"]
    assert skipped == ["1_reader", "2_mapper"]
    assert crash["n"] == 2  # assessor re-ran exactly once


def test_resume_rehydrates_shared_state(tmp_path):
    """State produced by earlier phases survives a crash + resume."""
    store = _store(tmp_path)
    crash = {"n": 0}
    pipe = Pipeline(_phases(crash), store=store)
    rid = new_run_id()
    pipe.run(PipelineContext("t1", rid, "a1"))
    ctx2 = PipelineContext("t1", rid, "a1")
    pipe.run(ctx2, resume=True)
    # reader's req[] and mapper's map{} were rehydrated from the checkpoint
    assert ctx2.state.get("req") == ["R1", "R2"]
    assert ctx2.state.get("map") == {"R1": "p1"}


def test_fresh_rerun_uses_new_run_id_and_replays(tmp_path):
    """ComplyKit /rerun: a new run_id starts from scratch (no skips)."""
    store = _store(tmp_path)
    pipe = Pipeline(_phases({"n": 5}), store=store)  # n>1 so assessor never crashes
    rid = new_run_id()
    ck = pipe.run(PipelineContext("t1", rid, "a1"))
    assert ck["status"] == RunStatus.COMPLETED.value
    assert all(e["status"] == "completed" for e in ck["phase_log"])


def test_max_duration_forces_terminal_state(tmp_path):
    """Blowing the time budget fails the run closed rather than continuing."""
    store = _store(tmp_path)
    clock = {"t": 0.0}

    def slow_reader(ctx):
        clock["t"] += 1000  # jump past the budget
        return {"ok": True}

    def second(ctx):
        return {"ran": True}  # should never run

    pipe = Pipeline(
        [FunctionPhase("1_reader", slow_reader), FunctionPhase("2_mapper", second)],
        store=store, max_duration_seconds=10, now=lambda: clock["t"],
    )
    ck = pipe.run(PipelineContext("t1", new_run_id(), "a1"))
    assert ck["status"] == RunStatus.FAILED.value
    assert "max_duration" in ck["error_message"]
    assert ck["completed_phases"] == ["1_reader"]  # second phase never ran


def test_sweeper_reaps_stalled_run(tmp_path):
    store = _store(tmp_path)
    store.save("stuck", {
        "run_id": "stuck", "tenant_id": "t1", "analysis_id": "a1",
        "status": "in_progress", "started_at": 0.0, "heartbeat_at": 0.0,
        "completed_phases": [], "phase_log": [], "phase_outputs": {},
        "state": {}, "error_message": None,
    })
    reaped = sweep_stuck(store, max_duration_seconds=300, grace_seconds=30, now=lambda: 1000.0)
    assert reaped == ["stuck"]
    assert store.load("stuck")["status"] == "failed"
    assert "stalled" in store.load("stuck")["error_message"]


def test_sweeper_leaves_live_run_with_recent_heartbeat(tmp_path):
    store = _store(tmp_path)
    # old started_at but a RECENT heartbeat -> worker still alive, not reaped.
    store.save("alive", {
        "run_id": "alive", "tenant_id": "t1", "analysis_id": "a1",
        "status": "in_progress", "started_at": 0.0, "heartbeat_at": 950.0,
        "completed_phases": [], "phase_log": [], "phase_outputs": {},
        "state": {}, "error_message": None,
    })
    reaped = sweep_stuck(store, max_duration_seconds=300, grace_seconds=30, now=lambda: 1000.0)
    assert reaped == []
    assert store.load("alive")["status"] == "in_progress"


def test_custom_skip_predicate(tmp_path):
    """should_skip can be data-driven (ComplyKit checks DB output existence)."""
    store = _store(tmp_path)
    ran = {"n": 0}

    def work(ctx):
        ran["n"] += 1
        return {"did": True}

    # skip predicate: skip if checkpoint already recorded this phase's output
    phase = FunctionPhase(
        "p", work,
        skip_predicate=lambda ctx, ck: "p" in ck.get("phase_outputs", {}),
    )
    pipe = Pipeline([phase], store=store)
    rid = new_run_id()
    pipe.run(PipelineContext("t1", rid, "a1"))
    pipe.run(PipelineContext("t1", rid, "a1"), resume=True)
    assert ran["n"] == 1  # second run skipped via predicate
