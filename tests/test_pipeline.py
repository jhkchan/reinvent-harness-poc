"""Tests for rail 7, the breeching: durable pipeline, brakes and sweeper."""

import os
import tempfile

import pytest

from harness.audit import AuditTrail
from harness.checkpoint import JsonCheckpointStore
from harness.pipeline import (
    FunctionPhase,
    Pipeline,
    PipelineContext,
    PipelineError,
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
    """Rerun: a new run_id starts from scratch (no skips)."""
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


def test_kill_switch_stops_before_next_phase(tmp_path):
    """A pulled brake fails the run closed before the next phase starts."""
    store = _store(tmp_path)
    brake = {"pulled": False}

    def first(ctx):
        brake["pulled"] = True  # a human pulls the brake mid-run
        return {"ok": True}

    def second(ctx):
        return {"ran": True}  # should never run

    pipe = Pipeline(
        [FunctionPhase("1_reader", first), FunctionPhase("2_mapper", second)],
        store=store, kill_switch=lambda: brake["pulled"],
    )
    ck = pipe.run(PipelineContext("t1", new_run_id(), "a1"))
    assert ck["status"] == RunStatus.FAILED.value
    assert "kill switch" in ck["error_message"]
    assert ck["completed_phases"] == ["1_reader"]


def test_kill_switch_error_fails_closed(tmp_path):
    """If the brake itself errors, the run stops (fail closed), never runs on."""
    store = _store(tmp_path)

    def broken_switch():
        raise ConnectionError("flag service unreachable")

    ran = {"n": 0}

    def phase(ctx):
        ran["n"] += 1
        return {}

    pipe = Pipeline([FunctionPhase("1_reader", phase)], store=store,
                    kill_switch=broken_switch)
    ck = pipe.run(PipelineContext("t1", new_run_id(), "a1"))
    assert ck["status"] == RunStatus.FAILED.value
    assert "ConnectionError" in ck["error_message"]
    assert ran["n"] == 0


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
    """should_skip can be data-driven (e.g. check that the output exists)."""
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


def test_reaped_run_resumes_with_a_fresh_budget(tmp_path):
    """The sweeper reaps a stalled run; a retry later still gets to finish."""
    store = _store(tmp_path)
    clock = {"t": 0.0}
    store.save("r1", {
        "run_id": "r1", "tenant_id": "t1", "analysis_id": "a1",
        "status": "in_progress", "started_at": 0.0, "heartbeat_at": 0.0,
        "completed_phases": ["1_reader"], "phase_log": [],
        "phase_outputs": {"1_reader": {"requirements": 2}},
        "state": {}, "error_message": None,
    })
    clock["t"] = 1000.0
    assert sweep_stuck(store, 300, 30, now=lambda: clock["t"]) == ["r1"]
    pipe = Pipeline([FunctionPhase("1_reader", lambda c: {"x": 1}),
                     FunctionPhase("2_mapper", lambda c: {"mapped": 1})],
                    store=store, max_duration_seconds=300, now=lambda: clock["t"])
    ck = pipe.run(PipelineContext("t1", "r1", "a1"), resume=True)
    assert ck["status"] == "completed", ck["error_message"]
    assert ck["first_started_at"] == 0.0 and ck["started_at"] == 1000.0


def test_reaped_worker_cannot_overwrite_the_terminal_state(tmp_path):
    """A slow worker whose run was reaped stops; 'failed' stays 'failed'."""
    store = _store(tmp_path)
    clock = {"t": 0.0}
    ran = {"second": 0}

    def slow(ctx):
        clock["t"] = 1000.0  # the phase outlives the budget
        sweep_stuck(store, 300, 30, now=lambda: clock["t"])  # sweeper runs now
        return {"ok": True}

    def second(ctx):
        ran["second"] += 1
        return {}

    pipe = Pipeline([FunctionPhase("1_reader", slow),
                     FunctionPhase("2_mapper", second)],
                    store=store, max_duration_seconds=300, now=lambda: clock["t"])
    ck = pipe.run(PipelineContext("t1", "r2", "a1"))
    assert ck["status"] == "failed" and "stalled" in ck["error_message"]
    assert store.load("r2")["status"] == "failed"
    assert ran["second"] == 0


def test_old_worker_cannot_overwrite_a_resumed_run(tmp_path):
    """Reaped, then resumed to completion by a new attempt: the old worker,
    still running, must not write over the completed run."""
    store = _store(tmp_path)
    clock = {"t": 0.0}
    second_pipe = {}

    def slow(ctx):
        clock["t"] = 1000.0
        sweep_stuck(store, 300, 30, now=lambda: clock["t"])        # reaped
        retry = second_pipe["p"].run(PipelineContext("t1", "r3", "a1"),
                                     resume=True)                 # resumed
        assert retry["status"] == "completed"
        return {"ok": True}

    phases = [FunctionPhase("1_reader", slow),
              FunctionPhase("2_mapper", lambda c: {"mapped": 1})]
    retry_phases = [FunctionPhase("1_reader", lambda c: {"x": 1}),
                    FunctionPhase("2_mapper", lambda c: {"mapped": 1})]
    second_pipe["p"] = Pipeline(retry_phases, store=store,
                                max_duration_seconds=300, now=lambda: clock["t"])
    old = Pipeline(phases, store=store, max_duration_seconds=300,
                   now=lambda: clock["t"])
    old.run(PipelineContext("t1", "r3", "a1"))
    final = store.load("r3")
    assert final["status"] == "completed"
    assert final["completed_phases"] == ["1_reader", "2_mapper"]


def test_a_tenant_cannot_resume_another_tenants_run(tmp_path):
    store = _store(tmp_path)
    pipe = Pipeline([FunctionPhase("1_reader", lambda c: (c.state.update(
        secret="tenant A data") or {"ok": True}))], store=store)
    pipe.run(PipelineContext("tenant-a", "r9", "a1"))
    before = store.load("r9")
    ctx_b = PipelineContext("tenant-b", "r9", "a1")
    with pytest.raises(PipelineError, match="no such run"):
        pipe.run(ctx_b, resume=True)
    assert "secret" not in ctx_b.state          # nothing leaked into B
    assert store.load("r9") == before           # A's run is untouched


def test_a_fresh_run_never_overwrites_an_existing_run(tmp_path):
    store = _store(tmp_path)
    pipe = Pipeline([FunctionPhase("1_reader", lambda c: {"ok": True})], store=store)
    pipe.run(PipelineContext("tenant-a", "r10", "a1"))
    before = store.load("r10")
    with pytest.raises(PipelineError, match="already in use"):
        pipe.run(PipelineContext("tenant-b", "r10", "b1"))
    assert store.load("r10") == before
