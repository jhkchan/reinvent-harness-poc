"""
demo.py -- runnable demonstration of the seven rails, in the talk's order.

Models a tiny multi-tenant review run and proves each rail, clearly
labelled. Only rail 3's judge fallback calls LIVE Bedrock (one Nova micro
`converse` call, ~zero cost); every other rail runs locally:

  RAIL 1  BIT (permission gate)     -- a destructive command is DENIED even
          under a broad allow: the blocklist wins.
  RAIL 2  BLINKERS (tool + tenant)  -- tenant B is DENIED tenant A's review;
          an unknown id, a missing tenant id and an off-surface tool are
          DENIED.
  RAIL 3  REINS (named human)       -- RACI from a deterministic matrix HIT,
          approved only by its named Accountable; a matrix MISS filled by the
          Bedrock judge (flagged, provisional until that person signs off).
  RAIL 4  HOOFPRINTS (audit)        -- the hash chain verifies intact, an edit
          to a past entry is detected, and a dropped tail is caught against
          an anchor.
  RAIL 5  GROUND-DRIVING (eval)     -- a hard check blocks a candidate before
          any model call.
  RAIL 6  STALL (isolated runtime)  -- not run here (it creates AWS resources);
          run `make sandbox-live`. See logs/sandbox.log.
  RAIL 7  BREECHING (brakes)        -- a run crashes and resumes from its
          checkpoint, the kill switch stops a run, and the sweeper reaps a
          stalled run.

Exits 1 with DEMO INCOMPLETE if rail 3's judge gives no usable answer.

Run:  python -m harness.demo   (default AWS credential chain, us-east-1)
"""

from __future__ import annotations

import os
import sys
import tempfile

import boto3

from .audit import AuditTrail
from .checkpoint import JsonCheckpointStore
from .eval_gate import EvalGate
from .permission_gate import Decision, PermissionGate
from .pipeline import (
    FunctionPhase,
    Pipeline,
    PipelineContext,
    new_run_id,
    sweep_stuck,
)
from .raci_gate import Bearer, MatrixRule, RaciGate
from .tenant_gate import REVIEW_TOOLS, TenantScopedGate

PROFILE = os.environ.get("AWS_PROFILE") or None   # None = default chain
REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ.get("HARNESS_MODEL_ID", "us.amazon.nova-micro-v1:0")

BAR = "=" * 74
TENANT_A = "tenant-a-bank"
TENANT_B = "tenant-b-insurer"


def _hdr(title: str) -> None:
    print("\n" + BAR)
    print(title)
    print(BAR)


def main() -> int:
    print("reinvent-harness-poc demo  (seven rails for a regulated agent)")
    print(f"region={REGION} model={MODEL_ID} credentials=default chain")

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    bedrock = session.client("bedrock-runtime")

    workdir = tempfile.mkdtemp(prefix="harness-demo-")
    audit = AuditTrail(path=os.path.join(workdir, "audit.jsonl"))
    store = JsonCheckpointStore(os.path.join(workdir, "checkpoints.json"))
    print("workdir: <tmp>/" + os.path.basename(workdir))

    # =====================================================================
    # RAIL 1: BIT -- permission gate (who allowed this tool call?)
    # =====================================================================
    _hdr("RAIL 1 BIT: permission gate (deny beats a broad allow)")
    bit = PermissionGate(tool_config={"run_bash": "allow"},
                         glob_overrides={"*": "allow"})
    for cmd in ("rm -rf /", "ls -la"):
        r = bit.before_tool("run_bash", {"command": cmd})
        print(f"  run_bash {cmd!r:<12} -> {r.decision.value.upper():<5} "
              f"[{r.rule}] {r.reason}")
        audit.append("tool_call", "agent:tenantA", TENANT_A,
                     {"tool": "run_bash", "command": cmd},
                     {"decision": r.decision.value, "rule": r.rule})
    assert bit.before_tool("run_bash", {"command": "rm -rf /"}).decision \
        is Decision.DENY
    print("  PROOF: the blocklist wins over a '*: allow' override. OK")

    # =====================================================================
    # RAIL 2: BLINKERS -- tool and tenant scope (what can the agent see?)
    # =====================================================================
    _hdr("RAIL 2 BLINKERS: tool and tenant scope")
    review_id = "REVIEW-" + new_run_id()
    owners = {review_id: TENANT_A}

    def resource_owner(tool_name, args):
        rid = args.get("review_id")
        return owners.get(rid) if rid else None

    gate = TenantScopedGate(
        permission_gate=PermissionGate(
            tool_config={t: "allow" for t in REVIEW_TOOLS},
        ),
        resource_owner=resource_owner,
        require_tenant_id=True,
    )
    tool = "get_review"
    args = {"review_id": review_id}
    print(f"  review tool surface: {len(REVIEW_TOOLS)} tools")

    r = gate.before_tool(tool, TENANT_A, args)
    print(f"  (2a) tenant A -> {tool} on its OWN review: "
          f"{r.decision.value.upper()} [{r.rule}]")
    audit.append("tool_call", "agent:tenantA", TENANT_A, {"tool": tool, **args},
                 {"decision": r.decision.value, "rule": r.rule})
    assert r.allowed, r

    r = gate.before_tool(tool, TENANT_B, args)
    print(f"  (2b) tenant B -> {tool} on tenant A's review: "
          f"{r.decision.value.upper()} [{r.rule}]  -- {r.reason}")
    audit.append("tool_call", "agent:tenantB", TENANT_B, {"tool": tool, **args},
                 {"decision": r.decision.value, "rule": r.rule})
    assert r.decision is Decision.DENY and r.rule == "cross-tenant", r

    r = gate.before_tool(tool, None, args)
    print(f"  (2c) no tenant id -> {r.decision.value.upper()} [{r.rule}]  "
          f"-- {r.reason}")
    assert r.decision is Decision.DENY and r.rule == "require-tenant-id", r

    r = gate.before_tool("drop_all_tables", TENANT_A, {})
    print(f"  (2d) tenant A -> 'drop_all_tables' (off the surface): "
          f"{r.decision.value.upper()} [{r.rule}]")
    assert r.decision is Decision.DENY and r.rule == "tool-allowlist", r

    r = gate.before_tool(tool, TENANT_A, {"review_id": "REVIEW-unknown"})
    print(f"  (2e) tenant A -> {tool} on an unknown id: "
          f"{r.decision.value.upper()} [{r.rule}]  -- {r.reason}")
    assert r.decision is Decision.DENY and r.rule == "cross-tenant", r
    print("  PROOF: cross-tenant, unknown id, missing tenant and off-surface "
          "tools all DENIED. OK")

    # =====================================================================
    # RAIL 3: REINS -- named-human approval (whose name is on this?)
    # =====================================================================
    _hdr("RAIL 3 REINS: RACI matrix, named approval, judge fallback on MISS")
    bearers = [
        Bearer("b-risk", "Chief Risk Officer",
               scope="capital adequacy, risk, liquidity"),
        Bearer("b-fin", "Head of Finance", scope="finance, treasury, capital"),
        Bearer("b-comp", "Compliance Officer",
               scope="compliance, regulatory reporting"),
        Bearer("b-ops", "Head of Operations",
               scope="operations, settlement, custody"),
    ]
    matrix = [
        MatrixRule("capital%", r_role="Head of Finance",
                   a_role="Chief Risk Officer",
                   c_roles=["Compliance Officer"], i_roles=[], priority=100),
        MatrixRule("liquidity%", r_role="Chief Risk Officer",
                   a_role="Chief Risk Officer", priority=90),
    ]
    raci = RaciGate(matrix=matrix, bearers=bearers, bedrock_runtime=bedrock,
                    model_id=MODEL_ID, audit=audit, tenant_id=TENANT_A)

    a1 = raci.assign("capital adequacy", action_id="ACT-1")
    print(f"  (3a) matrix HIT  : {a1.summary()}")
    assert a1.matrix_hit and not a1.used_llm_fallback, a1
    assert a1.raci_reasoning["r"]["source"] == "matrix"

    wrong = raci.approve(a1, "ACT-1", approver_id="b-fin")
    right = raci.approve(a1, "ACT-1", approver_id="b-risk")
    print(f"  (3a) approval by b-fin : approved={wrong.approved} ({wrong.reason})")
    print(f"  (3a) approval by b-risk: approved={right.approved} ({right.reason})")
    assert not wrong.approved and right.approved

    a2 = raci.assign("cybersecurity incident response", action_id="ACT-2")
    print(f"  (3b) matrix MISS : {a2.summary()}")
    assert not a2.matrix_hit, a2
    a_entry = a2.raci_reasoning.get("a")
    judge_proved = bool(a_entry) and a_entry["source"] == "llm_fallback"
    if judge_proved:
        print(f"       judge picked A={a_entry['bearer_name']} "
              f"(source={a_entry['source']}) "
              f"reason={a_entry['reasoning'][:70]!r}")
        assert a_entry["source"] == "llm_fallback" and a2.needs_confirmation
        print("       the LLM never approves: ACT-2 waits for "
              f"{a_entry['bearer_name']}'s own sign-off.")
        print("  PROOF: the matrix decided 3a and only its named Accountable "
              "could approve; the judge's pick for 3b is flagged and "
              "provisional. OK")
    elif raci.last_error:
        print(f"  SKIPPED: no usable answer from the Bedrock judge "
              f"({raci.last_error}). Check credentials, model access and "
              f"HARNESS_MODEL_ID for your Region.")
    else:
        print("  SKIPPED: the judge replied but named no valid Accountable, "
              "so ACT-2 has nobody who can approve it.")

    # =====================================================================
    # RAIL 4: HOOFPRINTS -- hash-chained audit (can you prove it?)
    # =====================================================================
    _hdr("RAIL 4 HOOFPRINTS: replay the audit trail; detect tampering")
    entries = audit.entries(tenant_id=TENANT_A)
    print(f"  audit entries for tenant {TENANT_A}: {len(entries)} of "
          f"{len(audit.entries())} (the gaps in seq are tenant B's entries)")
    for e in entries:
        print(f"    seq={e['seq']:>2} {e['event']:<15} actor={e['actor']:<14} "
              f"hash={e['entry_hash'][:10]}")
    v = audit.verify()
    print(f"  chain verification: ok={v.ok} checked={v.checked} ({v.detail})")
    assert v.ok, "audit chain should verify intact"
    tampered = AuditTrail(path=None)
    tampered._entries = [dict(e) for e in audit.entries()]
    tampered._entries[1] = dict(tampered._entries[1])
    tampered._entries[1]["outputs"] = {
        **tampered._entries[1]["outputs"], "decision": "TAMPERED"}
    v2 = tampered.verify()
    print(f"  re-verify a copy with one past entry edited: ok={v2.ok} "
          f"({v2.detail})")
    assert not v2.ok, "tampering should break the hash chain"
    anchor = audit.head()   # in production: written to S3 Object Lock
    cut = AuditTrail(path=None)
    cut._entries = [dict(e) for e in audit.entries()][:-1]
    v3, v4 = cut.verify(), cut.verify(anchor=anchor)
    print(f"  drop the newest entry: walk ok={v3.ok}; against the anchor "
          f"ok={v4.ok} ({v4.detail})")
    assert v3.ok and not v4.ok
    print("  PROOF: an edit breaks the chain; a dropped tail needs the "
          "anchor, and the anchor catches it. OK")

    # =====================================================================
    # RAIL 5: GROUND-DRIVING -- eval gate (does the new version pass the old tests?)
    # =====================================================================
    _hdr("RAIL 5 GROUND-DRIVING: hard checks block before any model call")
    ev = EvalGate(bedrock_runtime=None)  # hard checks never need the model
    rep = ev.evaluate("deploy into account 123456789012 now")
    print(f"  candidate 'deploy into account 123456789012 now' -> "
          f"{rep.summary()} (judged={rep.judged})")
    assert not rep.passed and not rep.judged
    print("  PROOF: the hard check failed closed with no model call. OK")

    # =====================================================================
    # RAIL 6: STALL -- isolated runtime (where does AI-written code run?)
    # =====================================================================
    _hdr("RAIL 6 STALL: isolated runtime (live run is separate)")
    print("  harness/sandbox.py runs AI-written code in an AWS Lambda MicroVM")
    print("  and tears it down. It creates real resources, so it is not part")
    print("  of this demo: run `make sandbox-live` (see logs/sandbox.log).")

    # =====================================================================
    # RAIL 7: BREECHING -- the brakes (how does it stop, and resume?)
    # =====================================================================
    _hdr("RAIL 7 BREECHING: crash + resume, kill switch, sweeper")
    crash_state = {"assessor_attempts": 0}

    def reader(ctx: PipelineContext):
        ctx.state["requirements"] = ["R1: capital adequacy",
                                     "R2: liquidity coverage"]
        return {"requirements": len(ctx.state["requirements"])}

    def mapper(ctx: PipelineContext):
        ctx.state["mapping"] = {"R1": "policy-7", "R2": "policy-12"}
        return {"mapped": len(ctx.state["mapping"])}

    def assessor(ctx: PipelineContext):
        crash_state["assessor_attempts"] += 1
        if crash_state["assessor_attempts"] == 1:
            raise RuntimeError("simulated worker crash during assessor")
        ctx.state["findings"] = [{"control_area": "capital adequacy",
                                  "status": "not_complied"}]
        return {"findings": len(ctx.state["findings"])}

    def reviewer(ctx: PipelineContext):
        return {"validated": True,
                "findings": len(ctx.state.get("findings", []))}

    phases = [
        FunctionPhase("1_reader", reader),
        FunctionPhase("2_mapper", mapper),
        FunctionPhase("3_assessor", assessor),
        FunctionPhase("4_reviewer", reviewer),
    ]
    pipeline = Pipeline(phases, store=store, audit=audit,
                        max_duration_seconds=300)
    run_id = new_run_id()
    ctx = PipelineContext(tenant_id=TENANT_A, run_id=run_id,
                          analysis_id=review_id)

    print("  attempt 1: running pipeline (assessor will crash)...")
    ck1 = pipeline.run(ctx)
    print(f"    status={ck1['status']!r}  completed={ck1['completed_phases']}")
    print(f"    error_message={ck1['error_message']!r}")
    assert ck1["status"] == "failed", "expected a crash on attempt 1"
    assert ck1["completed_phases"] == ["1_reader", "2_mapper"]

    print("  attempt 2: retry -> resume the same run_id...")
    ctx2 = PipelineContext(tenant_id=TENANT_A, run_id=run_id,
                           analysis_id=review_id)
    ck2 = pipeline.run(ctx2, resume=True)
    print(f"    status={ck2['status']!r}  completed={ck2['completed_phases']}")
    skipped = [e["phase"] for e in ck2["phase_log"] if e["status"] == "skipped"]
    print(f"    phases SKIPPED on resume (already done): {skipped}")
    assert ck2["status"] == "completed", ck2
    assert "1_reader" in skipped and "2_mapper" in skipped, skipped
    assert crash_state["assessor_attempts"] == 2

    print("  kill switch: a human pulls the brake after the first phase...")
    brake = {"pulled": False}

    def pull_after_reader(ctx: PipelineContext):
        brake["pulled"] = True
        return reader(ctx)

    braked = Pipeline([FunctionPhase("1_reader", pull_after_reader),
                       FunctionPhase("2_mapper", mapper)],
                      store=store, audit=audit,
                      kill_switch=lambda: brake["pulled"])
    ck3 = braked.run(PipelineContext(TENANT_A, new_run_id(), review_id))
    print(f"    status={ck3['status']!r}  completed={ck3['completed_phases']}"
          f"  error_message={ck3['error_message']!r}")
    assert ck3["status"] == "failed" and ck3["completed_phases"] == ["1_reader"]

    print("  sweeper: forcing a stalled in_progress run to a terminal state...")
    stuck_id = new_run_id()
    store.save(stuck_id, {
        "run_id": stuck_id, "tenant_id": TENANT_A,
        "analysis_id": "REVIEW-stuck", "status": "in_progress",
        "started_at": 0.0, "heartbeat_at": 0.0,
        "completed_phases": ["1_reader"], "phase_log": [],
        "phase_outputs": {}, "state": {}, "error_message": None,
    })
    reaped = sweep_stuck(store, max_duration_seconds=300, grace_seconds=30,
                         audit=audit)
    assert stuck_id in reaped, "sweeper failed to reap the stalled run"
    print(f"    reaped 1 run; status={store.load(stuck_id)['status']!r}")
    print("  PROOF: resume skips done work; the brake and the sweeper both "
          "stop runs fail-closed. OK")

    # =====================================================================
    # SUMMARY
    # =====================================================================
    _hdr("SUMMARY")
    print("  RAIL 1 bit            : destructive command DENIED under '*: allow'")
    print("  RAIL 2 blinkers       : cross-tenant, unknown id, no-tenant, "
          "off-surface DENIED")
    print("  RAIL 3 reins          : only the named Accountable approves; "
          "judge picks are flagged" + ("" if judge_proved else
                                       " (judge SKIPPED)"))
    print("  RAIL 4 hoofprints     : chain verified; edit and dropped tail "
          "detected")
    print("  RAIL 5 ground-driving : hard check blocked with no model call")
    print("  RAIL 6 stall          : see `make sandbox-live` / logs/sandbox.log")
    print("  RAIL 7 breeching      : resume, kill switch and sweeper all fail closed")
    final = audit.verify()
    print(f"  audit chain: ok={final.ok} entries={final.checked}")
    if not judge_proved:
        print("\nDEMO INCOMPLETE: rail 3's judge fallback was not shown")
        return 1
    print("\nDEMO OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
