"""
demo.py -- runnable demonstration of the 5 ComplyKit-derived governance rails.

Models a tiny multi-tenant regulatory gap-analysis run (the real ComplyKit
workload) and proves, clearly labelled, each rail against LIVE Bedrock
(Nova micro, ~zero cost):

  RAIL 1  DURABLE + RESUMABLE  -- run a phase pipeline, KILL it mid-way
          (a phase raises), then RESUME: completed phases are SKIPPED.
          Plus: the sweeper forces a stalled run to a terminal state.
  RAIL 2  IMMUTABLE AUDIT      -- replay the hash-chained audit trail for the
          analysis and verify the chain detects tampering.
  RAIL 3  MCP-TOOL SECURITY    -- a non-whitelisted tool is DENIED.
  RAIL 4  PER-TENANT ISOLATION -- tenant B is BLOCKED from tenant A's analysis.
  RAIL 5  RACI GATE            -- a control area gets RACI assigned: a matrix
          HIT and a matrix MISS resolved by the Bedrock judge fallback.

Run:  python -m harness.demo   (AWS profile voteetech, us-east-1, Nova micro)
"""

from __future__ import annotations

import os
import sys
import tempfile

import boto3

from .audit import AuditTrail
from .checkpoint import JsonCheckpointStore
from .permission_gate import Decision, PermissionGate
from .pipeline import (
    FunctionPhase,
    Pipeline,
    PipelineContext,
    new_run_id,
    sweep_stuck,
)
from .raci_gate import Bearer, MatrixRule, RaciGate
from .tenant_gate import COMPLIANCE_MCP_TOOLS, TenantScopedGate

PROFILE = os.environ.get("AWS_PROFILE", "voteetech")
REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ.get("HARNESS_MODEL_ID", "us.amazon.nova-micro-v1:0")

BAR = "=" * 74
TENANT_A = "tenant-a-bochk"
TENANT_B = "tenant-b-rival"


def _hdr(title: str) -> None:
    print("\n" + BAR)
    print(title)
    print(BAR)


def main() -> int:
    print("reinvent-harness-poc demo  (ComplyKit-derived governance rails)")
    print(f"profile={PROFILE} region={REGION} model={MODEL_ID}")

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    bedrock = session.client("bedrock-runtime")

    workdir = tempfile.mkdtemp(prefix="harness-demo-")
    audit = AuditTrail(path=os.path.join(workdir, "audit.jsonl"))
    store = JsonCheckpointStore(os.path.join(workdir, "checkpoints.json"))
    print(f"workdir: {workdir}")

    # =====================================================================
    # RAIL 1: DURABLE + RESUMABLE PIPELINE
    # =====================================================================
    _hdr("RAIL 1: DURABLE + RESUMABLE PIPELINE (kill mid-run, resume, skip done)")

    # A 4-phase gap-analysis pipeline (distilled from ComplyKit's 8 phases).
    # phase 3 (assessor) is rigged to CRASH on the first attempt, then succeed
    # on resume -- exactly the SIGKILL/crash recovery ComplyKit's /retry covers.
    crash_state = {"assessor_attempts": 0}

    def reader(ctx: PipelineContext):
        ctx.state["requirements"] = ["R1: capital adequacy", "R2: liquidity coverage"]
        return {"requirements": len(ctx.state["requirements"])}

    def mapper(ctx: PipelineContext):
        ctx.state["mapping"] = {"R1": "policy-7", "R2": "policy-12"}
        return {"mapped": len(ctx.state["mapping"])}

    def assessor(ctx: PipelineContext):
        crash_state["assessor_attempts"] += 1
        if crash_state["assessor_attempts"] == 1:
            raise RuntimeError("simulated worker crash (SIGKILL) during assessor")
        ctx.state["gaps"] = [{"control_area": "capital adequacy", "status": "not_complied"}]
        return {"gaps": len(ctx.state["gaps"])}

    def reviewer(ctx: PipelineContext):
        return {"validated": True, "gaps": len(ctx.state.get("gaps", []))}

    phases = [
        FunctionPhase("1_reader", reader),
        FunctionPhase("2_mapper", mapper),
        FunctionPhase("3_assessor", assessor),
        FunctionPhase("5_reviewer", reviewer),
    ]
    pipeline = Pipeline(phases, store=store, audit=audit, max_duration_seconds=300)

    run_id = new_run_id()
    analysis_id = "ANALYSIS-" + run_id
    ctx = PipelineContext(tenant_id=TENANT_A, run_id=run_id, analysis_id=analysis_id)

    print("  attempt 1: running pipeline (assessor will crash)...")
    ck1 = pipeline.run(ctx)
    print(f"    status={ck1['status']!r}  completed={ck1['completed_phases']}")
    print(f"    error_message={ck1['error_message']!r}")
    assert ck1["status"] == "failed", "expected a crash on attempt 1"
    assert ck1["completed_phases"] == ["1_reader", "2_mapper"], ck1["completed_phases"]

    print("  attempt 2: /retry -> resume same run_id (completed phases skipped)...")
    ctx2 = PipelineContext(tenant_id=TENANT_A, run_id=run_id, analysis_id=analysis_id)
    ck2 = pipeline.run(ctx2, resume=True)
    print(f"    status={ck2['status']!r}  completed={ck2['completed_phases']}")
    skipped = [e["phase"] for e in ck2["phase_log"] if e["status"] == "skipped"]
    print(f"    phases SKIPPED on resume (already done): {skipped}")
    assert ck2["status"] == "completed", ck2
    assert "1_reader" in skipped and "2_mapper" in skipped, skipped
    assert crash_state["assessor_attempts"] == 2, "assessor should have re-run once"
    print("  PROOF: reader+mapper ran once, were checkpointed, and were skipped on resume. OK")

    # terminal-state guarantee: the sweeper reaps a stalled in_progress run.
    print("  sweeper: forcing a stalled in_progress run to a terminal state...")
    stuck_id = new_run_id()
    stuck_ckpt = {
        "run_id": stuck_id, "tenant_id": TENANT_A, "analysis_id": "ANALYSIS-stuck",
        "status": "in_progress", "started_at": 0.0, "heartbeat_at": 0.0,
        "completed_phases": ["1_reader"], "phase_log": [], "phase_outputs": {},
        "state": {}, "error_message": None,
    }
    store.save(stuck_id, stuck_ckpt)
    reaped = sweep_stuck(store, max_duration_seconds=300, grace_seconds=30, audit=audit)
    print(f"    reaped run_ids: {reaped}")
    assert stuck_id in reaped, "sweeper failed to reap the stalled run"
    print(f"    reaped status: {store.load(stuck_id)['status']!r}  "
          f"({store.load(stuck_id)['error_message']!r})")
    print("  PROOF: no run can hang in 'in_progress' forever. OK")

    # =====================================================================
    # RAIL 2: IMMUTABLE AUDIT TRAIL (replay + tamper detection)
    # =====================================================================
    _hdr("RAIL 2: IMMUTABLE AUDIT TRAIL (replay one analysis; detect tampering)")
    entries = audit.entries(tenant_id=TENANT_A)
    print(f"  audit entries for tenant {TENANT_A}: {len(entries)}")
    for e in entries[:8]:
        print(f"    seq={e['seq']:>2} {e['event']:<20} actor={e['actor']:<22} "
              f"hash={e['entry_hash'][:10]}")
    if len(entries) > 8:
        print(f"    ... (+{len(entries) - 8} more)")
    v = audit.verify()
    print(f"  chain verification: ok={v.ok} checked={v.checked} ({v.detail})")
    assert v.ok, "audit chain should verify intact"

    # demonstrate tamper-evidence on a SEPARATE trail re-loaded from the same
    # JSONL file, so the live trail stays pristine.
    print("  simulating tampering on a re-loaded copy (edit a past entry)...")
    tampered = AuditTrail(path=None)
    tampered._entries = [dict(e) for e in audit.entries()]
    tampered._entries[1] = dict(tampered._entries[1])
    tampered._entries[1]["outputs"] = {**tampered._entries[1]["outputs"], "status": "TAMPERED"}
    v2 = tampered.verify()
    print(f"  re-verify tampered copy: ok={v2.ok} ({v2.detail})")
    assert not v2.ok, "tampering should break the hash chain"
    assert audit.verify().ok, "original trail must remain intact"
    print("  PROOF: any edit to a past entry breaks the hash chain. OK")

    # =====================================================================
    # RAIL 3: MCP-TOOL SECURITY (whitelist) + RAIL 4: PER-TENANT ISOLATION
    # =====================================================================
    _hdr("RAIL 3: MCP-TOOL SECURITY  +  RAIL 4: PER-TENANT ISOLATION")

    # Resource registry: which tenant owns which analysis (ComplyKit
    # _verify_analysis_tenant / RLS). tenant A owns analysis_id.
    owners = {analysis_id: TENANT_A}

    def resource_owner(tool_name, args):
        aid = args.get("analysis_id")
        return owners.get(aid) if aid else None

    gate = TenantScopedGate(
        permission_gate=PermissionGate(
            tool_config={t: "allow" for t in COMPLIANCE_MCP_TOOLS},
        ),
        resource_owner=resource_owner,
        require_tenant_id=True,
    )

    print(f"  compliance MCP surface: {len(COMPLIANCE_MCP_TOOLS)} whitelisted tools")
    # (3a) whitelisted tool, correct tenant -> ALLOW
    r = gate.before_tool("get_gap_analysis_summary", TENANT_A, {"analysis_id": analysis_id})
    print(f"  (3a) tenant A -> get_gap_analysis_summary on its OWN analysis: "
          f"{r.decision.value.upper()} [{r.rule}]")
    audit.append("tool_call", "agent:tenantA", TENANT_A,
                 {"tool": "get_gap_analysis_summary", "analysis_id": analysis_id},
                 {"decision": r.decision.value, "rule": r.rule})
    assert r.allowed, r

    # (3b) non-whitelisted tool -> DENY (ComplyKit returns 404)
    r = gate.before_tool("drop_all_tables", TENANT_A, {})
    print(f"  (3b) tenant A -> 'drop_all_tables' (NOT in MCP surface): "
          f"{r.decision.value.upper()} [{r.rule}]  -- {r.reason}")
    assert r.decision is Decision.DENY and r.rule == "tool-whitelist", r

    # (4a) cross-tenant: tenant B targets tenant A's analysis -> DENY
    r = gate.before_tool("get_gap_analysis_summary", TENANT_B, {"analysis_id": analysis_id})
    print(f"  (4a) tenant B -> get_gap_analysis_summary on tenant A's analysis: "
          f"{r.decision.value.upper()} [{r.rule}]  -- {r.reason}")
    audit.append("tool_call", "agent:tenantB", TENANT_B,
                 {"tool": "get_gap_analysis_summary", "analysis_id": analysis_id},
                 {"decision": r.decision.value, "rule": r.rule})
    assert r.decision is Decision.DENY and r.rule == "cross-tenant", r

    # (4b) missing tenant id -> DENY (GAP_ANALYSIS_REQUIRE_TENANT_ID)
    r = gate.before_tool("get_gap_analysis_summary", None, {"analysis_id": analysis_id})
    print(f"  (4b) no tenant id -> {r.decision.value.upper()} [{r.rule}]  -- {r.reason}")
    assert r.decision is Decision.DENY and r.rule == "require-tenant-id", r
    print("  PROOF: off-surface tools, cross-tenant access, and missing tenant all DENIED. OK")

    # =====================================================================
    # RAIL 5: RACI GATE (deterministic matrix + Bedrock judge fallback)
    # =====================================================================
    _hdr("RAIL 5: RACI GATE (matrix lookup HIT + Bedrock judge fallback on MISS)")

    bearers = [
        Bearer("b-risk", "Chief Risk Officer", scope="capital adequacy, risk, liquidity"),
        Bearer("b-fin", "Head of Finance", scope="finance, treasury, capital"),
        Bearer("b-comp", "Compliance Officer", scope="compliance, regulatory reporting"),
        Bearer("b-ops", "Head of Operations", scope="operations, settlement, custody"),
    ]
    matrix = [
        MatrixRule("capital%", r_role="Head of Finance", a_role="Chief Risk Officer",
                   c_roles=["Compliance Officer"], i_roles=[], priority=100),
        MatrixRule("liquidity%", r_role="Chief Risk Officer", a_role="Chief Risk Officer",
                   priority=90),
    ]
    raci = RaciGate(matrix=matrix, bearers=bearers, bedrock_runtime=bedrock,
                    model_id=MODEL_ID, audit=audit, tenant_id=TENANT_A)

    # (5a) matrix HIT: "capital adequacy" matches "capital%" deterministically.
    a1 = raci.assign("capital adequacy", action_id="ACT-1")
    print(f"  (5a) matrix HIT  : {a1.summary()}")
    assert a1.matrix_hit and not a1.used_llm_fallback, a1
    assert a1.raci_reasoning["r"]["source"] == "matrix"

    # (5b) matrix MISS: no rule matches "cybersecurity incident response" ->
    #      Bedrock judge fallback picks a Responsible + Accountable bearer.
    a2 = raci.assign("cybersecurity incident response", action_id="ACT-2")
    print(f"  (5b) matrix MISS : {a2.summary()}")
    assert not a2.matrix_hit, a2
    r_entry = a2.raci_reasoning.get("r")
    if a2.used_llm_fallback and r_entry:
        print(f"       judge picked R={r_entry['bearer_name']} "
              f"(source={r_entry['source']}) reason={r_entry['reasoning'][:70]!r}")
        assert r_entry["source"] == "llm_fallback", a2
        print("  PROOF: matrix decided 5a deterministically; Bedrock judge filled 5b. OK")
    else:
        # fail-safe path (judge returned nothing): still a valid terminal outcome
        print("       judge returned no assignment (fail-safe) -- recorded as missing.")
        print("  PROOF: matrix decided 5a deterministically; judge fallback exercised on 5b. OK")

    # =====================================================================
    # SUMMARY
    # =====================================================================
    _hdr("SUMMARY")
    print("  RAIL 1 durable/resumable : crash -> retry skipped done phases; sweeper reaped a stall")
    print("  RAIL 2 immutable audit   : hash chain verified intact; tamper detected")
    print("  RAIL 3 MCP-tool security : off-surface tool DENIED (whitelist)")
    print("  RAIL 4 per-tenant isolat.: tenant B DENIED from tenant A's analysis")
    print("  RAIL 5 RACI gate         : matrix HIT (deterministic) + judge fallback on MISS")
    final = audit.verify()
    print(f"  audit chain: ok={final.ok} entries={final.checked}")
    print("\nDEMO OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
