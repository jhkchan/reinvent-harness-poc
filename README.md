# reinvent-harness-poc

**An AI-agent harness for regulated industries on AWS — governance rails
derived from a real product.** This is the open-source distillation of the
governance machinery behind **ComplyKit**, a private multi-tenant regulatory
gap-analysis platform for banks and insurers. ComplyKit runs an LLM agent
pipeline that reads regulations, finds compliance gaps, and assigns
accountable owners — work a regulator must be able to *trust and audit*. The
rails below are the exact governance requirements ComplyKit needs, lifted out
of the product and re-implemented as a thin, framework-agnostic harness around
any tool-calling agent.

The talk this backs is *"Building AI Agents with a Harness on AWS for Regulated
Industries."* The harness is a **real, runnable POC**: `make demo` and
`make test` execute live against Amazon Bedrock (Nova micro) at ~zero cost.

> **Honesty note.** ComplyKit itself is **private** and is not in this repo.
> What is published here is the *extracted, generalized harness* — the
> governance rails (durable execution, immutable audit, tool/tenant security,
> RACI accountability) re-derived from ComplyKit's real requirements and
> rebuilt as standalone, dependency-light code. The ComplyKit-specific
> identifiers referenced below (`bearer_raci_matrix`, `should_skip_phase`,
> `REST_TOOL_NAMES`, `GAP_ANALYSIS_REQUIRE_TENANT_ID`, the 8-phase pipeline,
> the Beat sweeper, `_record_history`) are described so the mapping is honest,
> not because that code ships here.

## ComplyKit requirement → harness rail → AWS service

| # | ComplyKit requirement (real) | Harness rail (this repo) | AWS mapping |
|---|------------------------------|--------------------------|-------------|
| 1 | **Durable, resumable 8-phase pipeline.** `PHASES` registry + `PipelineContext`; `should_skip_phase(sb, analysis_id, phase)` skips already-done phases on `/retry`; `_log_pipeline_event` writes `pipeline_runs.phase_log` + `heartbeat_at`; Beat sweeper reaps `in_progress` runs past `max_duration + grace`; `/rerun` for a fresh `analysis_id`. | `harness/pipeline.py` (`Pipeline`, `PipelineContext`, `FunctionPhase.should_skip`, `sweep_stuck`), `harness/checkpoint.py` (`JsonCheckpointStore`). Crash a run; resume; completed phases are skipped; the sweeper forces a terminal state. | **Step Functions** (state machine of phases) / **SQS+Lambda** (one phase per task) + **DynamoDB** for checkpoints; **EventBridge**-scheduled sweeper Lambda. |
| 2 | **Complete audit trail.** `_record_history` → `gap_analysis_change_history` (`action_name`, `old_value`, `new_value`, `changed_by` from `X-Account-Id`, `changed_at`); `pipeline_runs.phase_log`; `raci_reasoning` with `source ∈ (matrix\|llm_fallback\|legacy_v2\|manual)`. | `harness/audit.py` (`AuditTrail`): **hash-chained**, append-only JSONL; every gate decision / tool call / phase transition / RACI assignment with who/what/when/inputs/outputs. Tamper, reorder, and deletion are all detectable via `verify()`. | **DynamoDB** (one item per entry, chain hash) + periodic **S3 Object Lock (WORM)** export for true immutability. |
| 3 | **MCP tool surface is fixed.** `compliance-mcp` exposes `REST_TOOL_NAMES` (17 tools); `POST /tools/{name}` returns **404** for anything off the surface. | `harness/tenant_gate.py` (`TenantScopedGate` + `COMPLIANCE_MCP_TOOLS` whitelist) wrapping the existing deterministic `harness/permission_gate.py` (blocklist → glob → per-tool → default). Off-surface tools are DENIED; the blocklist still wins inside the surface. | **AgentCore Identity** + **IAM** least-privilege tool scoping. |
| 4 | **Per-tenant isolation.** `X-Tenant-Id` header → `_require_tenant_id` (400 when `GAP_ANALYSIS_REQUIRE_TENANT_ID=true`); `_verify_analysis_tenant` / `_verify_bearer_tenant` reject cross-tenant; Postgres **RLS** (`tenant_id = ANY(get_user_tenant_ids())`). | `harness/tenant_gate.py`: a `tenant_id` is threaded through every call; the `resource_owner` guard rejects a tenant touching another tenant's resource; missing tenant id fails closed. | **RLS** in RDS/Aurora + per-session **scoped credentials** (STS) so a tenant's agent session physically cannot read another tenant's rows. |
| 5 | **RACI Bearer Matrix v3.** Deterministic `bearer_raci_matrix` lookup (highest-`priority` pattern match) resolves roles to bearers; `judge_raci` LLM tool **only** on a matrix miss / unresolved role; `raci_reasoning` JSONB records the assignment + `source`. | `harness/raci_gate.py` (`RaciGate`, `MatrixRule`, `Bearer`): deterministic matrix first, **Bedrock (Nova micro) judge fallback** on a miss, reasoning + provenance recorded to the audit trail. Replaces/extends the generic eval gate as the "who is accountable" decision. | **Amazon Bedrock** `converse` (Nova micro) for the judge; the matrix is config in **DynamoDB** / per-tenant JSON. |

Kept from the original generic POC (supporting rails): `harness/permission_gate.py`
(deterministic allow/ask/deny, fail-closed), `harness/observability.py` (OTel
spans → CloudWatch), `harness/guardrails.py` (Bedrock Guardrails, no-op until
configured), `harness/agent.py` (Bedrock `converse` tool-use loop),
`harness/eval_gate.py` (hard checks + LLM-as-judge for shipping a capability).

## What the demo proves

`make demo` runs a tiny multi-tenant gap-analysis and prints, clearly labelled:

- **Rail 1** — a 4-phase pipeline where the *assessor* phase crashes on the
  first attempt; `/retry` resumes the same run and the already-completed reader
  + mapper phases are **skipped**; then the **sweeper** forces a stalled
  `in_progress` run to `failed` (terminal-state guarantee).
- **Rail 2** — the hash-chained audit trail for the analysis is **replayed**
  and **verified intact**, then a simulated edit to a past entry is **detected**.
- **Rail 3** — a non-whitelisted tool (`drop_all_tables`) is **DENIED**.
- **Rail 4** — tenant B is **DENIED** access to tenant A's analysis; a call
  with no tenant id is **DENIED**.
- **Rail 5** — `capital adequacy` gets RACI assigned by a **deterministic
  matrix hit**; `cybersecurity incident response` (a matrix miss) is resolved
  by the **live Bedrock judge fallback**, with reasoning recorded.

## Run it

Prereqs: Python 3.9+, AWS credentials for a profile that can call Bedrock
`converse` on `us.amazon.nova-micro-v1:0` in `us-east-1`. Defaults assume
profile `voteetech`, region `us-east-1` (override with env vars).

```bash
make setup        # venv + boto3 + opentelemetry-sdk + pytest
make demo         # live demo of all 5 rails against Bedrock (Nova micro)
make test         # unit tests (fast, free: judge/eval use fake clients)
make test-live    # ALSO runs the 2 live-Bedrock tests (HARNESS_LIVE=1)

AWS_PROFILE=myprofile AWS_REGION=us-east-1 make demo   # override profile/region
```

Cost: the demo and live tests issue a handful of tiny Nova-micro `converse`
calls (single-digit to low-hundreds of tokens each). **No AWS resources are
provisioned or left behind** — checkpoints and the audit log are local files
in a temp dir.

## Repo layout

```
harness/
  pipeline.py        RAIL 1  durable executor: PipelineContext, should_skip,
                             heartbeats, terminal-state guarantee, sweep_stuck
  checkpoint.py      RAIL 1  JsonCheckpointStore (+ documented DynamoDB adapter)
  audit.py           RAIL 2  hash-chained, append-only AuditTrail + verify()
  tenant_gate.py     RAILS 3+4  MCP tool whitelist + per-tenant cross-access guard
  raci_gate.py       RAIL 5  matrix lookup + Bedrock judge fallback + reasoning
  permission_gate.py (kept) deterministic allow/ask/deny, blocklist-first
  eval_gate.py       (kept) hard checks + LLM-as-judge capability gate
  observability.py   (kept) OTel spans for tool calls + gate decisions
  guardrails.py      (kept) optional Bedrock Guardrails wrapper
  agent.py           (kept) Bedrock converse tool-use loop, gated + traced
  demo.py            runnable demonstration of all 5 ComplyKit-derived rails
tests/
  test_pipeline.py     RAIL 1  (crash/resume/skip, sweeper, terminal state)
  test_audit.py        RAIL 2  (chain link, tamper/reorder detection, replay)
  test_tenant_gate.py  RAILS 3+4  (whitelist, cross-tenant, require-tenant-id)
  test_raci_gate.py    RAIL 5  (matrix priority, judge fallback, audit, +live)
  test_permission_gate.py / test_eval_gate.py   (kept)
```

## Honesty notes

- **Deterministic where it matters.** The safety-critical decisions — which
  tool may run, which tenant may touch a resource, whether a run is terminal —
  are reproducible, explainable to a regulator, and **fail-closed**. The LLM is
  used only where it adds leverage: the RACI *judge fallback* (rail 5) and the
  capability *eval judge* (kept). A model jailbreak cannot widen the tool
  whitelist, cross a tenant boundary, or rewrite a sealed audit entry.
- **The matrix is policy; the judge fills gaps.** Rail 5 assigns accountability
  from a human-authored matrix first and only calls the model when the matrix
  has no rule — and always labels that contribution `source="llm_fallback"` in
  the audit trail. Accountability is mandatory: a missing Accountable bearer is
  flagged, mirroring ComplyKit's `missing_accountable` warning.
- **Tamper-evidence, not just tamper-resistance.** The audit trail is
  hash-chained so an after-the-fact edit/delete/reorder is *detectable*, which
  is what an auditor actually needs. In production you pair this with DynamoDB +
  S3 Object Lock for true write-once storage.
- **Local-first by design.** Checkpoints and the audit log are local files so
  the demo runs free and offline; the AWS adapters (Step Functions / SQS+Lambda
  / DynamoDB / S3 Object Lock / RLS) are documented in code comments and the
  mapping table, not provisioned. This is a POC: the phase set is small, the
  matrix is illustrative, and the executor is local rather than Step Functions.
- **ComplyKit is private.** This repo is the open-source harness extracted from
  it, not the product. The mapping table is the bridge between the two.

## License

Apache-2.0. See `LICENSE`.
