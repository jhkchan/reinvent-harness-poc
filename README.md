# The Agent Harness You Own on AWS for Regulated Industries (re:Invent 2026 COM321)

A small, runnable harness around a tool-calling AI agent. It has seven
**rails**. Each rail answers one question a regulator will ask about the
agent. For each one, the table shows what AWS covers today and what you still
own.

Four rails are real straps on a horse's harness: the bit, the blinkers, the
reins and the breeching. Three are practices around the harness: the tracks it
leaves (hoofprints), the training before it is hitched (ground-driving), and
the stall that keeps each horse apart.

There are two ways to run it. `make demo` runs each rail as plain Python on
your machine. `make agentcore-live` runs them on Amazon Bedrock AgentCore:
the AgentCore harness runs the agent loop, AgentCore Policy enforces Cedar at
the Gateway, and rails 1 and 2 run inside the loop as the harness's
`before_tool_call` hook. See [On AgentCore](#on-agentcore).

> **Where this comes from.** These rails are generalized from a production
> regulated-compliance platform: a multi-tenant agent pipeline that reads
> regulations, finds compliance findings and assigns accountable owners for
> banks and insurers. That platform is private and is not in this repo. What
> is here is the extracted harness, rebuilt as standalone, dependency-light
> code. The tool surface, tenants, matrix and phases in the demo are
> illustrative.

## Seven rails

Rows are in the talk's order. AWS status and dates were checked in October
2026. Service availability differs by Region, so check your Region.

| # | Harness part or practice | Regulator question | Module | AWS covers (status, date) | You still own |
|---|---|---|---|---|---|
| 1 | **Bit** (strap): permission gate | Who allowed this tool call? | `harness/permission_gate.py` | AgentCore Policy on Gateway: Cedar, default deny, forbid beats permit (GA, 3 Mar 2026). AgentCore harness `before_tool_call` lifecycle hook, `failureMode` deny by default (Sep 2026). IAM explicit deny (GA). | Tool calls from code that never reaches Gateway. MCP prompts and resources (always allowed). Mode drift to `LOG_ONLY`. Behavior on a policy-engine error (undocumented). The blocklist content. |
| 2 | **Blinkers** (strap): tool and tenant scope | What can the agent see? | `harness/tenant_gate.py` | AgentCore Gateway tool targets, AgentCore Identity (workload identity, inbound JWT, outbound credentials), AgentCore Runtime microVM per session (GA, Oct 2025). | The session-to-user mapping (AgentCore does not enforce it). A per-tenant tool list frozen at session start. Row-level security. Data residency. |
| 3 | **Reins** (strap): named-human approval | Whose name is on this action? | `harness/raci_gate.py` | Step Functions `.waitForTaskToken` (GA; pauses up to 1 year). Gateway Step Functions connector (Oct 2026). MCP elicitation via Gateway (May 2026). | Binding the task token to one named approver. Proving who the approver is: AWS can check that an approval happened, not who approved. The RACI matrix. The approver record. |
| 4 | **Hoofprints** (practice: the tracks): hash-chained audit | What happened, and can you prove it? | `harness/audit.py` | CloudTrail log file integrity validation (long-standing GA; API calls only). S3 Object Lock compliance mode (long-standing GA; WORM). AgentCore Observability (traces in CloudWatch). Not QLDB (end of support 31 Jul 2025); not CloudTrail Lake (closed to new customers 31 May 2026). | The content chain: tool arguments, policy decision, approver. Gateway data events (off by default, redacted). Running the validation. Data residency of the log. |
| 5 | **Ground-driving** (practice: training before hitching): eval gate | Does the new version pass the old tests? | `harness/eval_gate.py` | AgentCore Evaluations (GA, 31 Mar 2026): built-in evaluators, ground truth, custom LLM or Lambda evaluators, on-demand runs for CI/CD. | The pass/fail threshold. The step that blocks the deploy (no AWS gate primitive found as of Oct 2026). The golden set from your regulated cases. |
| 6 | **Stall** (practice: each horse kept apart): isolated runtime | Where does AI-written code run? | `harness/sandbox.py` | AWS Lambda MicroVMs (launched 22 Jun 2026; one Firecracker microVM per user or session, snapshot start, suspend and resume; 10 Regions on 19 Aug 2026). AgentCore Runtime microVM per session. AgentCore Code Interpreter in Sandbox network mode. | The session-to-user mapping. Egress control for MicroVMs: the API takes `egressNetworkConnectors`, but the default egress is not documented, and `sandbox.py` does not set it. What data goes in. Cleanup. |
| 7 | **Breeching** (strap: the brakes) | How does it stop, and resume? | `harness/checkpoint.py` + `harness/pipeline.py` | Lambda durable functions (GA, 2 Dec 2025): checkpointed steps, waits up to 1 year. Step Functions (GA). Gateway rate limits: `rate=0` blocks, but limits fail open on transient errors. | Who may pull the brake. Budgets. Idempotency. Which state is authoritative. |

On AgentCore, rails 1 and 2 run as the harness hook
(`harness/agentcore_lambdas.py`), rail 4 records every decision, and rail 5
uses AgentCore Evaluations as its judge (`harness/agentcore.py`).

Each module marks one short, real code region per rail between
`# [snippet:rail-N]` and `# [/snippet]` (10 lines or fewer, 60 columns or
fewer). Those are the regions shown on the talk's code slides.

Watching, not counted above: an AgentCore Policy temporal policy that checks
for a recorded approval earlier in the session (AWS blog, 6 Aug 2026; status
unconfirmed).

## Quickstart

Prerequisites: Python 3.10 or newer (tested on 3.11). If your `python3` is
older, run `make setup PY=python3.11`.

For `make demo` and `make test-live`: AWS credentials from the default
credential chain (export `AWS_PROFILE` to pick a named profile) that can call
Bedrock `converse` on `us.amazon.nova-micro-v1:0` in `us-east-1`. Outside the
US, set `HARNESS_MODEL_ID` to an inference profile for your Region.

For `make sandbox-live` (rail 6), in a Region where Lambda MicroVMs is
available:
- `sts:GetCallerIdentity`
- `s3:CreateBucket`, `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteBucket`,
  `s3:ListAllMyBuckets`
- `iam:CreateRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:DeleteRole`, `iam:ListRolePolicies` and `iam:PassRole` on
  `arn:aws:iam::<account-id>:role/harness-sandbox/*` (the roles are created
  under the `/harness-sandbox/` path), plus `iam:ListRoles`
- the Lambda MicroVMs actions for images and microVMs (create, run, get,
  terminate, delete, list)
- `logs:DeleteLogGroup`, `logs:DescribeLogGroups`

For `make agentcore-live`, in a Region with the AgentCore harness, Gateway,
Policy and Evaluations (built and run in `us-east-1`), and access to
`us.amazon.nova-lite-v1:0` (set `HARNESS_AGENTCORE_MODEL_ID` for another
model):
- `sts:GetCallerIdentity`
- `iam:CreateRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:DeleteRole`, `iam:ListRolePolicies` and `iam:PassRole` on
  `arn:aws:iam::<account-id>:role/harness-agentcore/*`, plus `iam:ListRoles`
- `lambda:CreateFunction`, `lambda:GetFunctionConfiguration`,
  `lambda:DeleteFunction`, `lambda:ListFunctions`
- `dynamodb:CreateTable`, `dynamodb:DescribeTable`, `dynamodb:PutItem`,
  `dynamodb:DeleteTable`, `dynamodb:ListTables`
- the `bedrock-agentcore` create, get, delete and list actions for
  harnesses, gateways, gateway targets, policy engines and policies, plus
  `ListAgentRuntimes`, `ListWorkloadIdentities`, `InvokeHarness` and
  `InvokeAgentRuntime` (the docs require both to invoke a harness),
  `InvokeGateway` and `Evaluate`
- `logs:DeleteLogGroup`, `logs:DescribeLogGroups`

```bash
make setup          # venv + requirements.txt
make test           # offline unit tests: no AWS calls, no credentials
make demo           # rails 1-5 and 7; rail 3's judge makes 1 live Bedrock call
make test-live      # also runs the 2 live Bedrock tests (HARNESS_LIVE=1)
make sandbox-live   # rail 6: one live AWS Lambda MicroVM run, then teardown
make sandbox-cleanup-check   # lists harness-sandbox-* leftovers (must be 0)
make agentcore-live # rails on a live AgentCore harness + Gateway, then teardown
make agentcore-cleanup-check # lists harness-agentcore leftovers (must be 0)

AWS_REGION=us-east-1 make demo   # override the Region
```

## Cost

- `make test` is free: Bedrock and the MicroVM service are replaced by fakes.
- `make demo` makes one Nova micro `converse` call (rail 3's judge), and
  `make test-live` makes two; each uses a few hundred tokens at most, a
  fraction of a cent. They create no AWS resources: checkpoints and the
  audit log are local temp files. If the judge gives no usable answer
  (no credentials, no model access, an unparseable reply), the demo prints
  `SKIPPED` and ends with `DEMO INCOMPLETE` (exit 1).
- `make sandbox-live` creates one MicroVM image, one microVM, two IAM roles
  and one S3 bucket, all named `harness-sandbox-*`, runs
  `print(sum(range(10)))`, and deletes all of them (plus the run's CloudWatch
  log group, `/aws/lambda-microvms/<name>`) in a `finally` block. The
  execution role has no permission policy (the code needs no AWS access);
  the build role can read only the run's zip and write only the run's log
  group; both trust policies pin `aws:SourceAccount`. The log records the
  code's sha256 and length, never its text or raw output
  (`HARNESS_SANDBOX_DEBUG=1` adds a short redacted preview). It
  takes a few minutes, mostly the server-side image build; expect cents, not
  dollars. Run `make sandbox-cleanup-check` afterwards. The redacted logs of
  one such run are in `logs/sandbox.log` and `logs/sandbox-cleanup.log`.
- `make agentcore-live` creates one AgentCore harness, one Gateway with one
  Lambda target, one Policy engine with three Cedar policies, two Lambda
  functions, one DynamoDB table and four IAM roles, all named
  `harness-agentcore` (or `harness_agentcore` where AgentCore allows no
  hyphen) plus the run id. It makes three harness invocations with Nova
  Lite (up to six if the model skips the tool), five signed Gateway calls
  and up to nine Evaluations calls, then deletes all of it (plus the run's
  three log groups) in a `finally` block, which also runs on Ctrl-C and
  SIGTERM. The harness runtime exports its logs about a minute late, which
  can bring its log group back after it is deleted, so teardown waits out
  that export and deletes again. Each role is
  trusted only for this account and scoped to this run's resources. The
  harness itself has no charge; you pay for its runtime seconds, the
  Gateway and Policy requests, the evaluations and the model tokens. One run
  took 6 to 15 minutes in our runs (deleting the harness took from seconds
  to six minutes, and teardown waits out the late log export); expect
  cents. Run `make agentcore-cleanup-check`
  afterwards. The redacted logs of one run are in `logs/agentcore.log` and
  `logs/agentcore-cleanup.log`.

## What the demo proves

`make demo` prints one labelled section per rail, in the table's order:

- **Rail 1, bit:** `rm -rf /` is denied even under a `*: allow` override,
  while `ls -la` under the same override is allowed.
- **Rail 2, blinkers:** a call with no tenant id is denied; a tool outside
  the illustrative 8-tool surface is denied before any resource lookup;
  tenant B asking for tenant A's review, and anyone asking for an unknown
  id, get the same generic "resource not found or not permitted" that never
  names the owner.
- **Rail 3, reins:** `capital adequacy` gets its RACI from the matrix, and
  only its named Accountable can approve the action (another person is
  refused). `cybersecurity incident response` misses the matrix, and the live
  Bedrock judge fills it, flagged `source="llm_fallback"`; its Accountable is
  provisional (`needs_confirmation`) until that person signs off. The LLM
  never approves.
- **Rail 4, hoofprints:** the hash chain verifies; editing one past entry
  breaks it; dropping the newest entry passes the walk but fails against an
  anchor taken earlier with `head()`.
- **Rail 5, ground-driving:** a candidate containing an account id is blocked
  by a hard check before any model call.
- **Rail 6, stall:** run separately with `make sandbox-live`.
- **Rail 7, breeching:** a crashed run resumes and skips the phases it already
  finished; a pulled kill switch stops a run before its next phase; the
  sweeper moves a stalled run to `failed`.

## On AgentCore

`make agentcore-live` builds this in your account, runs it, and deletes it:

```
AgentCore harness (Nova Lite, no container, managed memory off)
 |-- before_tool_call hook -> Lambda: rails 1 + 2, failureMode deny
 |                            reads session -> tenant from DynamoDB
 `-- tool: AgentCore Gateway (MCP, AWS_IAM inbound)
      |-- AgentCore Policy engine, ENFORCE mode (Cedar)
      `-- Lambda target: the review tools
```

What one run proves (`logs/agentcore.log`):

- **Cedar at the Gateway (AWS).** Called straight at the Gateway with SigV4,
  with no model and no hook. `tools/list` hides `delete_review`, which has
  no permit. `delete_review` is denied by default, and so is `get_review` on
  a malformed id, because the permit's condition does not match.
  `add_finding` with status `complied` is denied by the forbid, and the
  Gateway's reply names it: the agent may record a gap, but not sign off a
  control. With status `not_complied` it runs. A reply that is not a Cedar
  decision (an unknown tool, a throttle, a 5xx) fails the run instead of
  counting as a deny.
- **The hook (yours), through the harness.** The model picks the tool; a
  scenario counts only if it called `get_review` on `REVIEW-A1`, and the
  hook decides. Tenant A reading its own review: ALLOW.
  Tenant B asking for the same review: DENY `[cross-tenant]`. A session
  that no backend registered: DENY `[require-tenant-id]`.
- **The eval gate on AgentCore Evaluations.** Three built-in evaluators
  (Helpfulness, InstructionFollowing, Harmfulness) score each answer, and
  the gate's threshold and floor decide. A golden answer is released; an
  off-task answer is blocked.
- **Audit.** Every decision above goes on a rail-4 hash chain, which
  verifies at the end of the run. The chain is in memory and is checked by
  the process that wrote it; persist it and anchor `head()` as in rail 4
  for a real audit trail.

Three things the build showed about where AWS stops:

- **The hook payload names no user.** It carries the harness ARN and the
  session id. Mapping a session to a tenant is yours: here the backend
  writes it to a DynamoDB table before it calls `InvokeHarness`, and the
  hook reads it.
- **Behind a harness, Cedar sees one principal.** The Gateway uses AWS_IAM,
  so every tenant's call reaches Cedar as the harness execution role. Cedar
  can deny a tool, or an argument value, for everyone. It cannot tell
  tenant A's review from tenant B's, so that check stays in the hook.
- **Cedar validation refuses loose rules.** With `FAIL_ON_ANY_FINDINGS`, a
  permit with no condition is rejected as "Overly Permissive", and a forbid
  that leaves an action nothing to allow as "Overly Restrictive". Every
  permit here has a condition.

The two layers overlap on purpose. A caller that skips the harness still
meets Cedar. If the engine drifts to `LOG_ONLY`, the hook still leaves
`delete_review` off its allowlist and still refuses the agent's sign-off. The Gateway target has no tenant identity
of its own, so in production the data layer applies row-level security too.

## Repo layout

```
harness/
  permission_gate.py  rail 1  bit: blocklist -> glob -> per-tool -> default
  tenant_gate.py      rail 2  blinkers: tenant + tool allowlist + owner check
  raci_gate.py        rail 3  reins: RACI matrix, flagged LLM fallback, approve()
  audit.py            rail 4  hoofprints: hash chain, verify(), head() anchor
  eval_gate.py        rail 5  ground-driving: hard checks, then LLM judge
  sandbox.py          rail 6  stall: AWS Lambda MicroVM run + teardown
  pipeline.py         rail 7  breeching: budget, kill switch, resume, sweeper
  checkpoint.py       rail 7  JSON checkpoint store (+ DynamoDB adapter notes)
  observability.py    OpenTelemetry spans for tool calls and gate decisions
  guardrails.py       optional Bedrock Guardrails wrapper (no-op by default)
  agent.py            Bedrock converse tool-use loop, gated and traced (runs
                      on your machine; file tools stay in one workspace)
  agentcore.py        live AgentCore harness + Gateway + Policy + Evaluations:
                      build, scenarios, teardown, cleanup check
  agentcore_lambdas.py the harness before_tool_call hook (rails 1 + 2) and
                      the Gateway's Lambda target
  demo.py             the seven rails, in order
tests/                one test file per rail (+ live tests behind HARNESS_LIVE)
logs/                 output of pytest -v (make test, verbose), make demo,
                      make sandbox-live and make agentcore-live (account ids
                      and local paths redacted)
```

## Honesty notes

- **Deterministic where it matters.** Which tool may run, which tenant may
  touch a resource, and whether a run must stop are decided by code you can
  read, and every one of them fails closed. The LLM is used only where it adds
  leverage (the RACI judge fallback, the eval judge), and its contribution is
  labelled.
- **Tamper-evident, not tamper-proof.** The hash chain makes an edit, a
  deleted middle entry or a reorder detectable. Dropping the newest entries,
  or re-hashing the whole file, is caught only against an anchor kept out of
  the writer's reach: store `head()` in S3 Object Lock on a schedule.
- **An LLM judge is one signal.** The text it grades can try to steer it.
  The eval gate fences the candidate as data, fails a reply that quotes it
  back, clamps each score and fails closed on a bad reply. AgentCore
  Evaluations' built-in judges read the answer as given; an error or a
  missing score counts as 0. A judge also sees only what you send it: scored
  against a prompt that said "use get_review", with no tool call in the
  trace, one wording of a correct answer failed InstructionFollowing every
  time, so the AgentCore run scores answers against the user's question.
  Either way, let a judge PASS release nothing on its own: keep the hard
  checks and a human.
- **Examples, not a complete policy.** The blocklist patterns, the tool
  surface and the RACI matrix are examples. The README table lists them under
  "You still own" for that reason. A glob ALLOW on a shell tool
  (`run_bash:git *`) allows everything that program can do, including its
  own ways to run other commands; keep shell tools on ask, or run them in
  rail 6's sandbox.
- **Local-first, with two live runs.** `make demo` runs on local files.
  `make sandbox-live` (rail 6) and `make agentcore-live` create real AWS
  resources and delete them. The DynamoDB checkpoint store, Step Functions
  and S3 Object Lock adapters are still only documented in code comments.
  In the AgentCore run, the audit chain is kept by the process that calls
  the harness, from the hook decisions in the response stream; the hook
  Lambda itself only logs one line per decision.
- **A proof of concept.** The phase set is small, the matrix and tool surface
  are illustrative, and the executor is local rather than a managed workflow.

## License

Apache-2.0. See `LICENSE`.
