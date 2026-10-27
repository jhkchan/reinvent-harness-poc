"""
agentcore_lambdas.py -- the code you own, running inside Amazon Bedrock
AgentCore. ``agentcore.py`` deploys both handlers as AWS Lambda functions.

  hook_handler   The AgentCore harness ``before_tool_call`` lifecycle hook.
                 The harness calls it synchronously before every tool call
                 and runs the tool only on {"decision": "allow"}. It runs
                 rail 2 (tenant and tool scope) and, inside it, rail 1 (the
                 permission gate): the same TenantScopedGate the local demo
                 uses.
  tools_handler  The AgentCore Gateway Lambda target behind the review
                 tools. The Gateway calls it only after AgentCore Policy
                 (Cedar) allowed the call.

The hook payload carries the harness ARN and the session id, but no user
and no tenant. Mapping a session to a tenant is yours: the backend that
calls InvokeHarness writes {session_id -> tenant_id} to a DynamoDB table
first, and the hook reads it. An unregistered session has no tenant, so the
gate denies it.

Behind a harness, Cedar sees one principal for every tenant: the harness
execution role. A Cedar policy can deny a tool, or an argument value, for
everyone. It cannot tell tenant A's review from tenant B's. That check stays
here.

Stdlib only (boto3 comes with the Lambda Python runtime), so the deployment
zip is this file plus permission_gate.py and tenant_gate.py.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, Optional

from .permission_gate import PermissionGate
from .tenant_gate import TenantScopedGate

TARGET = "reviews"            # the Gateway target name
TOOL_SEP = "___"              # Gateway tool names are <target>___<tool>
REASON_MAX = 1024             # the harness caps a hook reason at 1,024 chars
TABLE_ENV = "SESSIONS_TABLE"

# An illustrative review store. In production the tools read a database and
# the owner lookup is SELECT tenant_id FROM reviews WHERE id = $1.
REVIEWS: Dict[str, Dict[str, Any]] = {
    "REVIEW-A1": {"tenant_id": "tenant-a-bank",
                  "title": "Capital adequacy review", "open_findings": 2},
    "REVIEW-B1": {"tenant_id": "tenant-b-insurer",
                  "title": "Claims handling review", "open_findings": 1},
}

FINDING_STATUSES = ("complied", "not_complied", "partial")

# The Gateway target's tool surface, as AgentCore Gateway tool schemas.
TOOL_SCHEMAS = [
    {"name": "get_review",
     "description": "Read one compliance review by its id.",
     "inputSchema": {"type": "object",
                     "properties": {"review_id": {"type": "string"}},
                     "required": ["review_id"]}},
    {"name": "add_finding",
     "description": "Record a finding on a review. status is one of: "
                    + ", ".join(FINDING_STATUSES) + ".",
     "inputSchema": {"type": "object",
                     "properties": {"review_id": {"type": "string"},
                                    "control_area": {"type": "string"},
                                    "status": {"type": "string"}},
                     "required": ["review_id", "control_area", "status"]}},
    {"name": "delete_review",
     "description": "Delete a review and all of its findings.",
     "inputSchema": {"type": "object",
                     "properties": {"review_id": {"type": "string"}},
                     "required": ["review_id"]}},
]

# The hook's own allowlist leaves delete_review off, and it refuses the
# agent's sign-off as Cedar does, so both stay denied even if the Cedar
# engine drifts to LOG_ONLY.
HOOK_TOOLS = frozenset({"get_review", "add_finding"})
SIGN_OFF = "complied"


def short_name(tool_name: str) -> str:
    """``reviews___get_review`` -> ``get_review`` (a bare name is kept)."""
    return str(tool_name).rsplit(TOOL_SEP, 1)[-1]


def hook_tool(tool_name: Any) -> Optional[str]:
    """The tool name the hook checks, or None for another target's tool.

    ``reviews___get_review`` and a bare ``get_review`` -> ``get_review``;
    ``admin___get_review`` -> None, so a same-named tool on a second target
    never borrows this target's allowlist."""
    target, sep, tool = str(tool_name or "").rpartition(TOOL_SEP)
    if not sep:
        return tool
    return tool if target == TARGET else None


def _no_duplicate_keys(pairs: Any) -> Dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def review_owner(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    review = REVIEWS.get(str(args.get("review_id", "")))
    return review["tenant_id"] if review else None


HOOK_GATE = TenantScopedGate(
    permission_gate=PermissionGate(
        tool_config={t: "allow" for t in HOOK_TOOLS}),
    allowed_tools=set(HOOK_TOOLS),
    resource_owner=review_owner,
    require_tenant_id=True,
)

TenantLookup = Callable[[str], Optional[str]]


def _deny(reason: str) -> Dict[str, str]:
    return {"decision": "deny", "reason": reason[:REASON_MAX]}


def decide(event: Dict[str, Any], tenant_of: TenantLookup,
           gate: TenantScopedGate = HOOK_GATE) -> Dict[str, str]:
    """The hook's answer for one harness event: allow, or deny with a reason.

    Fail closed: an unexpected event, another target's tool, or a tool input
    that is not one JSON object (duplicate keys included) is denied before
    the gate runs."""
    if not isinstance(event, dict) or event.get("event") != "before_tool_call":
        return _deny("[hook] unexpected event type")
    ctx = event.get("context")
    if not isinstance(ctx, dict):
        return _deny("[hook] missing tool context")
    tool = hook_tool(ctx.get("toolName"))
    if tool is None:
        return _deny("[hook] tool is not on this target")
    args = ctx.get("toolInput")
    if isinstance(args, str):       # the harness may send the input as text
        try:
            args = (json.loads(args, object_pairs_hook=_no_duplicate_keys)
                    if args.strip() else {})
        except ValueError:
            return _deny("[hook] tool input is not valid JSON")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _deny("[hook] tool input is not a JSON object")
    tenant = tenant_of(str(event.get("sessionId") or ""))
    r = gate.before_tool(tool, tenant, args)
    if not r.allowed:
        return _deny(f"[{r.rule}] {r.reason}")
    if tool == "add_finding" and args.get("status") == SIGN_OFF:
        return _deny("[sign-off] a named human signs off a control (rail 3)")
    return {"decision": "allow"}


# --------------------------------------------------------------------------- #
# Lambda entry points                                                         #
# --------------------------------------------------------------------------- #
_ddb = None


def _session_tenant(session_id: str) -> Optional[str]:
    """Read {session_id -> tenant_id} from the registry the backend writes."""
    global _ddb
    if not session_id:
        return None
    if _ddb is None:
        import boto3  # in the Lambda runtime; never imported by local tests

        _ddb = boto3.client("dynamodb")
    item = _ddb.get_item(
        TableName=os.environ[TABLE_ENV],
        Key={"session_id": {"S": session_id}},
        ConsistentRead=True,
    ).get("Item")
    return item["tenant_id"]["S"] if item else None


def hook_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, str]:
    """AgentCore harness before_tool_call hook (Lambda target)."""
    try:
        out = decide(event, _session_tenant)
    except Exception as e:  # fail closed; the hook's failureMode is deny too
        out = _deny(f"[hook-error] {type(e).__name__}")
    # One line per decision in CloudWatch: no tool input, no tenant data.
    print(json.dumps({"hook": "before_tool_call", "tool": _logged_tool(event),
                      "decision": out["decision"]}))
    return out


def _logged_tool(event: Any) -> str:
    try:
        return short_name(event["context"]["toolName"])
    except Exception:
        return "?"


def tools_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AgentCore Gateway Lambda target: ``event`` is the tool's arguments."""
    custom = getattr(getattr(context, "client_context", None), "custom",
                     None) or {}
    tool = short_name(custom.get("bedrockAgentCoreToolName", ""))
    args = event if isinstance(event, dict) else {}
    review_id = str(args.get("review_id", ""))
    review = REVIEWS.get(review_id)
    # This target has no tenant identity of its own (the Gateway uses
    # AWS_IAM). In production the data layer applies row-level security too.
    if tool == "get_review":
        if not review:
            return {"error": "review not found"}
        return {"review_id": review_id, "title": review["title"],
                "open_findings": review["open_findings"]}
    if tool == "add_finding":
        if not review:
            return {"error": "review not found"}
        if args.get("status") not in FINDING_STATUSES:
            return {"error": "status must be one of "
                             + ", ".join(FINDING_STATUSES)}
        return {"recorded": True, "review_id": review_id,
                "control_area": str(args.get("control_area", "")),
                "status": args["status"]}
    if tool == "delete_review":
        return {"deleted": bool(review), "review_id": review_id}
    return {"error": f"unknown tool {tool!r}"}
