"""
tenant_gate.py -- MCP-TOOL SECURITY + PER-TENANT ISOLATION (ComplyKit rails 3 & 4).

Wraps the deterministic `PermissionGate` (allow/ask/deny, blocklist-first) with
the two ComplyKit governance facts the generic gate did not model:

  RAIL 3 (MCP-tool security): a fixed tool WHITELIST -- the compliance MCP
  surface. ComplyKit's `compliance-mcp/server.py` defines
  `REST_TOOL_NAMES = frozenset({...17 tools...})` and `POST /tools/{name}`
  returns 404 for anything not in it. We model that surface here and DENY any
  call to a tool outside the whitelist (a model cannot invent a tool to call).

  RAIL 4 (per-tenant isolation): every tool call carries a ``tenant_id`` (the
  ComplyKit X-Tenant-Id header, enforced by `_require_tenant_id` /
  `GAP_ANALYSIS_REQUIRE_TENANT_ID=true`). A tool that operates on a resource
  belonging to a DIFFERENT tenant is DENIED before it can execute -- the
  open-source analogue of ComplyKit's `_verify_analysis_tenant` /
  `_verify_bearer_tenant` cross-tenant checks and Postgres RLS
  (`tenant_id = ANY(get_user_tenant_ids())`).

Resolution order (fail-closed, deterministic, no LLM):
  (0) require_tenant_id  -> DENY if missing (GAP_ANALYSIS_REQUIRE_TENANT_ID)
  (1) tool whitelist     -> DENY if tool not in the compliance MCP surface
  (2) cross-tenant guard -> DENY if the call's resource tenant != caller tenant
  (3) delegate to PermissionGate (blocklist -> glob -> per-tool -> default)

Maps to: AWS AgentCore Identity / IAM tool-scoping + per-session tenant
credentials. See README "AWS mapping".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Set

from .permission_gate import Decision, GateResult, PermissionGate


# The compliance MCP tool surface (ComplyKit REST_TOOL_NAMES, verbatim).
# A call to anything NOT in this set is denied (ComplyKit returns 404).
COMPLIANCE_MCP_TOOLS: Set[str] = frozenset({
    "create_gap_analysis",
    "store_gap_items",
    "store_gap_item_details",
    "store_implementation_actions",
    "complete_gap_analysis",
    "get_gap_analysis_summary",
    "get_gap_items",
    "get_gap_item_details",
    "get_implementation_actions",
    "update_gap_item",
    "update_gap_item_detail",
    "update_implementation_action",
    "delete_gap_item",
    "delete_gap_item_detail",
    "delete_implementation_action",
    "compliance_web_search",
    "calculate",
})


# A resource resolver answers "which tenant owns the resource this call targets?"
# In ComplyKit this is the DB lookup behind `_verify_analysis_tenant`
# (SELECT 1 FROM gap_analyses WHERE analysis_id=$1 AND tenant_id=$2). Here it is
# an injectable function so the demo/tests can model a resource registry.
ResourceOwnerResolver = Callable[[str, Dict[str, Any]], Optional[str]]


class CrossTenantError(PermissionError):
    """Raised/returned when a tenant tries to touch another tenant's resource."""


@dataclass
class TenantGateResult:
    decision: Decision
    rule: str
    reason: str
    tool_name: str
    tenant_id: str
    command: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.decision.value.upper()} [{self.rule}] tenant={self.tenant_id} {self.reason}"


class TenantScopedGate:
    """Per-tenant, whitelisted wrapper around the deterministic PermissionGate."""

    def __init__(
        self,
        permission_gate: Optional[PermissionGate] = None,
        allowed_tools: Optional[Set[str]] = None,
        resource_owner: Optional[ResourceOwnerResolver] = None,
        require_tenant_id: bool = True,  # ComplyKit GAP_ANALYSIS_REQUIRE_TENANT_ID
    ) -> None:
        self.gate = permission_gate or PermissionGate()
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else set(COMPLIANCE_MCP_TOOLS)
        self.resource_owner = resource_owner
        self.require_tenant_id = require_tenant_id

    def before_tool(
        self,
        tool_name: str,
        tenant_id: Optional[str],
        args: Optional[Dict[str, Any]] = None,
    ) -> TenantGateResult:
        args = args or {}

        # Stage 0: tenant context required (ComplyKit _require_tenant_id -> 400).
        if self.require_tenant_id and not tenant_id:
            return TenantGateResult(
                Decision.DENY, "require-tenant-id",
                "X-Tenant-Id required but missing (GAP_ANALYSIS_REQUIRE_TENANT_ID)",
                tool_name, tenant_id or "", "",
            )
        tid = tenant_id or ""

        # Stage 1: MCP tool whitelist (ComplyKit REST_TOOL_NAMES -> 404).
        if tool_name not in self.allowed_tools:
            return TenantGateResult(
                Decision.DENY, "tool-whitelist",
                f"tool '{tool_name}' is not in the compliance MCP surface",
                tool_name, tid, "",
            )

        # Stage 2: cross-tenant guard (ComplyKit _verify_analysis_tenant + RLS).
        if self.resource_owner is not None:
            owner = self.resource_owner(tool_name, args)
            if owner is not None and owner != tid:
                return TenantGateResult(
                    Decision.DENY, "cross-tenant",
                    f"tenant '{tid}' may not access a resource owned by tenant '{owner}'",
                    tool_name, tid, "",
                )

        # Stage 3: delegate to the deterministic permission gate
        # (blocklist -> glob -> per-tool config -> default posture).
        inner: GateResult = self.gate.before_tool(tool_name, args)
        return TenantGateResult(
            decision=inner.decision,
            rule=f"permission-gate:{inner.rule}",
            reason=inner.reason,
            tool_name=tool_name,
            tenant_id=tid,
            command=inner.command,
        )
