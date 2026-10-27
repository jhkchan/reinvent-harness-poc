"""
tenant_gate.py -- Rail 2, the blinkers: tool and tenant scope.

Regulator question: "What can the agent see?"

Wraps the deterministic `PermissionGate` (rail 1, the bit) with two scope
checks the generic gate does not model:

  Tenant scope: every tool call carries a ``tenant_id`` (an X-Tenant-Id
  header in a web service). A call with no tenant is DENIED when tenant
  context is required, and a call that targets a resource owned by a
  DIFFERENT tenant is DENIED before it can execute. In a database this is
  the same check as row-level security (`tenant_id = ANY(user_tenants)`).

  Tool scope: a fixed tool ALLOWLIST -- the tool surface the agent's MCP
  server exposes. A call to any tool outside it is DENIED (an MCP server
  returns 404), so a model cannot invent a tool to call.

Resolution order (fail-closed, deterministic, no LLM):
  (0) require tenant id  -> DENY if missing
  (1) tool allowlist     -> DENY if the tool is not on the surface (checked
                            before any resource lookup, so an off-surface
                            call never reaches the owner registry)
  (2) cross-tenant guard -> DENY if the resource tenant != caller tenant, and
                            DENY if a resource tool's owner cannot be resolved
  (3) delegate to PermissionGate (blocklist -> glob -> per-tool -> default)

The cross-tenant DENY is deliberately generic: one rule ("cross-tenant") and
one reason ("resource not found or not permitted") for both an unknown id and
another tenant's id. It never names the owning tenant, so a caller cannot use
the gate to learn who owns a resource id or that the id exists at all.

AWS covers: AgentCore Gateway tool targets, AgentCore Identity, a Runtime
microVM per session. You still own the session-to-user mapping, the
per-tenant tool list and row-level security. See the README rail table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Set

from .permission_gate import Decision, GateResult, PermissionGate


# An illustrative tool surface for a review agent's MCP server.
# A call to anything NOT in this set is denied.
REVIEW_TOOLS: Set[str] = frozenset({
    "open_review",
    "get_review",
    "add_finding",
    "get_finding",
    "update_finding",
    "delete_finding",
    "search_regulations",
    "calculate",
})

# Tools that act on an existing resource. For these the owner MUST resolve:
# an unknown owner is denied like another tenant's resource (fail closed).
RESOURCE_TOOLS: Set[str] = frozenset({
    "get_review", "add_finding", "get_finding", "update_finding",
    "delete_finding",
})

# Returned by the owner lookup when a resource tool's owner cannot be
# resolved. It never equals a tenant id, so the cross-tenant guard denies it.
UNRESOLVED: Any = object()


# A resource resolver answers "which tenant owns the resource this call
# targets?" In production this is a DB lookup (SELECT tenant_id FROM reviews
# WHERE id = $1). Here it is an injectable function so the demo and
# tests can model a resource registry.
ResourceOwnerResolver = Callable[[str, Dict[str, Any]], Optional[str]]


# Deny reasons. NOT_PERMITTED is shared by "no such resource" and "another
# tenant's resource" so the two cases are indistinguishable to the caller.
NOT_PERMITTED = "resource not found or not permitted"
OFF_SURFACE = "tool is not on the allowed tool surface"


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
        return (f"{self.decision.value.upper()} [{self.rule}] "
                f"tenant={self.tenant_id} {self.reason}")


def _deny(rule: str, tool: str, tid: str, reason: str) -> TenantGateResult:
    return TenantGateResult(Decision.DENY, rule, reason, tool, tid, "")


class TenantScopedGate:
    """Per-tenant, allowlisted wrapper around the deterministic PermissionGate."""

    def __init__(
        self,
        permission_gate: Optional[PermissionGate] = None,
        allowed_tools: Optional[Set[str]] = None,
        resource_owner: Optional[ResourceOwnerResolver] = None,
        require_tenant_id: bool = True,
        resource_tools: Optional[Set[str]] = None,
    ) -> None:
        self.gate = permission_gate or PermissionGate()
        self.allowed_tools = (set(allowed_tools) if allowed_tools is not None
                              else set(REVIEW_TOOLS))
        self.resource_owner = resource_owner
        self.require_tenant_id = require_tenant_id
        # With a custom allowlist and no resource_tools, treat every allowed
        # tool as a resource tool (fail closed); name the exceptions yourself.
        if resource_tools is not None:
            self.resource_tools = set(resource_tools)
        elif allowed_tools is not None:
            self.resource_tools = set(allowed_tools)
        else:
            self.resource_tools = set(RESOURCE_TOOLS)

    def _owner(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """The owning tenant of a resource tool's target, or UNRESOLVED.

        Only resource tools are looked up, so a tool that targets nothing
        never reveals whether an id exists."""
        if tool_name not in self.resource_tools:
            return None
        owner = (self.resource_owner(tool_name, args)
                 if self.resource_owner is not None else None)
        return UNRESOLVED if owner is None else owner

    def before_tool(
        self,
        tool_name: str,
        tenant_id: Optional[str],
        args: Optional[Dict[str, Any]] = None,
    ) -> TenantGateResult:
        args = args or {}

        # Stage 0: tenant context required. Stage 1: tool allowlist
        # (an MCP server returns 404 off-surface), checked before any
        # owner lookup. Stage 2: the cross-tenant guard, whose reason
        # never names the owning tenant.
        # [snippet:rail-2]
        if self.require_tenant_id and not tenant_id:
            return _deny("require-tenant-id", tool_name, "",
                         "tenant id required but missing")
        tid, tool = tenant_id or "", tool_name
        if tool not in self.allowed_tools:
            return _deny("tool-allowlist", tool, tid, OFF_SURFACE)
        owner = self._owner(tool, args)
        if owner is not None and owner != tid:
            return _deny("cross-tenant", tool, tid, NOT_PERMITTED)
        # [/snippet]

        # Stage 3: delegate to the deterministic permission gate
        # (blocklist -> glob -> per-tool config -> default posture).
        inner: GateResult = self.gate.before_tool(tool_name, args, scope=tid)
        return TenantGateResult(
            decision=inner.decision,
            rule=f"permission-gate:{inner.rule}",
            reason=inner.reason,
            tool_name=tool_name,
            tenant_id=tid,
            command=inner.command,
        )
