"""Tests for RAILS 3 & 4: MCP-tool security (whitelist) + per-tenant isolation."""

from harness.permission_gate import Decision, PermissionGate
from harness.tenant_gate import COMPLIANCE_MCP_TOOLS, TenantScopedGate


def _allow_all_gate():
    return PermissionGate(tool_config={t: "allow" for t in COMPLIANCE_MCP_TOOLS})


# --- RAIL 3: MCP tool whitelist ---------------------------------------------
def test_whitelisted_tool_allowed():
    g = TenantScopedGate(permission_gate=_allow_all_gate())
    r = g.before_tool("get_gap_analysis_summary", "tenant-a", {})
    assert r.allowed
    assert r.rule.startswith("permission-gate:")


def test_non_whitelisted_tool_denied():
    g = TenantScopedGate(permission_gate=_allow_all_gate())
    r = g.before_tool("drop_all_tables", "tenant-a", {})
    assert r.decision is Decision.DENY
    assert r.rule == "tool-whitelist"


def test_whitelist_has_all_17_compliance_tools():
    # ComplyKit REST_TOOL_NAMES surface
    assert "create_gap_analysis" in COMPLIANCE_MCP_TOOLS
    assert "complete_gap_analysis" in COMPLIANCE_MCP_TOOLS
    assert "compliance_web_search" in COMPLIANCE_MCP_TOOLS
    assert "calculate" in COMPLIANCE_MCP_TOOLS
    assert len(COMPLIANCE_MCP_TOOLS) == 17


# --- RAIL 4: per-tenant isolation -------------------------------------------
def test_cross_tenant_access_denied():
    owners = {"a1": "tenant-a"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("analysis_id")),
    )
    # tenant B reaching for tenant A's analysis -> DENY
    r = g.before_tool("get_gap_analysis_summary", "tenant-b", {"analysis_id": "a1"})
    assert r.decision is Decision.DENY
    assert r.rule == "cross-tenant"


def test_same_tenant_access_allowed():
    owners = {"a1": "tenant-a"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("analysis_id")),
    )
    r = g.before_tool("get_gap_analysis_summary", "tenant-a", {"analysis_id": "a1"})
    assert r.allowed


def test_missing_tenant_id_denied_when_required():
    g = TenantScopedGate(permission_gate=_allow_all_gate(), require_tenant_id=True)
    r = g.before_tool("get_gap_analysis_summary", None, {})
    assert r.decision is Decision.DENY
    assert r.rule == "require-tenant-id"


def test_missing_tenant_id_allowed_when_not_required():
    # ComplyKit GAP_ANALYSIS_REQUIRE_TENANT_ID=false (dev/back-compat)
    g = TenantScopedGate(permission_gate=_allow_all_gate(), require_tenant_id=False)
    r = g.before_tool("get_gap_analysis_summary", None, {})
    assert r.allowed


def test_blocklist_still_wins_through_tenant_gate():
    """A dangerous payload is denied by the inner permission gate even for a
    whitelisted tool on the correct tenant (defense-in-depth preserved)."""
    g = TenantScopedGate(
        permission_gate=PermissionGate(
            tool_config={"store_gap_item_details": "allow"},
        ),
    )
    # destructive content smuggled into a whitelisted tool's args
    r = g.before_tool("store_gap_item_details", "tenant-a", {"reasoning": "rm -rf /"})
    assert r.decision is Decision.DENY
    assert "blocklist" in r.rule


def test_resource_with_no_owner_is_not_cross_tenant():
    """A tool call whose resource has no recorded owner is not blocked by the
    cross-tenant guard (it falls through to the permission gate)."""
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: None,  # unknown owner
    )
    r = g.before_tool("calculate", "tenant-a", {"expression": "1+1"})
    assert r.allowed
