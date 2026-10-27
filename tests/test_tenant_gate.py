"""Tests for rail 2, the blinkers: tool allowlist + per-tenant isolation."""

from harness.permission_gate import Decision, PermissionGate
from harness.tenant_gate import (NOT_PERMITTED, RESOURCE_TOOLS, REVIEW_TOOLS,
                                 TenantScopedGate)


def _allow_all_gate():
    return PermissionGate(tool_config={t: "allow" for t in REVIEW_TOOLS})


# --- tool scope: the allowlist -----------------------------------------------
def test_allowlisted_tool_allowed():
    g = TenantScopedGate(permission_gate=_allow_all_gate())
    r = g.before_tool("search_regulations", "tenant-a", {})
    assert r.allowed
    assert r.rule.startswith("permission-gate:")


def test_tool_off_the_allowlist_denied():
    g = TenantScopedGate(permission_gate=_allow_all_gate())
    r = g.before_tool("drop_all_tables", "tenant-a", {})
    assert r.decision is Decision.DENY
    assert r.rule == "tool-allowlist"


def test_resource_tools_are_on_the_surface():
    # every tool that needs an owner check is also an allowed tool
    assert RESOURCE_TOOLS <= REVIEW_TOOLS
    assert "open_review" in REVIEW_TOOLS and "open_review" not in RESOURCE_TOOLS


# --- tenant scope: per-tenant isolation ------------------------------------
def test_cross_tenant_access_denied():
    owners = {"a1": "tenant-a"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("review_id")),
    )
    # tenant B reaching for tenant A's review -> DENY
    r = g.before_tool("get_review", "tenant-b", {"review_id": "a1"})
    assert r.decision is Decision.DENY
    assert r.rule == "cross-tenant"
    assert r.reason == NOT_PERMITTED


def test_cross_tenant_reason_never_discloses_the_owner():
    """The deny reason (and the printed result) must not name the tenant
    that owns the resource, so a caller cannot probe ownership."""
    owners = {"a1": "tenant-a-secret-owner"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("review_id")),
    )
    r = g.before_tool("get_review", "tenant-b", {"review_id": "a1"})
    assert r.decision is Decision.DENY and r.rule == "cross-tenant"
    assert "tenant-a-secret-owner" not in r.reason
    assert "tenant-a-secret-owner" not in str(r)
    assert "tenant-a-secret-owner" not in repr(r)


def test_unlisted_tool_denied_before_any_owner_lookup():
    """Order: missing tenant -> allowlist -> owner check. An off-surface tool
    is denied without ever calling the resource-owner resolver, even when
    the resource belongs to another tenant."""
    lookups = []

    def owner(tool, args):
        lookups.append((tool, dict(args)))
        return "tenant-a"

    g = TenantScopedGate(permission_gate=_allow_all_gate(),
                         resource_owner=owner)
    r = g.before_tool("drop_all_tables", "tenant-b", {"review_id": "a1"})
    assert r.decision is Decision.DENY
    assert r.rule == "tool-allowlist"
    assert lookups == []


def test_missing_tenant_denied_before_allowlist_and_owner_lookup():
    lookups = []
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: lookups.append(tool) or "tenant-a",
    )
    r = g.before_tool("drop_all_tables", None, {"review_id": "a1"})
    assert r.rule == "require-tenant-id"
    assert lookups == []


def test_same_tenant_access_allowed():
    owners = {"a1": "tenant-a"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("review_id")),
    )
    r = g.before_tool("get_review", "tenant-a", {"review_id": "a1"})
    assert r.allowed


def test_missing_tenant_id_denied_when_required():
    g = TenantScopedGate(permission_gate=_allow_all_gate(), require_tenant_id=True)
    r = g.before_tool("get_review", None, {})
    assert r.decision is Decision.DENY
    assert r.rule == "require-tenant-id"


def test_missing_tenant_id_allowed_when_not_required():
    # tenant context optional (dev/back-compat mode)
    g = TenantScopedGate(permission_gate=_allow_all_gate(), require_tenant_id=False)
    r = g.before_tool("search_regulations", None, {})
    assert r.allowed


def test_blocklist_still_wins_through_tenant_gate():
    """A dangerous payload is denied by the inner permission gate even for an
    allowlisted tool on the correct tenant (defense-in-depth preserved)."""
    g = TenantScopedGate(
        permission_gate=PermissionGate(
            tool_config={"open_review": "allow"},
        ),
    )
    # destructive content smuggled into an allowlisted tool's args
    r = g.before_tool("open_review", "tenant-a", {"title": "rm -rf /"})
    assert r.decision is Decision.DENY
    assert "blocklist" in r.rule


def test_tool_without_a_resource_skips_the_owner_check():
    """A tool that targets no resource (calculate) has no owner to check, so
    it falls through to the permission gate."""
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: None,
    )
    r = g.before_tool("calculate", "tenant-a", {"expression": "1+1"})
    assert r.allowed


def test_unknown_resource_owner_fails_closed():
    """A resource tool whose owner cannot be resolved is denied with the same
    rule and reason as another tenant's resource, so the two look the same."""
    owners = {"a1": "tenant-a"}
    g = TenantScopedGate(
        permission_gate=_allow_all_gate(),
        resource_owner=lambda tool, args: owners.get(args.get("review_id")),
    )
    unknown = g.before_tool("get_review", "tenant-a", {"review_id": "nope"})
    unread = g.before_tool("get_finding", "tenant-a", {"finding": "a1"})
    other = g.before_tool("get_review", "tenant-b", {"review_id": "a1"})
    for r in (unknown, unread, other):
        assert r.decision is Decision.DENY
        assert (r.rule, r.reason) == ("cross-tenant", NOT_PERMITTED)


def test_resource_tool_without_a_resolver_fails_closed():
    g = TenantScopedGate(permission_gate=_allow_all_gate())
    r = g.before_tool("get_review", "tenant-a", {"review_id": "a1"})
    assert r.decision is Decision.DENY and r.rule == "cross-tenant"


def test_a_tool_without_a_resource_never_looks_up_an_owner():
    """calculate with another tenant's id and with an unknown id must get the
    same answer, so it cannot be used to learn that an id exists."""
    lookups = []
    owners = {"a1": "tenant-a"}

    def owner(tool, args):
        lookups.append(tool)
        return owners.get(args.get("review_id"))

    g = TenantScopedGate(permission_gate=_allow_all_gate(), resource_owner=owner)
    other = g.before_tool("calculate", "tenant-b", {"review_id": "a1"})
    unknown = g.before_tool("calculate", "tenant-b", {"review_id": "nope"})
    assert (other.decision, other.rule) == (unknown.decision, unknown.rule)
    assert lookups == []


def test_custom_allowlist_without_resource_tools_fails_closed():
    g = TenantScopedGate(
        permission_gate=PermissionGate(tool_config={"read_ledger": "allow"}),
        allowed_tools={"read_ledger"},
        resource_owner=lambda tool, args: None,
    )
    r = g.before_tool("read_ledger", "tenant-a", {"ledger_id": "x"})
    assert r.decision is Decision.DENY and r.rule == "cross-tenant"


def test_an_approval_for_one_tenant_does_not_cover_another():
    seen = []
    inner = PermissionGate(human_review=lambda tool, cmd: seen.append(cmd) or True)
    g = TenantScopedGate(permission_gate=inner)
    a = g.before_tool("open_review", "tenant-a", {"title": "Q3"})
    b = g.before_tool("open_review", "tenant-b", {"title": "Q3"})
    assert a.allowed and b.allowed
    assert "cache" not in b.rule and len(seen) == 2   # B was reviewed itself
    again = g.before_tool("open_review", "tenant-a", {"title": "Q3"})
    assert again.rule == "permission-gate:cache"
