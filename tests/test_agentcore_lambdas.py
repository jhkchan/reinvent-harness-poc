"""Tests for the code that runs inside AgentCore (offline, NO AWS calls):
the harness before_tool_call hook and the Gateway Lambda target."""

import json
from types import SimpleNamespace

import pytest

from harness import agentcore_lambdas as L

SESSIONS = {"s-a": "tenant-a-bank", "s-b": "tenant-b-insurer"}


def ev(tool, tool_input, session="s-a", event="before_tool_call"):
    return {"hookEventId": "h-1", "name": "gate", "event": event,
            "harnessArn": "arn:aws:bedrock-agentcore:us-east-1:"
                          "123456789012:harness/x",
            "sessionId": session,
            "context": {"toolName": tool, "toolType": "agentcore_gateway",
                        "toolInput": tool_input, "toolUseId": "t-1"}}


def decide(*a, **kw):
    return L.decide(ev(*a, **kw), SESSIONS.get)


def test_owner_tenant_is_allowed():
    assert decide("reviews___get_review", {"review_id": "REVIEW-A1"}) == \
        {"decision": "allow"}


def test_cross_tenant_is_denied_without_naming_the_owner():
    out = decide("reviews___get_review", {"review_id": "REVIEW-A1"}, "s-b")
    assert out["decision"] == "deny"
    assert out["reason"].startswith("[cross-tenant]")
    assert "tenant-a" not in out["reason"]


def test_unknown_review_reads_like_another_tenants():
    unknown = decide("reviews___get_review", {"review_id": "REVIEW-Z9"})
    other = decide("reviews___get_review", {"review_id": "REVIEW-B1"})
    assert unknown == other and unknown["decision"] == "deny"


def test_unregistered_session_has_no_tenant_and_is_denied():
    out = decide("reviews___get_review", {"review_id": "REVIEW-A1"}, "s-x")
    assert out == {"decision": "deny",
                   "reason": "[require-tenant-id] tenant id required but "
                             "missing"}


def test_delete_is_off_the_hook_surface_even_if_cedar_drifts():
    out = decide("reviews___delete_review", {"review_id": "REVIEW-A1"})
    assert out["decision"] == "deny"
    assert out["reason"].startswith("[tool-allowlist]")


def test_blocklist_runs_inside_the_hook():
    out = decide("reviews___add_finding",
                 {"review_id": "REVIEW-A1", "control_area": "rm -rf /",
                  "status": "partial"})
    assert out["decision"] == "deny" and "blocklist" in out["reason"]


def test_tool_input_sent_as_json_text_is_parsed():
    out = decide("get_review", json.dumps({"review_id": "REVIEW-A1"}))
    assert out == {"decision": "allow"}


@pytest.mark.parametrize("bad,why", [
    ("{not json", "not valid JSON"),
    (["REVIEW-A1"], "not a JSON object"),
    ("[1]", "not a JSON object"),
])
def test_malformed_tool_input_is_denied(bad, why):
    out = decide("get_review", bad)
    assert out["decision"] == "deny" and why in out["reason"]


@pytest.mark.parametrize("kind", ["after_tool_call", "before_invocation", ""])
def test_unexpected_event_type_is_denied(kind):
    out = L.decide(ev("get_review", {"review_id": "REVIEW-A1"}, event=kind),
                   SESSIONS.get)
    assert out["decision"] == "deny"


def test_reason_is_capped_for_the_harness():
    assert len(L._deny("x" * 5000)["reason"]) == L.REASON_MAX


@pytest.mark.parametrize("name,short", [
    ("reviews___get_review", "get_review"),
    ("get_review", "get_review"),
    ("gw___reviews___add_finding", "add_finding"),
    ("", ""),
])
def test_short_name_strips_the_target_prefix(name, short):
    assert L.short_name(name) == short


def test_hook_handler_fails_closed_and_logs_no_input(monkeypatch, capsys):
    def boom(_sid):
        raise RuntimeError("table unreachable")

    monkeypatch.setattr(L, "_session_tenant", boom)
    out = L.hook_handler(ev("reviews___get_review",
                            {"review_id": "REVIEW-A1"}))
    assert out == {"decision": "deny", "reason": "[hook-error] RuntimeError"}
    line = json.loads(capsys.readouterr().out.strip())
    assert line == {"hook": "before_tool_call", "tool": "get_review",
                    "decision": "deny"}


def test_session_lookup_reads_the_registry_consistently(monkeypatch):
    calls = []

    class FakeDdb:
        def get_item(self, **kw):
            calls.append(kw)
            sid = kw["Key"]["session_id"]["S"]
            return ({"Item": {"tenant_id": {"S": "tenant-a-bank"}}}
                    if sid == "s-a" else {})

    monkeypatch.setattr(L, "_ddb", FakeDdb())
    monkeypatch.setenv(L.TABLE_ENV, "harness-agentcore-sessions-x")
    assert L._session_tenant("s-a") == "tenant-a-bank"
    assert L._session_tenant("s-zz") is None
    assert L._session_tenant("") is None          # no call for an empty id
    assert len(calls) == 2
    assert all(c["ConsistentRead"] and
               c["TableName"] == "harness-agentcore-sessions-x" for c in calls)


# --------------------------------------------------------------------------- #
# Gateway Lambda target                                                       #
# --------------------------------------------------------------------------- #
def ctx(tool):
    return SimpleNamespace(client_context=SimpleNamespace(
        custom={"bedrockAgentCoreToolName": f"reviews___{tool}"}))


def test_tools_handler_reads_a_review():
    out = L.tools_handler({"review_id": "REVIEW-A1"}, ctx("get_review"))
    assert out == {"review_id": "REVIEW-A1",
                   "title": "Capital adequacy review", "open_findings": 2}
    assert "tenant_id" not in out


def test_tools_handler_validates_finding_status():
    ok = L.tools_handler({"review_id": "REVIEW-A1", "control_area": "x",
                          "status": "partial"}, ctx("add_finding"))
    bad = L.tools_handler({"review_id": "REVIEW-A1", "control_area": "x",
                           "status": "done"}, ctx("add_finding"))
    assert ok["recorded"] is True and "error" in bad


@pytest.mark.parametrize("event,context,err", [
    ({"review_id": "REVIEW-Z9"}, ctx("get_review"), "not found"),
    ({}, ctx("drop_tables"), "unknown tool"),
    ({}, None, "unknown tool"),
])
def test_tools_handler_errors(event, context, err):
    assert err in L.tools_handler(event, context)["error"]


def test_hook_surface_is_a_subset_of_the_gateway_schemas():
    names = {t["name"] for t in L.TOOL_SCHEMAS}
    assert set(L.HOOK_TOOLS) < names and "delete_review" in names
    for t in L.TOOL_SCHEMAS:
        schema = t["inputSchema"]
        assert schema["type"] == "object"
        assert set(schema["required"]) <= set(schema["properties"])


def test_another_targets_tool_does_not_borrow_the_allowlist():
    out = decide("admin___get_review", {"review_id": "REVIEW-A1"})
    assert out == {"decision": "deny",
                   "reason": "[hook] tool is not on this target"}


@pytest.mark.parametrize("name,tool", [
    ("reviews___get_review", "get_review"),
    ("get_review", "get_review"),
    ("admin___get_review", None),
    ("gw___reviews___get_review", None),
    (None, ""),
])
def test_hook_tool(name, tool):
    assert L.hook_tool(name) == tool


def test_the_hook_refuses_the_agents_sign_off_like_cedar():
    """If the Cedar engine drifts to LOG_ONLY, the hook still refuses."""
    out = decide("reviews___add_finding",
                 {"review_id": "REVIEW-A1", "control_area": "x",
                  "status": "complied"})
    assert out["decision"] == "deny" and out["reason"].startswith("[sign-off]")
    gap = decide("reviews___add_finding",
                 {"review_id": "REVIEW-A1", "control_area": "x",
                  "status": "not_complied"})
    assert gap == {"decision": "allow"}


def test_duplicate_json_keys_are_denied():
    """A later parser that keeps the first key would read another review."""
    out = decide("get_review",
                 '{"review_id": "REVIEW-B1", "review_id": "REVIEW-A1"}')
    assert out["decision"] == "deny" and "not valid JSON" in out["reason"]


@pytest.mark.parametrize("event", [None, [], "x",
                                   {"event": "before_tool_call"},
                                   {"event": "before_tool_call",
                                    "context": "x"}])
def test_malformed_events_are_denied(event):
    assert L.decide(event, SESSIONS.get)["decision"] == "deny"


def test_hook_handler_logs_a_placeholder_for_a_malformed_event(capsys):
    assert L.hook_handler(None)["decision"] == "deny"
    assert json.loads(capsys.readouterr().out)["tool"] == "?"
