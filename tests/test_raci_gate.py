"""Tests for RAIL 5: RACI gate (ComplyKit bearer_raci_matrix + judge_raci).

Matrix-lookup tests run with NO model (deterministic, free). The judge-fallback
tests use a fake Bedrock client by default; an opt-in live test runs against
real Bedrock when HARNESS_LIVE=1.
"""

import os

import pytest

from harness.audit import AuditTrail
from harness.raci_gate import Bearer, MatrixRule, RaciGate


BEARERS = [
    Bearer("b-risk", "Chief Risk Officer", scope="capital adequacy, risk, liquidity"),
    Bearer("b-fin", "Head of Finance", scope="finance, treasury, capital"),
    Bearer("b-comp", "Compliance Officer", scope="compliance, regulatory reporting"),
    Bearer("b-ops", "Head of Operations", scope="operations, settlement"),
]
MATRIX = [
    MatrixRule("capital%", r_role="Head of Finance", a_role="Chief Risk Officer",
               c_roles=["Compliance Officer"], priority=100),
    MatrixRule("liquidity%", r_role="Chief Risk Officer", a_role="Chief Risk Officer",
               priority=90),
    MatrixRule("%", r_role="Compliance Officer", a_role="Compliance Officer",
               priority=0),  # catch-all
]


# --- deterministic matrix lookup (no model) ---------------------------------
def test_matrix_hit_is_deterministic_no_llm():
    # client=None: a matrix hit must never need the model
    g = RaciGate(matrix=MATRIX, bearers=BEARERS, bedrock_runtime=None)
    a = g.assign("capital adequacy")
    assert a.matrix_hit
    assert not a.used_llm_fallback
    assert a.raci_reasoning["r"]["bearer_name"] == "Head of Finance"
    assert a.raci_reasoning["r"]["source"] == "matrix"
    assert a.raci_reasoning["a"]["bearer_name"] == "Chief Risk Officer"
    # Consulted resolved too
    assert a.raci_reasoning["c"][0]["bearer_name"] == "Compliance Officer"


def test_highest_priority_rule_wins():
    g = RaciGate(matrix=MATRIX, bearers=BEARERS, bedrock_runtime=None)
    # "capital adequacy" matches both "capital%" (p100) and "%" (p0) -> p100 wins
    a = g.assign("capital adequacy")
    assert a.raci_reasoning["r"]["bearer_name"] == "Head of Finance"


def test_catch_all_rule_matches_when_specific_miss():
    g = RaciGate(matrix=MATRIX, bearers=BEARERS, bedrock_runtime=None)
    a = g.assign("market conduct supervision")  # only "%" matches
    assert a.matrix_hit
    assert a.raci_reasoning["r"]["bearer_name"] == "Compliance Officer"


def test_matrix_miss_without_client_yields_no_assignment():
    # no catch-all this time -> genuine miss; no client -> no fallback
    g = RaciGate(matrix=[MATRIX[0]], bearers=BEARERS, bedrock_runtime=None)
    a = g.assign("cybersecurity incident response")
    assert not a.matrix_hit
    assert not a.used_llm_fallback
    assert a.raci_reasoning["r"] is None
    assert a.missing_accountable


def test_missing_accountable_flagged():
    # a rule whose A role does not resolve to any bearer
    matrix = [MatrixRule("ops%", r_role="Head of Operations",
                         a_role="Nonexistent Role", priority=50)]
    g = RaciGate(matrix=matrix, bearers=BEARERS, bedrock_runtime=None)
    a = g.assign("ops resilience")
    assert a.raci_reasoning["r"]["bearer_name"] == "Head of Operations"
    assert a.missing_accountable


def test_raci_assignment_written_to_audit():
    audit = AuditTrail(path=None)
    g = RaciGate(matrix=MATRIX, bearers=BEARERS, bedrock_runtime=None,
                 audit=audit, tenant_id="t1")
    g.assign("capital adequacy", action_id="ACT-1")
    entries = audit.entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["event"] == "raci_assigned"
    assert e["actor"] == "raci_gate"
    assert e["inputs"]["control_area"] == "capital adequacy"
    assert e["outputs"]["raci_reasoning"]["r"]["source"] == "matrix"


# --- judge fallback with a fake Bedrock client ------------------------------
class _FakeBedrock:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        return {"output": {"message": {"content": [{"text": self._payload}]}},
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}}


def test_judge_fallback_on_matrix_miss():
    fake = _FakeBedrock(
        '{"r_bearer_id": "b-ops", "a_bearer_id": "b-comp", '
        '"reasoning_r": "ops owns response", "reasoning_a": "compliance signs off"}'
    )
    g = RaciGate(matrix=[MATRIX[0]], bearers=BEARERS, bedrock_runtime=fake)
    a = g.assign("cybersecurity incident response")
    assert not a.matrix_hit
    assert a.used_llm_fallback
    assert fake.calls == 1
    assert a.raci_reasoning["r"]["bearer_id"] == "b-ops"
    assert a.raci_reasoning["r"]["source"] == "llm_fallback"
    assert a.raci_reasoning["a"]["bearer_id"] == "b-comp"
    assert not a.missing_accountable


def test_judge_not_called_on_matrix_hit():
    fake = _FakeBedrock("{}")
    g = RaciGate(matrix=MATRIX, bearers=BEARERS, bedrock_runtime=fake)
    g.assign("capital adequacy")  # fully resolved by matrix
    assert fake.calls == 0  # the model was never consulted


def test_judge_constrains_to_known_bearer_ids():
    # model hallucinates an unknown bearer id -> dropped (constraint)
    fake = _FakeBedrock(
        '{"r_bearer_id": "b-hallucinated", "a_bearer_id": "b-comp", '
        '"reasoning_r": "x", "reasoning_a": "y"}'
    )
    g = RaciGate(matrix=[MATRIX[0]], bearers=BEARERS, bedrock_runtime=fake)
    a = g.assign("cyber incident")
    # r dropped (invalid id), a kept
    assert a.raci_reasoning["r"] is None
    assert a.raci_reasoning["a"]["bearer_id"] == "b-comp"


def test_judge_failure_is_failsafe():
    class _Boom:
        def converse(self, **kwargs):
            raise RuntimeError("bedrock down")

    g = RaciGate(matrix=[MATRIX[0]], bearers=BEARERS, bedrock_runtime=_Boom())
    a = g.assign("cyber incident")  # miss + judge throws
    assert not a.used_llm_fallback
    assert a.raci_reasoning["r"] is None  # no assignment, but no crash


# --- opt-in live test against real Bedrock ----------------------------------
@pytest.mark.skipif(os.environ.get("HARNESS_LIVE") != "1",
                    reason="set HARNESS_LIVE=1 to run against real Bedrock")
def test_judge_fallback_live_bedrock():
    import boto3
    session = boto3.Session(
        profile_name=os.environ.get("AWS_PROFILE", "voteetech"),
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )
    g = RaciGate(
        matrix=[MATRIX[0]], bearers=BEARERS,
        bedrock_runtime=session.client("bedrock-runtime"),
        model_id="us.amazon.nova-micro-v1:0",
    )
    a = g.assign("cybersecurity incident response")
    assert not a.matrix_hit
    # the live judge should pick a valid Responsible bearer from the known set
    if a.used_llm_fallback and a.raci_reasoning["r"]:
        assert a.raci_reasoning["r"]["bearer_id"] in {b.bearer_id for b in BEARERS}
        assert a.raci_reasoning["r"]["source"] == "llm_fallback"
