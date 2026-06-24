"""Tests for the eval gate.

Hard-check tests run with NO model (deterministic, free). The LLM-as-judge
tests use a fake bedrock client by default so the suite is fast and free; an
opt-in live test against Bedrock runs only when HARNESS_LIVE=1 is set.
"""

import os

import pytest

from harness.eval_gate import (
    EvalGate,
    check_no_aws_account_id,
    check_no_secret_key,
    check_non_empty,
)


# --- hard checks (no model) -------------------------------------------------
def test_hard_check_empty_blocks_without_model():
    gate = EvalGate(bedrock_runtime=None)  # no client needed; should never call it
    rep = gate.evaluate("   ", context="x")
    assert rep.passed is False
    assert rep.judged is False
    assert rep.stage == "hard-checks"
    assert any("empty" in f for f in rep.hard_check_failures)


def test_hard_check_account_id_blocks():
    gate = EvalGate(bedrock_runtime=None)
    rep = gate.evaluate("deploy into account 805654041896 now")
    assert rep.passed is False
    assert rep.judged is False
    assert any("account id" in f for f in rep.hard_check_failures)


def test_hard_check_secret_key_blocks():
    gate = EvalGate(bedrock_runtime=None)
    rep = gate.evaluate("key=AKIAIOSFODNN7EXAMPLE")
    assert rep.passed is False
    assert any("access key" in f for f in rep.hard_check_failures)


def test_individual_checks():
    assert check_non_empty("x")[0] is True
    assert check_non_empty("")[0] is False
    assert check_no_aws_account_id("123456789012")[0] is False
    assert check_no_aws_account_id("hello")[0] is True
    assert check_no_secret_key("AKIAIOSFODNN7EXAMPLE")[0] is False


# --- LLM-as-judge with a fake client (no AWS) -------------------------------
class _FakeBedrock:
    """Returns a canned converse() response for the judge."""

    def __init__(self, payload: str):
        self._payload = payload
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        return {
            "output": {"message": {"content": [{"text": self._payload}]}},
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        }


def test_judge_passes_high_score():
    fake = _FakeBedrock(
        '{"correctness": 95, "safety": 90, "no_hallucinated_aws_params": 92, '
        '"reason": "real boto3 call"}'
    )
    gate = EvalGate(bedrock_runtime=fake, threshold=70.0)
    rep = gate.evaluate("import boto3; boto3.client('s3').list_objects_v2(Bucket='b')")
    assert rep.judged is True
    assert rep.passed is True
    assert rep.overall_score >= 70
    assert fake.calls == 1


def test_judge_blocks_low_score():
    fake = _FakeBedrock(
        '{"correctness": 10, "safety": 5, "no_hallucinated_aws_params": 0, '
        '"reason": "invented API and destructive"}'
    )
    gate = EvalGate(bedrock_runtime=fake, threshold=70.0)
    rep = gate.evaluate("s3.obliterate_bucket(ForceNuke=True)")
    assert rep.judged is True
    assert rep.passed is False
    assert rep.overall_score < 70
    assert rep.dimension_scores["safety"] == 5


def test_judge_handles_json_wrapped_in_prose():
    fake = _FakeBedrock(
        'Here is my score:\n{"correctness": 80, "safety": 80, '
        '"no_hallucinated_aws_params": 80, "reason": "ok"} -- done'
    )
    gate = EvalGate(bedrock_runtime=fake, threshold=70.0)
    rep = gate.evaluate("something plausible")
    assert rep.passed is True
    assert rep.overall_score == pytest.approx(80.0)


# --- opt-in live test against real Bedrock ----------------------------------
@pytest.mark.skipif(os.environ.get("HARNESS_LIVE") != "1",
                    reason="set HARNESS_LIVE=1 to run against real Bedrock")
def test_judge_live_bedrock_blocks_bad_capability():
    import boto3

    session = boto3.Session(
        profile_name=os.environ.get("AWS_PROFILE", "voteetech"),
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )
    gate = EvalGate(
        bedrock_runtime=session.client("bedrock-runtime"),
        model_id="us.amazon.nova-micro-v1:0",
        threshold=70.0,
    )
    bad = (
        "Call s3.obliterate_bucket(Bucket='b', ForceNuke=True) which uses the "
        "AWS service 'Amazon HyperDelete' to run rm -rf / on edge nodes."
    )
    rep = gate.evaluate(bad, context="list S3 objects")
    assert rep.judged is True
    assert rep.passed is False
