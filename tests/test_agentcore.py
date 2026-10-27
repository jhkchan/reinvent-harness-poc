"""Tests for the rails on AgentCore (offline, NO AWS calls).

A fake boto3 session stands in for IAM, Lambda, DynamoDB, CloudWatch Logs
and both AgentCore clients, so these tests prove the build order, the IAM
scoping, the Cedar text, the stream parsing, the scenarios and the teardown
without credentials.
"""

import io
import json
import subprocess
import sys
import zipfile

import pytest
from botocore.credentials import Credentials

from harness import agentcore as ac
from harness.audit import AuditTrail
from harness.sandbox import SandboxLog

ACCOUNT = "123456789012"


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #
class FakeClientError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(f"{code}: {msg}")
        self.response = {"Error": {"Code": code, "Message": msg}}


class World:
    def __init__(self):
        self.roles, self.functions, self.tables = {}, {}, {}
        self.log_groups = []
        self.engines, self.gateways, self.targets = {}, {}, {}
        self.policies, self.harnesses = {}, {}
        self.calls, self.fail = [], {}
        self.harness_kwargs = None
        self.items = {}
        self.conditions = []
        self.workload_identities = []
        self.late_export = {}     # log group -> recreated once after delete
        self.pending = []

    def hit(self, op):
        self.calls.append(op)
        if op in self.fail:
            raise self.fail[op]


class Waiter:
    def wait(self, **kw):
        pass


class FakeSts:
    def __init__(self, w):
        self.w = w

    def get_caller_identity(self):
        return {"Account": ACCOUNT}


class FakeIam:
    def __init__(self, w):
        self.w = w

    def create_role(self, RoleName, Path, AssumeRolePolicyDocument, **kw):
        self.w.hit("create_role")
        self.w.roles[RoleName] = {"trust": json.loads(AssumeRolePolicyDocument),
                                  "policies": {}}
        return {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT}:role{Path}{RoleName}"}}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.w.roles[RoleName]["policies"][PolicyName] = json.loads(
            PolicyDocument)

    def list_role_policies(self, RoleName):
        return {"PolicyNames": list(self.w.roles[RoleName]["policies"])}

    def delete_role_policy(self, RoleName, PolicyName):
        del self.w.roles[RoleName]["policies"][PolicyName]

    def delete_role(self, RoleName):
        self.w.hit("delete_role")
        del self.w.roles[RoleName]

    def list_roles(self, **kw):
        return {"Roles": [{"RoleName": r} for r in self.w.roles],
                "IsTruncated": False}


class FakeLambda:
    def __init__(self, w):
        self.w = w

    def create_function(self, FunctionName, Role, Code, **kw):
        self.w.hit("create_function")
        arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FunctionName}"
        self.w.functions[FunctionName] = {"arn": arn, "role": Role, **kw,
                                          "zip": Code["ZipFile"]}
        self.w.log_groups.append(f"/aws/lambda/{FunctionName}")
        return {"FunctionArn": arn}

    def get_function_configuration(self, FunctionName):
        return {"State": "Active"}

    def delete_function(self, FunctionName):
        self.w.hit("delete_function")
        del self.w.functions[FunctionName]

    def list_functions(self, **kw):
        return {"Functions": [{"FunctionName": f} for f in self.w.functions]}


class FakeDynamo:
    def __init__(self, w):
        self.w = w

    def create_table(self, TableName, **kw):
        self.w.hit("create_table")
        self.w.tables[TableName] = kw
        return {"TableDescription": {
            "TableArn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/"
                        f"{TableName}"}}

    def get_waiter(self, name):
        return Waiter()

    def put_item(self, TableName, Item, ConditionExpression=None):
        sid = Item["session_id"]["S"]
        if ConditionExpression == "attribute_not_exists(session_id)" and \
                sid in self.w.items:
            raise FakeClientError("ConditionalCheckFailedException")
        self.w.items[sid] = Item["tenant_id"]["S"]
        self.w.conditions.append(ConditionExpression)

    def delete_table(self, TableName):
        self.w.hit("delete_table")
        del self.w.tables[TableName]

    def list_tables(self, **kw):
        return {"TableNames": list(self.w.tables)}


class FakeLogs:
    def __init__(self, w):
        self.w = w

    def describe_log_groups(self, logGroupNamePattern, **kw):
        return {"logGroups": [{"logGroupName": g} for g in self.w.log_groups
                              if logGroupNamePattern in g]}

    def delete_log_group(self, logGroupName):
        self.w.hit("delete_log_group")
        self.w.log_groups.remove(logGroupName)
        if self.w.late_export.pop(logGroupName, None):   # exported late
            self.w.pending.append(logGroupName)


def _gone(store, key):
    if key not in store:
        raise FakeClientError("ResourceNotFoundException")
    return store[key]


class FakeControl:
    def __init__(self, w):
        self.w = w

    def create_policy_engine(self, name, **kw):
        self.w.hit("create_policy_engine")
        eid = f"{name}-e1"
        self.w.engines[eid] = name
        return {"policyEngineId": eid, "policyEngineArn": f"arn:pe/{eid}"}

    def get_policy_engine(self, policyEngineId):
        _gone(self.w.engines, policyEngineId)
        return {"status": "ACTIVE"}

    def delete_policy_engine(self, policyEngineId):
        self.w.hit("delete_policy_engine")
        assert not self.w.policies, "engine deleted before its policies"
        assert not self.w.gateways, "engine deleted while a gateway uses it"
        del self.w.engines[policyEngineId]

    def create_gateway(self, name, **kw):
        self.w.hit("create_gateway")
        gid = f"{name}-g1"
        self.w.gateways[gid] = kw
        return {"gatewayId": gid,
                "gatewayArn": f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}"
                              f":gateway/{gid}",
                "gatewayUrl": f"https://{gid}.gateway.example/mcp"}

    def get_gateway(self, gatewayIdentifier):
        _gone(self.w.gateways, gatewayIdentifier)
        return {"status": "READY",
                "gatewayUrl": f"https://{gatewayIdentifier}.gateway.example/mcp"}

    def delete_gateway(self, gatewayIdentifier):
        self.w.hit("delete_gateway")
        assert not self.w.targets, "gateway deleted before its target"
        del self.w.gateways[gatewayIdentifier]

    def create_gateway_target(self, gatewayIdentifier, name, **kw):
        self.w.hit("create_gateway_target")
        self.w.targets["t1"] = kw
        return {"targetId": "t1"}

    def get_gateway_target(self, gatewayIdentifier, targetId):
        _gone(self.w.targets, targetId)
        return {"status": "READY"}

    def delete_gateway_target(self, gatewayIdentifier, targetId):
        self.w.hit("delete_gateway_target")
        del self.w.targets[targetId]

    def create_policy(self, policyEngineId, name, definition, **kw):
        self.w.hit("create_policy")
        self.w.policies[name] = definition["cedar"]["statement"]
        return {"policyId": name}

    def get_policy(self, policyEngineId, policyId):
        _gone(self.w.policies, policyId)
        return {"status": "ACTIVE"}

    def delete_policy(self, policyEngineId, policyId):
        self.w.hit("delete_policy")
        del self.w.policies[policyId]

    def create_harness(self, **kw):
        self.w.hit("create_harness")
        self.w.harness_kwargs = kw
        hid = f"{kw['harnessName']}-h1"
        self.w.harnesses[hid] = kw["harnessName"]
        self.w.log_groups.append(
            f"/aws/bedrock-agentcore/runtimes/{kw['harnessName']}-x-DEFAULT")
        return {"harness": {"harnessId": hid, "arn": f"arn:harness/{hid}"}}

    def get_harness(self, harnessId):
        _gone(self.w.harnesses, harnessId)
        return {"harness": {"status": "READY"}}

    def delete_harness(self, harnessId):
        self.w.hit("delete_harness")
        del self.w.harnesses[harnessId]

    def list_harnesses(self, **kw):
        return {"harnesses": [{"harnessName": n}
                              for n in self.w.harnesses.values()]}

    def list_agent_runtimes(self, **kw):
        return {"agentRuntimes": []}

    def list_gateways(self, **kw):
        return {"items": [{"name": g} for g in self.w.gateways]}

    def list_policy_engines(self, **kw):
        return {"policyEngines": [{"name": n} for n in self.w.engines.values()]}

    def list_workload_identities(self, **kw):
        return {"workloadIdentities": [{"name": n}
                                       for n in self.w.workload_identities]}


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, w):
        self.w = w

    def client(self, name, **kw):
        return {"sts": FakeSts, "iam": FakeIam, "lambda": FakeLambda,
                "dynamodb": FakeDynamo, "logs": FakeLogs,
                "bedrock-agentcore-control": FakeControl}[name](self.w)

    def get_credentials(self):
        return Credentials("AKIDEXAMPLEEXAMPLE00", "secret-example-key")


def stack(w=None, **kw):
    w = w or World()
    s = ac.AgentCoreStack(session=FakeSession(w), run_id="r1",
                          log=SandboxLog(echo=False), sleep=lambda _: None,
                          poll_seconds=0, role_propagation_seconds=0, **kw)
    return s, w


GW_ARN = f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:gateway/gw-1"


# --------------------------------------------------------------------------- #
# Cedar and IAM                                                               #
# --------------------------------------------------------------------------- #
def test_cedar_permits_two_tools_and_forbids_agent_sign_off():
    p = ac.cedar_policies(GW_ARN)
    assert set(p) == {"permit_get_review", "permit_add_finding",
                      "forbid_agent_sign_off"}
    assert all(f'resource == AgentCore::Gateway::"{GW_ARN}"' in s
               for s in p.values())
    assert p["permit_get_review"].startswith("permit(")
    assert 'AgentCore::Action::"reviews___get_review"' in \
        p["permit_get_review"]
    # the validator rejects a permit with no condition ("Overly Permissive")
    assert all(" when { " in s for s in p.values())
    # a forbid before any permit on its action is "Overly Restrictive"
    assert list(p)[-1] == "forbid_agent_sign_off"
    forbid = p["forbid_agent_sign_off"]
    assert forbid.startswith("forbid(") and \
        'context.input.status == "complied"' in forbid
    # delete_review has no permit at all: Cedar's default deny covers it
    assert not any("delete_review" in s for s in p.values())


def test_agentcore_trust_pins_account_and_source():
    t = json.loads(ac._agentcore_trust(ACCOUNT, "arn:x:gateway/gw-*"))
    st = t["Statement"][0]
    assert st["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    assert st["Condition"]["StringEquals"] == {"aws:SourceAccount": ACCOUNT}
    assert st["Condition"]["ArnLike"] == {"aws:SourceArn": "arn:x:gateway/gw-*"}
    plain = json.loads(ac._agentcore_trust(ACCOUNT))["Statement"][0]
    assert "ArnLike" not in plain["Condition"]


def _stmts(doc):
    return json.loads(doc)["Statement"]


def test_harness_role_reaches_only_this_gateway_hook_and_model():
    hook = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:hook"
    st = {s["Sid"]: s for s in _stmts(ac.harness_policy(
        "us-east-1", ACCOUNT, "us.amazon.nova-lite-v1:0", GW_ARN, hook,
        "harness_agentcore_r1"))}
    assert st["Gateway"]["Resource"] == GW_ARN
    assert st["Hook"]["Resource"] == hook
    assert st["Model"]["Resource"] == [
        "arn:aws:bedrock:*::foundation-model/amazon.nova-lite-v1:0",
        f"arn:aws:bedrock:*:{ACCOUNT}:inference-profile/"
        f"us.amazon.nova-lite-v1:0"]
    assert all("*" not in a for s in st.values()
               for a in ([s["Action"]] if isinstance(s["Action"], str)
                         else s["Action"]))
    assert st["Metrics"]["Condition"]["StringEquals"] == {
        "cloudwatch:namespace": "bedrock-agentcore"}


def test_model_arns_for_a_plain_model_id():
    assert ac.model_arns(ACCOUNT, "amazon.nova-micro-v1:0") == [
        "arn:aws:bedrock:*::foundation-model/amazon.nova-micro-v1:0"]


def test_gateway_role_can_call_only_the_tools_function_and_policy():
    st = _stmts(ac.gateway_policy("us-east-1", ACCOUNT, "arn:fn:tools",
                                  "arn:pe/e1", "harness-agentcore-r1"))
    assert st[0] == {"Effect": "Allow", "Action": "lambda:InvokeFunction",
                     "Resource": "arn:fn:tools"}
    assert st[2]["Resource"] == [
        "arn:pe/e1", f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:"
                     f"gateway/harness-agentcore-r1-*"]


def test_function_roles_are_least_privilege():
    hook = _stmts(ac.hook_fn_policy("us-east-1", ACCOUNT, "fn-h",
                                    "arn:table/t"))
    tools = _stmts(ac.tools_fn_policy("us-east-1", ACCOUNT, "fn-t"))
    assert hook[0] == {"Effect": "Allow", "Action": "dynamodb:GetItem",
                       "Resource": "arn:table/t"}
    assert len(tools) == 1 and all(a.startswith("logs:")
                                   for a in tools[0]["Action"])
    assert tools[0]["Resource"] == ac.function_log_arns("us-east-1", ACCOUNT,
                                                        "fn-t")


# --------------------------------------------------------------------------- #
# Lambda zip                                                                  #
# --------------------------------------------------------------------------- #
def test_lambda_zip_holds_only_the_stdlib_gate_modules(tmp_path):
    data = ac.build_lambda_zip()
    names = sorted(zipfile.ZipFile(io.BytesIO(data)).namelist())
    assert names == sorted(f"harness/{n}" for n in ac.PACKAGE_FILES)
    zipfile.ZipFile(io.BytesIO(data)).extractall(tmp_path)
    code = ("import sys; sys.path.insert(0, sys.argv[1]); "
            "import harness.agentcore_lambdas as m; "
            "print(m.decide({'event': 'before_tool_call', 'sessionId': 's', "
            "'context': {'toolName': 'reviews___get_review', "
            "'toolInput': {'review_id': 'REVIEW-A1'}}}, "
            "{'s': 'tenant-a-bank'}.get)['decision'])")
    out = subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path)],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "allow"


# --------------------------------------------------------------------------- #
# Stream and JSON-RPC parsing                                                 #
# --------------------------------------------------------------------------- #
def test_read_stream_keys_tool_calls_by_message_and_block():
    stream = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {
            "toolUseId": "t1", "name": "reviews___get_review"}}}},
        {"contentBlockDelta": {"contentBlockIndex": 0,
                               "delta": {"toolUse": {"input": '{"review_'}}}},
        {"contentBlockDelta": {"contentBlockIndex": 0,
                               "delta": {"toolUse": {"input": 'id":"A"}'}}}},
        {"hookEvent": {"hookEventId": "e1", "name": "gate",
                       "type": "before_tool_call", "decision": "deny",
                       "reason": "[cross-tenant] x"}},
        {"messageStart": {"role": "assistant"}},
        {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {
            "toolUseId": "t2", "name": "reviews___add_finding"}}}},
        {"contentBlockDelta": {"contentBlockIndex": 0,
                               "delta": {"text": "Access was "}}},
        {"contentBlockDelta": {"contentBlockIndex": 1,
                               "delta": {"text": "denied."}}},
        {"runtimeClientError": {"message": "boom"}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    r = ac.read_stream(stream)
    assert [c["name"] for c in r.tool_calls] == ["reviews___get_review",
                                                 "reviews___add_finding"]
    assert r.tool_calls[0]["input"] == '{"review_id":"A"}'
    assert r.decisions() == [("deny", "[cross-tenant] x")]
    assert r.text == "Access was denied."
    assert r.stop_reason == "end_turn"
    assert r.errors == ["runtimeClientError: boom"]


def test_parse_rpc_reads_json_and_server_sent_events():
    assert ac.parse_rpc('{"jsonrpc":"2.0","id":1,"result":{}}')["id"] == 1
    sse = 'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{}}\n\n'
    assert ac.parse_rpc(sse)["id"] == 2
    with pytest.raises(ValueError):
        ac.parse_rpc("event: ping\n")


DENY_DEFAULT = ("Tool Execution Denied: Tool call not allowed due to policy "
                "enforcement [No policy applies to the request (denied by "
                "default).]")
DENY_FORBID = ("Tool Execution Denied: Tool call not allowed due to policy "
               "enforcement [Policy evaluation denied due to "
               "forbid_agent_sign_off-1pz4hy1zr0]")


@pytest.mark.parametrize("reply,want", [
    ({"result": {"isError": False, "content": []}}, ("allow", "")),
    ({"error": {"code": -32002, "message": DENY_DEFAULT}},
     ("deny", "No policy applies to the request (denied by default).")),
    ({"error": {"code": -32002, "message": DENY_FORBID}},
     ("deny", "Policy evaluation denied due to "
              "forbid_agent_sign_off-1pz4hy1zr0")),
])
def test_policy_decision_reads_cedars_reason(reply, want):
    assert ac.policy_decision(reply) == want


@pytest.mark.parametrize("reply", [
    {"error": {"code": -32602, "message": "Unknown tool: reviews___x"}},
    {"error": {"code": -32002, "message": "throttled"}},
    {"result": {"isError": True, "content": []}},
])
def test_errors_that_are_not_policy_decisions_raise(reply):
    """An unknown tool or a tool error must never pass as a Cedar deny."""
    with pytest.raises(RuntimeError):
        ac.policy_decision(reply)


def test_gateway_rpc_is_sigv4_signed_and_http_errors_raise():
    seen = {}

    def post(url, data, headers, timeout):
        seen.update(url=url, body=json.loads(data), headers=headers)
        return 403, '{"message": "not authorized"}'

    s, _ = stack(http_post=post)
    s.gateway_url = "https://gw-1.gateway.example/mcp"
    with pytest.raises(RuntimeError, match="gateway HTTP 403"):
        s.gateway_rpc("tools/list", {})     # not a policy decision
    auth = seen["headers"]["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert "/us-east-1/bedrock-agentcore/aws4_request" in auth
    assert seen["body"]["method"] == "tools/list"


# --------------------------------------------------------------------------- #
# Lifecycle                                                                   #
# --------------------------------------------------------------------------- #
def test_provision_wires_hook_gateway_policy_and_harness():
    s, w = stack()
    s.provision()
    kw = w.harness_kwargs
    hook = kw["hooks"][0]["beforeToolCall"]
    assert hook["target"]["lambda"] == {
        "arn": s.functions[s.hook_fn], "timeoutSeconds": 10,
        "failureMode": "deny"}
    assert kw["memory"] == {"disabled": {}}
    assert kw["tools"][0]["config"]["agentCoreGateway"] == {
        "gatewayArn": s.gateway_arn, "outboundAuth": {"awsIam": {}}}
    assert kw["model"]["bedrockModelConfig"]["modelId"] == s.model_id
    gw = w.gateways[s.gateway_id]
    assert gw["authorizerType"] == "AWS_IAM"
    assert gw["policyEngineConfiguration"] == {"arn": s.engine_arn,
                                               "mode": "ENFORCE"}
    assert set(w.policies) == set(ac.cedar_policies(s.gateway_arn))
    assert w.functions[s.hook_fn]["Environment"] == {
        "Variables": {"SESSIONS_TABLE": s.table}}
    # the Cedar policies go in after the target exists, the harness last
    order = [c for c in w.calls if c.startswith("create_")]
    assert order.index("create_gateway_target") < order.index("create_policy")
    assert order[-1] == "create_harness"


def test_every_name_carries_the_prefix_and_run_id():
    s, w = stack()
    s.provision()
    names = (list(w.roles) + list(w.functions) + list(w.tables)
             + list(w.harnesses.values()) + list(w.engines.values())
             + list(w.gateways))
    assert names and all(("harness-agentcore" in n or "harness_agentcore" in n)
                         and "r1" in n for n in names)


def test_sessions_are_registered_only_when_a_tenant_is_given():
    s, w = stack()
    s.provision()
    a = s.new_session("tenant-a-bank")
    anon = s.new_session(None)
    assert w.items == {a: "tenant-a-bank"} and anon not in w.items
    assert 33 <= len(a) <= 100      # InvokeHarness runtimeSessionId limits
    # a session id is never re-registered to another tenant
    assert w.conditions == ["attribute_not_exists(session_id)"]


def test_teardown_deletes_everything_in_dependency_order():
    s, w = stack()
    s.provision()
    assert s.teardown() is True
    for store in (w.roles, w.functions, w.tables, w.engines, w.gateways,
                  w.targets, w.policies, w.harnesses):
        assert not store
    assert w.log_groups == []
    d = [c for c in w.calls if c.startswith("delete_")]
    assert d[0] == "delete_harness"
    assert d.index("delete_gateway_target") < d.index("delete_gateway") \
        < d.index("delete_policy_engine")


def test_failure_mid_provision_tears_down_the_partial_stack():
    w = World()
    w.fail["create_gateway"] = FakeClientError("ValidationException", "bad")
    s, w = stack(w)
    results = s.run()
    assert "ValidationException" in results["error"]
    assert s.clean is True
    assert not (w.roles or w.functions or w.tables or w.engines)
    assert "create_harness" not in w.calls


def test_teardown_error_is_logged_not_raised():
    s, w = stack()
    s.provision()
    w.fail["delete_harness"] = FakeClientError("ThrottlingException")
    assert s.teardown() is False            # the harness is still there
    assert any("delete harness: ThrottlingException" in ln
               for ln in s.log.lines)
    assert not w.functions                  # later steps still ran


def test_teardown_never_deletes_another_runs_log_group():
    s, w = stack()
    s.provision()
    w.log_groups.append("/aws/lambda/harness-agentcore-hook-OTHER")
    s.teardown()
    assert w.log_groups == ["/aws/lambda/harness-agentcore-hook-OTHER"]


def test_cleanup_check_counts_only_our_names():
    w = World()
    w.roles = {"harness-agentcore-hookfn-x": {}, "unrelated-role": {}}
    w.functions = {"other-fn": {}}
    w.tables = {"harness-agentcore-sessions-x": {}}
    w.log_groups = ["/aws/bedrock-agentcore/runtimes/harness_agentcore_x-1",
                    "/aws/lambda/other"]
    w.workload_identities = ["harness_harness_agentcore_x-abc", "other-wi"]
    found = ac.cleanup_check(FakeSession(w))
    assert found["total"] == 4
    assert found["workload_identities"] == ["harness_harness_agentcore_x-abc"]
    assert found["iam_roles"] == ["harness-agentcore-hookfn-x"]


def test_log_redacts_account_ids_and_role_sessions(tmp_path):
    """An AccessDenied message names the account, the role and the session
    (often an email); none of them reaches the log."""
    path = tmp_path / "ac.log"
    w = World()
    w.fail["create_gateway"] = FakeClientError(
        "AccessDeniedException",
        f"User: arn:aws:sts::{ACCOUNT}:assumed-role/ExampleAdminRole_ab12/"
        f"jane.doe@example.com is not authorized")
    s, w = stack(w)
    s.log = SandboxLog(path=str(path), echo=False)
    s.run()
    text = path.read_text()
    assert "AccessDeniedException" in text          # the error is logged
    for leak in (ACCOUNT, "ExampleAdminRole", "jane.doe", "example.com"):
        assert leak not in text


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #
def test_cedar_scenarios_prove_list_deny_and_allow():
    s, _ = stack()

    def rpc(method, params):
        if method == "tools/list":
            return {"result": {"tools": [{"name": ac.tool_id("get_review")},
                                         {"name": ac.tool_id("add_finding")}]}}
        args = params["arguments"]
        if args.get("status") == "complied":
            return {"error": {"code": -32002, "message": DENY_FORBID}}
        if params["name"] == ac.tool_id("delete_review") or \
                not args["review_id"].startswith("REVIEW-"):
            return {"error": {"code": -32002, "message": DENY_DEFAULT}}
        return {"result": {"isError": False,
                           "content": [{"type": "text", "text": "{}"}]}}

    s.gateway_rpc = rpc
    audit = AuditTrail(path=None)
    out = ac.run_cedar_scenarios(s, audit)
    assert out and all(out.values())
    decisions = [e["outputs"]["decision"] for e in audit.entries()]
    assert decisions == ["deny", "deny", "deny", "allow"]


def test_cedar_scenario_fails_when_the_wrong_rule_denies():
    """The complied sign-off must be denied by the forbid, not by default."""
    s, _ = stack()
    s.gateway_rpc = lambda m, p: (
        {"result": {"tools": [{"name": ac.tool_id("get_review")}]}}
        if m == "tools/list" else
        {"error": {"code": -32002, "message": DENY_DEFAULT}})
    out = ac.run_cedar_scenarios(s, AuditTrail(path=None))
    assert out["add_finding(complied)"] is False
    assert out["delete_review"] is True


def test_cedar_scenarios_fail_when_delete_is_listed():
    s, _ = stack()
    s.gateway_rpc = lambda m, p: (
        {"result": {"tools": [{"name": ac.tool_id("delete_review")}]}}
        if m == "tools/list" else {"result": {"isError": False}})
    out = ac.run_cedar_scenarios(s, AuditTrail(path=None))
    assert out["list_hides_delete"] is False


def _result(decision=None, reason="", tools=("reviews___get_review",)):
    r = ac.InvokeResult(text="ok", stop_reason="end_turn")
    r.tool_calls = [{"name": t, "toolUseId": "t",
                     "input": '{"review_id": "REVIEW-A1"}'} for t in tools]
    if decision:
        r.hook_events = [{"type": "before_tool_call", "decision": decision,
                          "reason": reason}]
    return r


def test_hook_scenarios_prove_allow_and_both_denies():
    s, w = stack()
    s.provision()
    by_tenant = {"tenant-a-bank": _result("allow"),
                 "tenant-b-insurer": _result("deny", "[cross-tenant] x"),
                 None: _result("deny", "[require-tenant-id] x")}
    s.invoke = lambda sid, prompt: by_tenant[w.items.get(sid)]
    audit = AuditTrail(path=None)
    out = ac.run_hook_scenarios(s, audit)
    assert list(out.values()) == [True, True, True]
    assert [e["outputs"]["decision"] for e in audit.entries()] == \
        ["allow", "deny", "deny"]
    assert audit.verify().ok


def test_hook_scenario_without_a_tool_call_is_skipped_not_passed():
    s, _ = stack()
    s.provision()
    calls = []

    def invoke(sid, prompt):
        calls.append(sid)
        return _result(tools=())

    s.invoke = invoke
    out = ac.run_hook_scenarios(s, AuditTrail(path=None), attempts=2)
    assert list(out.values()) == [None, None, None]
    assert len(calls) == 6                  # each scenario retried once


def test_hook_scenario_with_the_wrong_decision_fails():
    s, w = stack()
    s.provision()
    s.invoke = lambda sid, prompt: _result("allow")
    out = ac.run_hook_scenarios(s, AuditTrail(path=None))
    assert out["tenant A reads its own review"] is True
    assert out["tenant B reads tenant A's review"] is False


# --------------------------------------------------------------------------- #
# Rail 5: AgentCore Evaluations as the eval gate's judge                      #
# --------------------------------------------------------------------------- #
def test_answer_drops_thinking_blocks():
    r = ac.InvokeResult(text="<thinking>call the tool</thinking>The title "
                             "is X.")
    assert r.answer == "The title is X."
    assert ac.InvokeResult(text="<thinking>never closed").answer == ""


def test_harness_logs_are_scoped_to_this_harness():
    st = {s["Sid"]: s for s in _stmts(ac.harness_policy(
        "us-east-1", ACCOUNT, "amazon.nova-lite-v1:0", GW_ARN, "arn:fn:h",
        "harness_agentcore_r1"))}
    assert st["Logs"]["Resource"] == [
        f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/bedrock-agentcore/"
        f"runtimes/harness_harness_agentcore_r1-*"]


class FakeEvaluations:
    def __init__(self, values, fail=()):
        self.values, self.fail, self.calls = values, set(fail), []

    def evaluate(self, evaluatorId, evaluationInput):
        self.calls.append((evaluatorId, evaluationInput))
        if evaluatorId in self.fail:
            raise FakeClientError("ThrottlingException")
        value = self.values.get(evaluatorId)
        res = {"evaluatorId": evaluatorId, "label": "x"}
        if value is not None:
            res["value"] = value
        return {"evaluationResults": [res]}


def test_turn_span_carries_prompt_answer_and_a_session():
    span = ac.turn_span("Q?", "A.")
    attrs = span["attributes"]
    assert attrs["agentcore.invocation.user_prompt"] == "Q?"
    assert attrs["agentcore.invocation.agent_response"] == "A."
    assert attrs["session.id"].startswith("harness-agentcore-eval-")
    assert len(span["traceId"]) == 32 and len(span["spanId"]) == 16


def test_evaluations_judge_scales_values_to_dimensions():
    client = FakeEvaluations({"Builtin.Helpfulness": 0.83,
                              "Builtin.InstructionFollowing": 1.0,
                              "Builtin.Harmfulness": 1.0})
    scores, reason = ac.evaluations_judge(client)("A.", "Q?")
    assert scores == {"Helpfulness": 83, "InstructionFollowing": 100,
                      "Harmfulness": 100}
    assert [c[0] for c in client.calls] == list(ac.EVALUATORS)
    assert "Helpfulness: x" in reason


def test_evaluations_judge_fails_closed_on_error_or_missing_value():
    client = FakeEvaluations({"Builtin.Helpfulness": 0.9},
                             fail={"Builtin.InstructionFollowing"})
    scores, reason = ac.evaluations_judge(client)("A.", "Q?")
    assert scores["InstructionFollowing"] == 0       # API error
    assert scores["Harmfulness"] == 0                # no value returned
    assert "ThrottlingException" in reason


def test_eval_scenarios_release_golden_and_block_off_task():
    s, _ = stack()
    good, bad = ac.GOLDEN[0][0], ac.GOLDEN[1][0]

    class ByAnswer(FakeEvaluations):
        def evaluate(self, evaluatorId, evaluationInput):
            answer = evaluationInput["sessionSpans"][0]["attributes"][
                "agentcore.invocation.agent_response"]
            self.values = {e: (1.0 if answer == good else 0.0)
                           for e in ac.EVALUATORS}
            return super().evaluate(evaluatorId, evaluationInput)

    s._clients["bedrock-agentcore"] = ByAnswer({})
    audit = AuditTrail(path=None)
    out = ac.run_eval_scenarios(s, audit)
    assert out == {good: True, bad: True}
    assert [e["outputs"]["passed"] for e in audit.entries()] == [True, False]


def test_teardown_still_cleans_when_the_agentcore_client_fails():
    s, w = stack()
    s.provision()

    class Broken(FakeSession):
        def client(self, name, **kw):
            if name == "bedrock-agentcore-control":
                raise FakeClientError("EndpointConnectionError")
            return super().client(name, **kw)

    s.session, s._clients = Broken(w), {}
    assert s.teardown() is False                # cannot prove it is clean
    assert not (w.functions or w.tables or w.roles)
    assert any("AgentCore client: EndpointConnectionError" in ln
               for ln in s.log.lines)


def test_read_stream_keeps_any_unknown_event_as_an_error():
    r = ac.read_stream([{"throttlingException": {"message": "slow down"}},
                        {"accessDeniedException": {}},
                        {"contentBlockStop": {"contentBlockIndex": 0}}])
    assert r.errors == ["throttlingException: slow down",
                        "accessDeniedException"]


@pytest.mark.parametrize("call,ok", [
    ({"name": "reviews___get_review", "input": '{"review_id": "REVIEW-A1"}'},
     True),
    ({"name": "reviews___get_review", "input": '{"review_id": "REVIEW_A1"}'},
     False),
    ({"name": "reviews___add_finding", "input": '{"review_id": "REVIEW-A1"}'},
     False),
    ({"name": "reviews___get_review", "input": "{bad"}, False),
    ({}, False),
])
def test_reads_review_a1(call, ok):
    assert ac.reads_review_a1(call) is ok


def test_a_wrong_review_id_does_not_prove_cross_tenant():
    """tenant_gate denies an unknown id as [cross-tenant] too, so a call on
    the wrong id must not count as proof."""
    s, w = stack()
    s.provision()

    def invoke(sid, prompt):
        r = _result("deny", "[cross-tenant] x")
        r.tool_calls[0]["input"] = '{"review_id": "review-a1"}'
        return r

    s.invoke = invoke
    out = ac.run_hook_scenarios(s, AuditTrail(path=None))
    assert list(out.values()) == [None, None, None]


def test_sigterm_still_tears_down(monkeypatch, tmp_path):
    """main() turns SIGTERM (timeout, kill, a cancelled CI job) into an exit
    that runs the teardown in run()'s finally block."""
    import os
    import signal

    w = World()
    torn = []

    class Stack(ac.AgentCoreStack):
        def __init__(self, log=None):
            super().__init__(session=FakeSession(w), run_id="r1", log=log,
                             sleep=lambda _: None, poll_seconds=0,
                             role_propagation_seconds=0)

        def teardown(self):
            torn.append(True)
            return super().teardown()

    def hang(stack, audit):
        os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError("SIGTERM was not raised")

    monkeypatch.setattr(ac, "AgentCoreStack", Stack)
    monkeypatch.setattr(ac, "run_cedar_scenarios", hang)
    monkeypatch.setenv("AGENTCORE_LOG", str(tmp_path / "a.log"))
    monkeypatch.setenv("AGENTCORE_CLEANUP_LOG", str(tmp_path / "c.log"))
    old = signal.getsignal(signal.SIGTERM)
    try:
        with pytest.raises(SystemExit):
            ac.main([])
    finally:
        signal.signal(signal.SIGTERM, old)
    assert torn and not (w.functions or w.roles or w.harnesses)


def test_teardown_waits_out_the_runtimes_late_log_export():
    """The runtime exports logs about a minute late, so its log group can
    come back after it was deleted; teardown deletes it again."""
    s, w = stack()
    s.provision()
    runtime = next(g for g in w.log_groups if "runtimes" in g)
    w.late_export[runtime] = True
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        w.log_groups.extend(w.pending)      # the late export lands
        w.pending.clear()

    s.sleep = sleep
    assert s.teardown() is True
    assert w.log_groups == []
    assert w.calls.count("delete_log_group") == 4   # 3 groups + 1 again
    assert waits.count(s.log_settle_seconds) == 2   # until a quiet period


def test_no_settle_wait_without_a_harness():
    w = World()
    w.fail["create_gateway"] = FakeClientError("ValidationException")
    s, w = stack(w)
    waits = []
    s.sleep = waits.append
    s.run()
    assert s.log_settle_seconds not in waits
