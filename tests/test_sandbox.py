"""Tests for rail 6, the stall: the MicroVM sandbox (offline, NO AWS calls).

A fake boto3 session stands in for lambda-microvms, IAM, S3 and CloudWatch
Logs, so these tests prove the lifecycle, the fail-closed paths, the teardown
and the cleanup check without credentials. The in-microVM app is also started
locally on 127.0.0.1 to prove it really executes code over HTTP.
"""

import io
import json
import threading
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

import pytest

from harness import sandbox as sb


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #
class FakeClientError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(f"{code}: {msg}")
        self.response = {"Error": {"Code": code, "Message": msg}}


class FakeWorld:
    """Shared fake account state across the fake clients."""

    def __init__(self):
        self.buckets = {}
        self.roles = {}
        self.images = {}
        self.microvms = {}
        self.log_groups = []
        self.calls = []
        self.fail = {}            # op name -> exception to raise
        self.build_states = ["IN_PROGRESS", "SUCCESSFUL"]

    def hit(self, op):
        self.calls.append(op)
        if op in self.fail:
            raise self.fail[op]


class FakeS3:
    def __init__(self, w):
        self.w = w

    def create_bucket(self, Bucket, **kw):
        self.w.hit("create_bucket")
        self.w.buckets[Bucket] = {}

    def put_object(self, Bucket, Key, Body, **kw):
        self.w.hit("put_object")
        self.w.buckets[Bucket][Key] = Body

    def delete_object(self, Bucket, Key):
        self.w.hit("delete_object")
        self.w.buckets[Bucket].pop(Key, None)

    def delete_bucket(self, Bucket):
        self.w.hit("delete_bucket")
        del self.w.buckets[Bucket]

    def list_buckets(self):
        return {"Buckets": [{"Name": b} for b in self.w.buckets]}


class FakeIAM:
    def __init__(self, w):
        self.w = w

    def create_role(self, RoleName, Path, AssumeRolePolicyDocument, **kw):
        self.w.hit("create_role")
        trust = json.loads(AssumeRolePolicyDocument)
        self.w.roles[RoleName] = {"trust": trust, "policies": {}}
        return {"Role": {"Arn": f"arn:aws:iam::123456789012:role{Path}"
                                f"{RoleName}"}}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.w.roles[RoleName]["policies"][PolicyName] = PolicyDocument

    def list_role_policies(self, RoleName):
        return {"PolicyNames": list(self.w.roles[RoleName]["policies"])}

    def delete_role_policy(self, RoleName, PolicyName):
        del self.w.roles[RoleName]["policies"][PolicyName]

    def delete_role(self, RoleName):
        self.w.hit("delete_role")
        if self.w.roles[RoleName]["policies"]:
            raise FakeClientError("DeleteConflict", "detach policies first")
        del self.w.roles[RoleName]

    def list_roles(self, **kw):
        names = list(self.w.roles) + ["unrelated-role"]
        return {"Roles": [{"RoleName": n} for n in names],
                "IsTruncated": False}


class FakeMicroVMs:
    def __init__(self, w):
        self.w = w

    def create_microvm_image(self, baseImageArn, buildRoleArn, codeArtifact,
                             name, **kw):
        self.w.hit("create_microvm_image")
        arn = f"arn:aws:lambda:us-east-1:123456789012:microvm-image:{name}"
        self.w.images[arn] = {"name": name, "state": "CREATING",
                              "imageArn": arn, "base": baseImageArn,
                              "uri": codeArtifact["uri"]}
        return {"imageArn": arn, "imageVersion": "1.0", "state": "CREATING"}

    def list_microvm_image_builds(self, imageIdentifier, imageVersion):
        return {"items": [{"buildId": "b-1", "buildState": "PENDING"}]}

    def get_microvm_image_build(self, imageIdentifier, imageVersion, buildId):
        self.w.hit("get_microvm_image_build")
        state = self.w.build_states.pop(0) if len(self.w.build_states) > 1 \
            else self.w.build_states[0]
        return {"buildState": state, "stateReason": "fake reason"}

    def run_microvm(self, imageIdentifier, **kw):
        self.w.hit("run_microvm")
        vm = "microvm-fake-1"
        name = imageIdentifier.rsplit(":", 1)[-1]
        self.w.log_groups.append(f"/aws/lambda-microvms/{name}")
        self.w.microvms[vm] = {"microvmId": vm, "state": "PENDING",
                               "imageArn": imageIdentifier}
        return {"microvmId": vm, "endpoint": "fake.lambda-microvm.on.aws",
                "state": "PENDING"}

    def get_microvm(self, microvmIdentifier):
        vm = self.w.microvms[microvmIdentifier]
        if vm["state"] == "PENDING":
            vm["state"] = "RUNNING"
        return {"state": vm["state"]}

    def create_microvm_auth_token(self, microvmIdentifier, expirationInMinutes,
                                  allowedPorts):
        self.w.hit("create_microvm_auth_token")
        return {"authToken": {"X-aws-proxy-auth": "tok"}}

    def terminate_microvm(self, microvmIdentifier):
        self.w.hit("terminate_microvm")
        self.w.microvms[microvmIdentifier]["state"] = "TERMINATED"

    def delete_microvm_image(self, imageIdentifier):
        self.w.hit("delete_microvm_image")
        self.w.images.pop(imageIdentifier, None)

    def list_microvm_images(self, **kw):
        items = list(self.w.images.values())
        items.append({"name": "someone-elses-image", "state": "CREATED"})
        return {"items": items}

    def list_microvms(self, **kw):
        return {"items": list(self.w.microvms.values())}


class FakeLogs:
    def __init__(self, w):
        self.w = w

    def describe_log_groups(self, logGroupNamePattern):
        return {"logGroups": [{"logGroupName": g} for g in self.w.log_groups
                              if logGroupNamePattern in g]}

    def delete_log_group(self, logGroupName):
        self.w.hit("delete_log_group")
        if logGroupName not in self.w.log_groups:
            raise FakeClientError("ResourceNotFoundException", logGroupName)
        self.w.log_groups.remove(logGroupName)


class FakeSTS:
    def __init__(self, w):
        self.w = w

    def get_caller_identity(self):
        self.w.hit("get_caller_identity")
        return {"Account": "123456789012"}


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, w):
        self.w = w

    def client(self, name):
        return {"s3": FakeS3, "iam": FakeIAM, "lambda-microvms": FakeMicroVMs,
                "logs": FakeLogs, "sts": FakeSTS}[name](self.w)


def _ok_post(url, data, headers, timeout):
    body = json.loads(data)
    assert headers["X-aws-proxy-auth"] == "tok"
    assert headers["X-aws-proxy-port"] == str(sb.APP_PORT)
    assert url.endswith(sb.EXEC_PATH)
    assert body["code"]
    return 200, json.dumps({"returncode": 0, "stdout": "45\n", "stderr": ""})


def _box(world, http_post=_ok_post, **kw):
    log = sb.SandboxLog(echo=False, profile="example-profile")
    return sb.MicroVMSandbox(session=FakeSession(world), log=log,
                             run_id="t1", http_post=http_post,
                             sleep=lambda s: None, **kw)


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #
def test_run_executes_in_microvm_and_tears_everything_down():
    w = FakeWorld()
    box = _box(w)
    r = box.run("print(sum(range(10)))")
    assert r.allowed and r.passed
    assert r.stdout.strip() == "45"
    assert r.microvm_id == "microvm-fake-1"
    # everything created was deleted, and the cleanup check proved it
    assert box.clean is True
    assert w.buckets == {} and w.roles == {} and w.images == {}
    assert w.log_groups == []   # the service-created log group is deleted
    assert w.microvms["microvm-fake-1"]["state"] == "TERMINATED"
    order = [c for c in w.calls if c in (
        "create_bucket", "create_role", "create_microvm_image", "run_microvm",
        "create_microvm_auth_token", "terminate_microvm",
        "delete_microvm_image", "delete_bucket", "delete_role")]
    assert order == [
        "create_bucket", "create_role", "create_role",
        "create_microvm_image", "run_microvm", "create_microvm_auth_token",
        "terminate_microvm", "delete_microvm_image", "delete_bucket",
        "delete_role", "delete_role"]


def test_every_resource_name_has_the_prefix():
    box = _box(FakeWorld())
    for name in (box.name, box.bucket, box.build_role, box.exec_role):
        assert name.startswith("harness-sandbox-")


def test_roles_trust_lambda_and_image_uses_managed_base():
    w = FakeWorld()
    box = _box(w)
    box.account_id = "123456789012"
    box._upload_zip()
    box._create_roles()
    box._build_image()
    for role in w.roles.values():
        principal = role["trust"]["Statement"][0]["Principal"]["Service"]
        assert principal == "lambda.amazonaws.com"
    (img,) = w.images.values()
    assert img["base"] == "arn:aws:lambda:us-east-1:aws:microvm-image:al2023-1"
    assert img["uri"] == f"s3://{box.bucket}/{sb.ZIP_KEY}"
    box.teardown()


def test_nonzero_exit_is_allowed_but_not_passed():
    def post(url, data, headers, timeout):
        return 200, json.dumps({"returncode": 1, "stdout": "",
                                "stderr": "AssertionError"})
    r = _box(FakeWorld(), http_post=post).run("assert False")
    assert r.allowed is True
    assert r.passed is False
    assert r.returncode == 1


# --------------------------------------------------------------------------- #
# Least privilege                                                             #
# --------------------------------------------------------------------------- #
def _provisioned_roles():
    w = FakeWorld()
    box = _box(w)
    box.account_id = "123456789012"
    box._upload_zip()
    box._create_roles()
    return w, box


def test_trust_policies_pin_source_account():
    w, box = _provisioned_roles()
    assert set(w.roles) == {box.build_role, box.exec_role}
    for role in w.roles.values():
        (stmt,) = role["trust"]["Statement"]
        assert stmt["Principal"] == {"Service": "lambda.amazonaws.com"}
        assert stmt["Action"] == "sts:AssumeRole"
        assert stmt["Condition"] == {
            "StringEquals": {"aws:SourceAccount": "123456789012"}}


def test_exec_role_has_no_permissions():
    w, box = _provisioned_roles()
    assert w.roles[box.exec_role]["policies"] == {}


def test_build_role_is_scoped_to_this_run():
    w, box = _provisioned_roles()
    (doc,) = w.roles[box.build_role]["policies"].values()
    stmts = json.loads(doc)["Statement"]
    by_action = {a: st for st in stmts for a in st["Action"]}
    group = ("arn:aws:logs:us-east-1:123456789012:log-group:"
             "/aws/lambda-microvms/harness-sandbox-t1")
    for a in ("logs:CreateLogGroup", "logs:CreateLogStream",
              "logs:PutLogEvents"):
        assert by_action[a]["Resource"] == [group, group + ":*"]
    assert by_action["s3:GetObject"]["Resource"] == [
        f"arn:aws:s3:::{box.bucket}/{sb.ZIP_KEY}"]
    # only actions without resource-level support may use "*"
    star = {a for st in stmts if st["Resource"] == "*" for a in st["Action"]}
    assert star == {"ecr-public:GetAuthorizationToken",
                    "sts:GetServiceBearerToken"}


def test_teardown_deletes_only_this_runs_log_group():
    w = FakeWorld()
    w.log_groups = ["/aws/lambda-microvms/harness-sandbox-t1-other",
                    "/aws/lambda-microvms/unrelated"]
    box = _box(w)
    r = box.run("print(1)")
    assert r.allowed
    assert w.log_groups == ["/aws/lambda-microvms/harness-sandbox-t1-other",
                            "/aws/lambda-microvms/unrelated"]
    assert any("deleted log group /aws/lambda-microvms/harness-sandbox-t1"
               in ln for ln in box.log.lines)


# --------------------------------------------------------------------------- #
# Fail-closed                                                                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code", ["", "   ", "import os\nos.system('rm -rf /')"])
def test_precheck_denies_without_any_aws_call(code):
    w = FakeWorld()
    r = _box(w).run(code)
    assert r.allowed is False
    assert r.reason.startswith("DENY (fail-closed)")
    assert w.calls == []


def test_image_build_failure_denies_and_never_runs_code():
    w = FakeWorld()
    w.build_states = ["FAILED"]
    box = _box(w)
    r = box.run("print(1)")
    assert r.allowed is False
    assert "image build FAILED" in r.reason
    assert "run_microvm" not in w.calls
    assert "create_microvm_auth_token" not in w.calls
    assert box.clean is True
    assert w.buckets == {} and w.roles == {} and w.images == {}


def test_api_error_mid_provision_denies_and_cleans_partial_state():
    w = FakeWorld()
    w.fail["create_microvm_image"] = FakeClientError("AccessDeniedException")
    box = _box(w)
    r = box.run("print(1)")
    assert r.allowed is False
    assert "AccessDeniedException" in r.reason
    assert box.clean is True
    assert w.buckets == {} and w.roles == {}


def test_unreachable_endpoint_denies_and_tears_down():
    calls = {"n": 0}

    def down(url, data, headers, timeout):
        calls["n"] += 1
        raise OSError("connection refused")

    w = FakeWorld()
    box = _box(w, http_post=down, exec_attempts=3)
    r = box.run("print(1)")
    assert r.allowed is False
    assert calls["n"] == 3
    assert w.microvms["microvm-fake-1"]["state"] == "TERMINATED"
    assert box.clean is True


def test_teardown_error_is_logged_not_raised():
    w = FakeWorld()
    w.fail["terminate_microvm"] = FakeClientError("ThrottlingException")
    box = _box(w)
    r = box.run("print(1)")
    assert r.allowed is True          # the code ran
    assert box.clean is False         # but the microVM is still listed
    assert any("ThrottlingException" in ln for ln in box.log.lines)


# --------------------------------------------------------------------------- #
# Cleanup check                                                               #
# --------------------------------------------------------------------------- #
def test_cleanup_check_counts_only_prefixed_resources():
    w = FakeWorld()
    log = sb.SandboxLog(echo=False)
    assert sb.cleanup_check(FakeSession(w), log=log)["total"] == 0
    w.roles["harness-sandbox-build-x"] = {"policies": {}}
    w.buckets["harness-sandbox-x"] = {}
    w.buckets["other-bucket"] = {}
    w.log_groups = ["/aws/microvms/harness-sandbox-x", "/aws/other"]
    w.microvms["vm-1"] = {
        "microvmId": "vm-1", "state": "RUNNING",
        "imageArn": "arn:aws:lambda:us-east-1:1:microvm-image:harness-sandbox-x"}
    found = sb.cleanup_check(FakeSession(w), log=log)
    assert found["iam_roles"] == ["harness-sandbox-build-x"]
    assert found["s3_buckets"] == ["harness-sandbox-x"]
    assert found["log_groups"] == ["/aws/microvms/harness-sandbox-x"]
    assert found["microvms"] == [("vm-1", "RUNNING")]
    assert found["total"] == 4


# --------------------------------------------------------------------------- #
# Redaction                                                                   #
# --------------------------------------------------------------------------- #
def test_log_redacts_account_ids_and_profile(tmp_path):
    path = tmp_path / "s.log"
    log = sb.SandboxLog(path=str(path), profile="my-secret-profile",
                        echo=False, fresh=True)
    log("arn:aws:iam::123456789012:role/x profile=my-secret-profile")
    text = path.read_text()
    assert "123456789012" not in text
    assert "my-secret-profile" not in text
    assert "<account-id>" in text and "<profile>" in text


# Fake, secret-SHAPED fixtures. They are built by concatenation so that secret
# scanners (and GitHub push protection) do not flag this test file or its logs.
_FAKE_AKIA = "AKIA" + "ABCDEFGHIJKLMNOP"
_FAKE_ASIA = "ASIA" + "QRSTUVWXYZ234567"
_PEM = "PRIVATE" + " KEY-----"


@pytest.mark.parametrize("secret", [
    _FAKE_AKIA,
    _FAKE_ASIA,
    "aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    'AWS_SESSION_TOKEN: "IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE"',
    "-----BEGIN RSA " + _PEM + "\nMIIEabc\n-----END RSA " + _PEM,
    "-----BEGIN OPENSSH " + _PEM + "\nb3BlbnNzaC1rZXk",  # truncated
], ids=["akia", "asia", "secret-kv", "session-token", "rsa-pem", "openssh-pem"])
def test_redact_masks_secret_shaped_strings(secret):
    out = sb.redact(f"stdout: {secret} end")
    assert "<secret>" in out
    for frag in ("ABCDEFGHIJKLMNOP", "QRSTUVWXYZ234567", "wJalrXUtnFEMI",
                 "IQoJb3JpZ2lu", "MIIEabc", "b3BlbnNzaC1rZXk"):
        assert frag not in out
    assert out.endswith("end") or "BEGIN" in secret


def test_redact_masks_any_profile_assignment():
    out = sb.redact("aws s3 ls --profile team-prod; AWS_PROFILE=other-acct")
    assert "team-prod" not in out and "other-acct" not in out
    assert out.count("<profile>") == 2


def test_redact_leaves_other_numbers_alone():
    assert sb.redact("took 1234 ms, id 12345678901") == \
        "took 1234 ms, id 12345678901"
    assert sb.redact("x 1234567890123 y") == "x 1234567890123 y"


# --------------------------------------------------------------------------- #
# What the log may record about code and output                              #
# --------------------------------------------------------------------------- #
SECRET_CODE = ("KEY = '" + _FAKE_AKIA + "'\n"
               "print('confidential-marker', 123456789012)\n")


def _secret_post(url, data, headers, timeout):
    return 200, json.dumps({"returncode": 0, "stdout":
                            "confidential-marker 123456789012\n",
                            "stderr": "warn: confidential-marker"})


def test_log_never_contains_code_or_raw_output(monkeypatch):
    monkeypatch.delenv(sb.DEBUG_ENV, raising=False)
    box = _box(FakeWorld(), http_post=_secret_post)
    r = box.run(SECRET_CODE)
    assert r.allowed and r.stdout.startswith("confidential-marker")
    text = "\n".join(box.log.lines)
    assert "confidential-marker" not in text
    assert "AKIA" not in text and "print(" not in text
    assert sb.code_fingerprint(SECRET_CODE) in text
    assert f"bytes={len(SECRET_CODE.encode())}" in text
    assert "stdout_len=33" in text and "stdout_preview" not in text


def test_debug_flag_adds_a_short_redacted_preview(monkeypatch):
    monkeypatch.setenv(sb.DEBUG_ENV, "1")
    box = _box(FakeWorld(), http_post=_secret_post)
    box.run(SECRET_CODE)
    text = "\n".join(box.log.lines)
    assert "stdout_preview='confidential-marker <account-id>'" in text
    assert "123456789012" not in text
    assert "print(" not in text          # code text is never logged
    s = sb.output_summary("stdout", "x" * 500)
    assert len(s) < 80 and s.endswith("...'")


def test_debug_flag_must_be_exactly_one(monkeypatch):
    monkeypatch.setenv(sb.DEBUG_ENV, "true")
    assert sb.debug_enabled() is False
    assert "preview" not in sb.output_summary("stdout", "hello")


# --------------------------------------------------------------------------- #
# The in-microVM app                                                          #
# --------------------------------------------------------------------------- #
def test_zip_holds_dockerfile_and_app():
    with zipfile.ZipFile(io.BytesIO(sb.build_zip_bytes())) as zf:
        assert set(zf.namelist()) == {"Dockerfile", "app.py"}
    assert "public.ecr.aws/lambda/microvms:al2023-minimal" in sb.DOCKERFILE
    assert str(sb.APP_PORT) in sb.DOCKERFILE


def test_auth_headers_route_to_the_app_port():
    h = sb.auth_headers({"X-aws-proxy-auth": "tok"})
    assert h["X-aws-proxy-auth"] == "tok"
    assert h["X-aws-proxy-port"] == str(sb.APP_PORT)
    assert sb.auth_headers({"token": "abc"})["X-aws-proxy-auth"] == "abc"
    assert sb.endpoint_url("h.example", "/exec") == "https://h.example/exec"


def test_app_executes_code_over_http_locally():
    ns = {"__name__": "sandbox_app"}
    exec(compile(sb.APP_PY, "app.py", "exec"), ns)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ns["Handler"])
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/exec"
        code, raw = sb._urllib_post(
            url, json.dumps({"code": "print(sum(range(10)))"}).encode(),
            {"Content-Type": "application/json"}, 30)
        assert code == 200
        assert json.loads(raw) == {"returncode": 0, "stdout": "45\n",
                                   "stderr": ""}
        code, raw = sb._urllib_post(
            url, json.dumps({"code": "raise SystemExit(3)"}).encode(),
            {"Content-Type": "application/json"}, 30)
        assert json.loads(raw)["returncode"] == 3
        ready = urllib.request.urlopen(f"http://127.0.0.1:{port}/ready")
        assert ready.status == 200
    finally:
        server.shutdown()
