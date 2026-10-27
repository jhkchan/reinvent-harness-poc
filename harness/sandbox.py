"""
sandbox.py -- Rail 6, the stall: run AI-written code in an isolated runtime.

Regulator question: "Where does AI-written code run?"

Code an LLM just wrote is untrusted by definition. A shared-kernel container
on the agent's host is not a safe boundary for it. This rail runs each
snippet in its own AWS Lambda MicroVM (one Firecracker microVM, no shared
kernel) and tears everything down afterwards, using the boto3
``lambda-microvms`` client (botocore >= 1.43.36).

One ``MicroVMSandbox.run(code)`` call does the whole lifecycle:

  precheck   -> deny empty or oversized code, and code the rail-1 blocklist
                denies, before anything is created
  provision  -> zip {Dockerfile, app.py} to a temporary S3 bucket, create a
                build role and an execution role (trust: lambda.amazonaws.com,
                only when aws:SourceAccount is this account),
                CreateMicrovmImage (Lambda builds the Dockerfile server-side
                and takes a snapshot), wait for build state SUCCESSFUL, then
                RunMicrovm and wait for RUNNING
  execute    -> CreateMicrovmAuthToken, POST the code to the microVM's /exec
                endpoint with the token map as headers (X-aws-proxy-auth) and
                X-aws-proxy-port, return {returncode, stdout, stderr}
  teardown   -> always (in ``finally``): TerminateMicrovm, DeleteMicrovmImage,
                delete the S3 zip and bucket, delete both IAM roles, delete
                the CloudWatch log group the service creates
                (/aws/lambda-microvms/<image name>)

Fail-closed: any error in provision or execute returns a DENY result, so a
caller never treats a half-built or unreachable sandbox as "the code ran".
Every resource name starts with ``harness-sandbox-``, so ``cleanup_check()``
can list anything left behind with that prefix (it must report 0).

Least privilege. The code inside the microVM needs no AWS access, so the
execution role has NO permission policy at all. The build role can read only
this run's code zip, fetch the public ECR pull token, and write only to this
run's log group (/aws/lambda-microvms/<name>, account and region computed at
runtime). Both trust policies require aws:SourceAccount = this account.

Logging. Every log line is redacted: 12-digit numbers (AWS account ids) ->
``<account-id>``, the AWS profile name -> ``<profile>``, access key ids
(AKIA..., ASIA...), ``aws_secret_access_key=...`` style secrets and PEM
private-key blocks -> ``<secret>``. The submitted code and its raw output are
never logged: the log records the code's sha256 and length, and the output's
length. Set HARNESS_SANDBOX_DEBUG=1 to add a short, redacted output preview.

AWS covers: AWS Lambda MicroVMs (one Firecracker microVM per user or session,
snapshot start, suspend and resume) and AgentCore Code Interpreter. You still
own the session-to-user mapping, egress control, what data goes in, and the
cleanup. See the README rail table.

Live run (creates and deletes real resources; tiny cost):
    make sandbox-live      # or: python -m harness.sandbox
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .permission_gate import Decision, PermissionGate

PREFIX = "harness-sandbox"
ROLE_PATH = f"/{PREFIX}/"
APP_PORT = 8080
EXEC_PATH = "/exec"
AUTH_HEADER = "X-aws-proxy-auth"
PORT_HEADER = "X-aws-proxy-port"
TRUST_PRINCIPAL = "lambda.amazonaws.com"
MAX_CODE_BYTES = 64 * 1024
ZIP_KEY = "sandbox/code.zip"
BUILD_OK = ("SUCCESSFUL", "SUCCEEDED")
BUILD_BAD = ("FAILED", "CANCELLED", "CANCELED")
LOG_GROUP_ROOT = "/aws/lambda-microvms"   # the service logs to <root>/<name>
DEBUG_ENV = "HARNESS_SANDBOX_DEBUG"       # "1" adds redacted output previews
PREVIEW_CHARS = 40


def base_image_arn(region: str) -> str:
    """The AWS-managed Amazon Linux 2023 MicroVM base image."""
    return f"arn:aws:lambda:{region}:aws:microvm-image:al2023-1"


# --------------------------------------------------------------------------- #
# The in-microVM app: stdlib only, so the image build needs no pip install.  #
# --------------------------------------------------------------------------- #
DOCKERFILE = f"""\
FROM public.ecr.aws/lambda/microvms:al2023-minimal
RUN dnf install -y python3 && dnf clean all
WORKDIR /app
COPY app.py .
EXPOSE {APP_PORT}
CMD ["python3", "/app/app.py"]
"""

APP_PY = r'''"""Run one untrusted Python snippet per request, inside the microVM.

POST /exec {"code": "<python>", "timeout": 10}
    -> {"returncode": int, "stdout": str, "stderr": str}
Every other path (including MicroVM lifecycle hooks) answers 200.
"""
import json
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8080


def execute(code, timeout=10):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
    try:
        p = subprocess.run([sys.executable, f.name], capture_output=True,
                           text=True, timeout=timeout)
        return {"returncode": p.returncode, "stdout": p.stdout[-4000:],
                "stderr": p.stderr[-4000:]}
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "",
                "stderr": "TIMEOUT after %ss" % timeout}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, {"ok": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        if self.path != "/exec":
            self._send(200, {"ok": True})
            return
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self._send(400, {"error": "body must be JSON"})
            return
        out = execute(body.get("code", ""), int(body.get("timeout", 10)))
        self._send(200, out)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
'''


def build_zip_bytes() -> bytes:
    """Zip {Dockerfile, app.py} in memory (the MicroVM code artifact)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", DOCKERFILE)
        zf.writestr("app.py", APP_PY)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Redacting log                                                               #
# --------------------------------------------------------------------------- #
_ACCOUNT_RX = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PEM_RX = re.compile(
    r"-----BEGIN [A-Z0-9 ]*KEY-----.*?(?:-----END [A-Z0-9 ]*KEY-----|$)",
    re.DOTALL)
_KEY_ID_RX = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"
                        r"(?![A-Z0-9])")
_SECRET_KV_RX = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_session_token|secret_?access_?key"
    r"|session_?token)([\"']?\s*[=:]\s*[\"']?)[A-Za-z0-9/+=]{8,}")
_PROFILE_KV_RX = re.compile(r"(?i)(--profile\s+|\baws_profile\s*=\s*"
                            r"|\bprofile\s*=\s*)[\"']?[\w.@-]+")
# An STS role-session ARN names the role and the session, which is often a
# person's email: arn:aws:sts::<id>:assumed-role/<role>/<session>.
_ASSUMED_ROLE_RX = re.compile(r"(assumed-role/)[^\s\"',;)]+")
_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def redact(text: str, profile: Optional[str] = None) -> str:
    """Mask secrets, profile names and account ids in one log line.

    PEM private-key blocks, access key ids (AKIA/ASIA...) and
    ``aws_secret_access_key=...``-style values become ``<secret>``; any
    ``profile=``/``--profile`` value and the named profile become
    ``<profile>``; an ``assumed-role/<role>/<session>`` tail becomes
    ``assumed-role/<redacted>``; email addresses become ``<email>``;
    12-digit numbers become ``<account-id>``.
    """
    out = _PEM_RX.sub("<secret>", str(text))
    out = _ASSUMED_ROLE_RX.sub(lambda m: m.group(1) + "<redacted>", out)
    out = _EMAIL_RX.sub("<email>", out)
    out = _KEY_ID_RX.sub("<secret>", out)
    out = _SECRET_KV_RX.sub(lambda m: m.group(1) + "=<secret>", out)
    out = _PROFILE_KV_RX.sub(lambda m: m.group(1) + "<profile>", out)
    if profile:
        out = re.sub(re.escape(profile), "<profile>", out,
                     flags=re.IGNORECASE)
    return _ACCOUNT_RX.sub("<account-id>", out)


def debug_enabled() -> bool:
    """True only when HARNESS_SANDBOX_DEBUG=1 is set explicitly."""
    return os.environ.get(DEBUG_ENV, "") == "1"


def code_fingerprint(code: str) -> str:
    """What the log records about submitted code: sha256 + length only."""
    data = code.encode("utf-8")
    return f"sha256={hashlib.sha256(data).hexdigest()} bytes={len(data)}"


def output_summary(label: str, text: str) -> str:
    """``<label>_len=N``; plus a short preview only in debug mode."""
    text = text or ""
    out = f"{label}_len={len(text)}"
    if debug_enabled():
        flat = text.strip().replace("\n", " | ")
        cut = flat[:PREVIEW_CHARS] + ("..." if len(flat) > PREVIEW_CHARS
                                      else "")
        out += f" {label}_preview={cut!r}"
    return out


class SandboxLog:
    """Timestamped log line sink that redacts before anything is written."""

    def __init__(self, path: Optional[str] = None,
                 profile: Optional[str] = None, echo: bool = True,
                 fresh: bool = False) -> None:
        self.path = path
        self.profile = profile if profile is not None else (
            os.environ.get("AWS_PROFILE") or None)
        self.echo = echo
        self.lines: List[str] = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            if fresh:
                open(path, "w", encoding="utf-8").close()

    def __call__(self, msg: str = "") -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = redact(f"[{ts}] {msg}", self.profile)
        self.lines.append(line)
        if self.echo:
            print(line)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


def _err_code(e: Exception) -> str:
    resp = getattr(e, "response", None) or {}
    return resp.get("Error", {}).get("Code", type(e).__name__)


# --------------------------------------------------------------------------- #
# Result                                                                      #
# --------------------------------------------------------------------------- #
@dataclass
class SandboxResult:
    allowed: bool                 # did the code run in a MicroVM?
    returncode: Optional[int]
    stdout: str
    stderr: str
    reason: str
    microvm_id: str = ""

    @property
    def passed(self) -> bool:
        return self.allowed and self.returncode == 0

    @classmethod
    def deny(cls, reason: str) -> "SandboxResult":
        return cls(False, None, "", "", f"DENY (fail-closed): {reason}")

    @classmethod
    def ran(cls, out: Dict[str, Any], microvm_id: str) -> "SandboxResult":
        return cls(True, out.get("returncode"), out.get("stdout", ""),
                   out.get("stderr", ""), "ran in an isolated MicroVM",
                   microvm_id)


# --------------------------------------------------------------------------- #
# HTTP                                                                        #
# --------------------------------------------------------------------------- #
HttpPost = Callable[[str, bytes, Dict[str, str], float], Tuple[int, str]]


def _urllib_post(url: str, data: bytes, headers: Dict[str, str],
                 timeout: float) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=data, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def endpoint_url(endpoint: str, path: str) -> str:
    """RunMicrovm returns a bare host; requests are plain HTTPS."""
    ep = endpoint.strip()
    if not ep.startswith(("http://", "https://")):
        ep = "https://" + ep
    return ep.rstrip("/") + path


def auth_headers(token: Dict[str, str]) -> Dict[str, str]:
    """The auth-token map's keys ARE the header names (X-aws-proxy-auth)."""
    headers = dict(token)
    if AUTH_HEADER not in token and len(token) == 1:
        headers[AUTH_HEADER] = next(iter(token.values()))
    headers[PORT_HEADER] = str(APP_PORT)
    headers["Content-Type"] = "application/json"
    return headers


# --------------------------------------------------------------------------- #
# IAM policy documents                                                        #
# --------------------------------------------------------------------------- #
def log_group_name(name: str) -> str:
    return f"{LOG_GROUP_ROOT}/{name}"


def log_group_arns(region: str, account: str, name: str) -> List[str]:
    """The one log group this run may write to (the group and its streams)."""
    arn = f"arn:aws:logs:{region}:{account}:log-group:{log_group_name(name)}"
    return [arn, arn + ":*"]


def _trust_policy(account: str) -> str:
    """lambda.amazonaws.com may assume the role only for THIS account."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": TRUST_PRINCIPAL},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account}},
        }],
    })


def _build_policy(bucket: str, region: str, account: str, name: str) -> str:
    """Read this run's zip, get the public ECR pull token, log to one group.

    ecr-public:GetAuthorizationToken and sts:GetServiceBearerToken do not
    support resource-level permissions, so they need Resource "*".
    """
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["s3:GetObject", "s3:GetObjectVersion"],
             "Resource": [f"arn:aws:s3:::{bucket}/{ZIP_KEY}"]},
            {"Effect": "Allow",
             "Action": ["ecr-public:GetAuthorizationToken",
                        "sts:GetServiceBearerToken"],
             "Resource": "*"},
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                        "logs:PutLogEvents"],
             "Resource": log_group_arns(region, account, name)},
        ],
    })


def _exec_policy() -> Optional[str]:
    """The in-microVM code needs no AWS access: no permission policy."""
    return None


def _session(region: Optional[str]):
    import boto3  # imported lazily so offline tests never need credentials

    return boto3.Session(
        profile_name=os.environ.get("AWS_PROFILE") or None,
        region_name=region or os.environ.get("AWS_REGION") or "us-east-1",
    )


# --------------------------------------------------------------------------- #
# The sandbox                                                                 #
# --------------------------------------------------------------------------- #
class MicroVMSandbox:
    """Run one snippet of untrusted code in a fresh AWS Lambda MicroVM."""

    def __init__(
        self,
        session: Any = None,
        region: Optional[str] = None,
        log: Optional[SandboxLog] = None,
        run_id: Optional[str] = None,
        http_post: Optional[HttpPost] = None,
        sleep: Callable[[float], None] = time.sleep,
        gate: Optional[PermissionGate] = None,
        poll_seconds: float = 15.0,
        build_timeout_seconds: float = 900.0,
        ready_timeout_seconds: float = 180.0,
        max_duration_seconds: int = 900,
        role_propagation_seconds: float = 10.0,
        exec_attempts: int = 24,
    ) -> None:
        self.session = session or _session(region)
        self.region = (region or getattr(self.session, "region_name", None)
                       or "us-east-1")
        self.log = log or SandboxLog(echo=False)
        self.run_id = run_id or uuid.uuid4().hex[:10]
        self.name = f"{PREFIX}-{self.run_id}"
        self.bucket = self.name
        self.build_role = f"{PREFIX}-build-{self.run_id}"
        self.exec_role = f"{PREFIX}-exec-{self.run_id}"
        self.log_group = log_group_name(self.name)
        self.account_id: Optional[str] = None
        self.http_post = http_post or _urllib_post
        self.sleep = sleep
        self.gate = gate or PermissionGate(tool_config={"run_python": "allow"})
        self.poll_seconds = poll_seconds
        self.build_timeout_seconds = build_timeout_seconds
        self.ready_timeout_seconds = ready_timeout_seconds
        self.max_duration_seconds = max_duration_seconds
        self.role_propagation_seconds = role_propagation_seconds
        self.exec_attempts = exec_attempts
        # created-resource state (drives an exact teardown)
        self.bucket_created = False
        self.roles_created: List[str] = []
        self.role_arns: Dict[str, str] = {}
        self.image_arn: Optional[str] = None
        self.image_version: Optional[str] = None
        self.microvm_id: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.clean: Optional[bool] = None

    def _client(self, name: str):
        return self.session.client(name)

    # -- the rail ------------------------------------------------------------
    def run(self, code: str, timeout: int = 10) -> SandboxResult:
        """Run untrusted code once in a fresh MicroVM; always tear down."""
        why = self.precheck(code)
        if why:
            self.log(f"[deny] precheck: {why} (nothing was created)")
            return SandboxResult.deny(why)
        # [snippet:rail-6]
        try:
            self.provision()
            out = self.execute(code, timeout)
            return SandboxResult.ran(out, self.microvm_id or "")
        except Exception as e:  # fail closed: deny
            self.log(f"[deny] {type(e).__name__}: {e}")
            return SandboxResult.deny(f"{type(e).__name__}: {e}")
        finally:
            self.clean = self.teardown()
        # [/snippet]

    def precheck(self, code: str) -> Optional[str]:
        """Cheap local checks before any AWS resource exists."""
        if not code or not code.strip():
            return "empty code"
        if len(code.encode("utf-8")) > MAX_CODE_BYTES:
            return f"code larger than {MAX_CODE_BYTES} bytes"
        g = self.gate.before_tool("run_python", {"script": code})
        if g.decision is not Decision.ALLOW:
            return f"permission gate: {g.rule} {g.reason}"
        return None

    # -- provision -----------------------------------------------------------
    def provision(self) -> None:
        self.account_id = self._client("sts").get_caller_identity()["Account"]
        self._upload_zip()
        self._create_roles()
        self._build_image()
        self._run_microvm()

    def _upload_zip(self) -> None:
        s3 = self._client("s3")
        if self.region == "us-east-1":
            s3.create_bucket(Bucket=self.bucket)
        else:
            s3.create_bucket(Bucket=self.bucket, CreateBucketConfiguration={
                "LocationConstraint": self.region})
        self.bucket_created = True
        data = build_zip_bytes()
        s3.put_object(Bucket=self.bucket, Key=ZIP_KEY, Body=data,
                      ContentType="application/zip")
        self.log(f"[s3] created bucket {self.bucket}; uploaded "
                 f"{ZIP_KEY} ({len(data)} bytes: Dockerfile + app.py)")

    def _create_roles(self) -> None:
        iam = self._client("iam")
        account = self.account_id or ""
        build = _build_policy(self.bucket, self.region, account, self.name)
        for name, policy in ((self.build_role, build),
                             (self.exec_role, _exec_policy())):
            r = iam.create_role(
                RoleName=name, Path=ROLE_PATH,
                AssumeRolePolicyDocument=_trust_policy(account),
                Description="harness sandbox rail (temporary)",
            )
            self.roles_created.append(name)
            self.role_arns[name] = r["Role"]["Arn"]
            if policy:
                iam.put_role_policy(RoleName=name, PolicyName="inline",
                                    PolicyDocument=policy)
            perms = ("s3 zip read, ecr-public token, logs on "
                     f"{self.log_group} only" if policy else
                     "NO permission policy")
            self.log(f"[iam] created role {name} (trust {TRUST_PRINCIPAL}, "
                     f"aws:SourceAccount=<account-id>; {perms}) "
                     f"-> {r['Role']['Arn']}")
        self.log(f"[iam] waiting {self.role_propagation_seconds:.0f}s "
                 "for role propagation")
        self.sleep(self.role_propagation_seconds)

    def _build_image(self) -> None:
        mv = self._client("lambda-microvms")
        resp = mv.create_microvm_image(
            baseImageArn=base_image_arn(self.region),
            buildRoleArn=self.role_arns[self.build_role],
            codeArtifact={"uri": f"s3://{self.bucket}/{ZIP_KEY}"},
            name=self.name,
            description="harness sandbox rail (temporary)",
        )
        self.image_arn = resp["imageArn"]
        self.image_version = resp["imageVersion"]
        self.log(f"[image] CreateMicrovmImage {self.image_arn} "
                 f"version={self.image_version} state={resp.get('state')}")
        build_id = self._find_build_id(mv)
        deadline = time.monotonic() + self.build_timeout_seconds
        last = None
        while time.monotonic() < deadline:
            b = mv.get_microvm_image_build(
                imageIdentifier=self.image_arn,
                imageVersion=self.image_version, buildId=build_id)
            state = b["buildState"]
            if state != last:
                self.log(f"[build] buildId={build_id} state={state}")
                last = state
            if state in BUILD_OK:
                return
            if state in BUILD_BAD:
                raise RuntimeError(
                    f"image build {state}: {b.get('stateReason', '')}")
            self.sleep(self.poll_seconds)
        raise TimeoutError(f"image build not done after "
                           f"{self.build_timeout_seconds:.0f}s ({last})")

    def _find_build_id(self, mv) -> str:
        for _ in range(12):
            items = mv.list_microvm_image_builds(
                imageIdentifier=self.image_arn,
                imageVersion=self.image_version).get("items", [])
            if items:
                return items[0]["buildId"]
            self.sleep(5)
        raise RuntimeError("no buildId for the created image version")

    def _run_microvm(self) -> None:
        mv = self._client("lambda-microvms")
        resp = mv.run_microvm(
            imageIdentifier=self.image_arn,
            imageVersion=self.image_version,
            executionRoleArn=self.role_arns[self.exec_role],
            idlePolicy={"maxIdleDurationSeconds": 300,
                        "suspendedDurationSeconds": 60,
                        "autoResumeEnabled": False},
            maximumDurationInSeconds=self.max_duration_seconds,
        )
        self.microvm_id = resp["microvmId"]
        self.endpoint = resp["endpoint"]
        self.log(f"[microvm] RunMicrovm {self.microvm_id} "
                 f"state={resp.get('state')} "
                 f"maxDuration={self.max_duration_seconds}s")
        deadline = time.monotonic() + self.ready_timeout_seconds
        while time.monotonic() < deadline:
            state = mv.get_microvm(microvmIdentifier=self.microvm_id)["state"]
            if state == "RUNNING":
                self.log("[microvm] state=RUNNING")
                return
            if state in ("FAILED", "TERMINATED", "TERMINATING"):
                raise RuntimeError(f"microVM entered {state}")
            self.sleep(5)
        raise TimeoutError("microVM did not reach RUNNING")

    # -- execute -------------------------------------------------------------
    def execute(self, code: str, timeout: int = 10) -> Dict[str, Any]:
        mv = self._client("lambda-microvms")
        token = mv.create_microvm_auth_token(
            microvmIdentifier=self.microvm_id, expirationInMinutes=15,
            allowedPorts=[{"port": APP_PORT}])["authToken"]
        headers = auth_headers(token)
        url = endpoint_url(self.endpoint or "", EXEC_PATH)
        body = json.dumps({"code": code, "timeout": timeout}).encode("utf-8")
        self.log(f"[exec] POST {EXEC_PATH} on the microVM endpoint "
                 f"(headers: {AUTH_HEADER}, {PORT_HEADER}={APP_PORT})")
        self.log(f"[exec] code {code_fingerprint(code)} (text not logged)")
        last = ""
        for attempt in range(1, self.exec_attempts + 1):
            try:
                status, raw = self.http_post(url, body, headers, timeout + 30)
            except (urllib.error.URLError, OSError) as e:
                status, raw = 0, f"{type(e).__name__}: {e}"
            if status == 200:
                out = json.loads(raw)
                self.log(f"[exec] HTTP 200 after {attempt} attempt(s) -> "
                         f"returncode={out.get('returncode')} "
                         f"{output_summary('stdout', out.get('stdout', ''))} "
                         f"{output_summary('stderr', out.get('stderr', ''))}")
                return out
            last = f"status={status} {output_summary('body', raw)}"
            if status and status < 500 and status not in (403, 404, 408, 429):
                break  # a hard client error will not fix itself
            self.sleep(5)
        raise RuntimeError(f"microVM endpoint did not run the code ({last})")

    # -- teardown ------------------------------------------------------------
    def teardown(self) -> bool:
        """Delete everything this run created; True iff the prefix is clean.

        Never raises: each step logs its own error and the next step runs.
        """
        mv = self._client("lambda-microvms")
        if self.microvm_id:
            self._step("terminate microVM", self._terminate, mv)
        if self.image_arn:
            self._step("delete image", self._delete_image, mv)
        if self.bucket_created:
            self._step("delete bucket", self._delete_bucket)
        for name in list(self.roles_created):
            self._step(f"delete role {name}", self._delete_role, name)
        if self.image_arn:  # the build logs to /aws/lambda-microvms/<name>
            self._step("delete log group", self._delete_log_group)
        try:
            found = cleanup_check(self.session, log=self.log)
            return found["total"] == 0
        except Exception as e:  # cannot prove clean -> not clean
            self.log(f"[teardown] cleanup check failed: {_err_code(e)}")
            return False

    def _step(self, label: str, fn: Callable, *args) -> None:
        try:
            fn(*args)
        except Exception as e:
            self.log(f"[teardown] {label}: {_err_code(e)}: {e}")

    def _terminate(self, mv) -> None:
        mv.terminate_microvm(microvmIdentifier=self.microvm_id)
        self.log(f"[teardown] TerminateMicrovm {self.microvm_id}")
        for _ in range(30):
            try:
                state = mv.get_microvm(
                    microvmIdentifier=self.microvm_id)["state"]
            except Exception as e:
                if "NotFound" in _err_code(e):
                    return
                raise
            if state == "TERMINATED":
                self.log("[teardown] microVM state=TERMINATED")
                return
            self.sleep(4)

    def _delete_image(self, mv) -> None:
        for _ in range(20):
            try:
                mv.delete_microvm_image(imageIdentifier=self.image_arn)
                self.log(f"[teardown] DeleteMicrovmImage {self.image_arn}")
                break
            except Exception as e:
                code = _err_code(e)
                if "NotFound" in code:
                    return
                self.log(f"[teardown] delete image: {code} (retry)")
                self.sleep(6)
        for _ in range(60):  # wait until the image is gone, not just DELETING
            if not _list_images(mv, self.name):
                self.log("[teardown] image gone")
                return
            self.sleep(5)

    def _delete_bucket(self) -> None:
        s3 = self._client("s3")
        s3.delete_object(Bucket=self.bucket, Key=ZIP_KEY)
        s3.delete_bucket(Bucket=self.bucket)
        self.bucket_created = False
        self.log(f"[teardown] deleted s3://{self.bucket}/{ZIP_KEY} and bucket")

    def _delete_log_group(self) -> None:
        """Delete exactly this run's log group (never a prefix match)."""
        logs = self._client("logs")
        try:
            logs.delete_log_group(logGroupName=self.log_group)
        except Exception as e:
            if "ResourceNotFound" in _err_code(e):
                self.log(f"[teardown] log group {self.log_group} not present")
                return
            raise
        self.log(f"[teardown] deleted log group {self.log_group}")

    def _delete_role(self, name: str) -> None:
        iam = self._client("iam")
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
        self.roles_created.remove(name)
        self.log(f"[teardown] deleted IAM role {name}")


# --------------------------------------------------------------------------- #
# Cleanup check: anything with the harness-sandbox prefix still around?       #
# --------------------------------------------------------------------------- #
def _paged(call: Callable, key: str, **kw) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    token = None
    while True:
        args = dict(kw)
        if token:
            args["nextToken"] = token
        page = call(**args)
        items.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return items


def _list_images(mv, name_prefix: str) -> List[Dict[str, Any]]:
    items = _paged(mv.list_microvm_images, "items")
    return [i for i in items if str(i.get("name", "")).startswith(name_prefix)]


def cleanup_check(session: Any = None, region: Optional[str] = None,
                  log: Optional[SandboxLog] = None) -> Dict[str, Any]:
    """List every MicroVM, image, IAM role, S3 bucket and log group whose name
    starts with ``harness-sandbox``. ``total`` must be 0 after a run."""
    session = session or _session(region)
    log = log or SandboxLog(echo=False)
    mv = session.client("lambda-microvms")
    iam = session.client("iam")
    s3 = session.client("s3")
    logs = session.client("logs")

    vms = [m for m in _paged(mv.list_microvms, "items")
           if f":microvm-image:{PREFIX}" in str(m.get("imageArn", ""))
           and m.get("state") != "TERMINATED"]
    images = _list_images(mv, PREFIX)
    roles: List[str] = []
    marker = None
    while True:
        kw = {"Marker": marker} if marker else {}
        page = iam.list_roles(**kw)
        roles += [r["RoleName"] for r in page.get("Roles", [])
                  if r["RoleName"].startswith(PREFIX)]
        marker = page.get("Marker") if page.get("IsTruncated") else None
        if not marker:
            break
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])
               if b["Name"].startswith(PREFIX)]
    groups = [g["logGroupName"] for g in logs.describe_log_groups(
        logGroupNamePattern=PREFIX).get("logGroups", [])]

    found = {
        "microvms": [(m.get("microvmId"), m.get("state")) for m in vms],
        "images": [(i.get("name"), i.get("state")) for i in images],
        "iam_roles": roles,
        "s3_buckets": buckets,
        "log_groups": groups,
    }
    found["total"] = sum(len(v) for v in found.values())
    for k in ("microvms", "images", "iam_roles", "s3_buckets", "log_groups"):
        log(f"[cleanup-check] {k} with prefix '{PREFIX}': "
            f"{len(found[k])} {found[k] if found[k] else ''}".rstrip())
    log(f"[cleanup-check] TOTAL lingering '{PREFIX}' resources: "
        f"{found['total']}")
    return found


# --------------------------------------------------------------------------- #
# Live run: make sandbox-live                                                  #
# --------------------------------------------------------------------------- #
LIVE_CODE = "print(sum(range(10)))\n"


def main(argv: Optional[List[str]] = None) -> int:
    log_path = os.environ.get("SANDBOX_LOG", "logs/sandbox.log")
    clean_path = os.environ.get("SANDBOX_CLEANUP_LOG",
                                "logs/sandbox-cleanup.log")
    log = SandboxLog(path=log_path, fresh=True)
    box = MicroVMSandbox(log=log)
    log(f"rail 6 (the stall): run AI-written code in a MicroVM "
        f"region={box.region} run={box.name}")
    t0 = time.monotonic()
    result = box.run(LIVE_CODE)
    took = time.monotonic() - t0
    log(f"[result] allowed={result.allowed} passed={result.passed} "
        f"returncode={result.returncode} "
        f"{output_summary('stdout', result.stdout)} "
        f"expected_output_matched={result.stdout.strip() == '45'}")
    log(f"[result] reason={result.reason}")
    log(f"[result] teardown clean={box.clean} duration={took:.0f}s")

    clean_log = SandboxLog(path=clean_path, fresh=True)
    clean_log(f"cleanup_check() region={box.region} after run {box.name}")
    found = cleanup_check(box.session, log=clean_log)
    ok = result.passed and result.stdout.strip() == "45" and \
        found["total"] == 0
    log(f"[summary] {'OK' if ok else 'FAILED'}: code ran in a MicroVM "
        f"and {found['total']} '{PREFIX}' resources remain")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
