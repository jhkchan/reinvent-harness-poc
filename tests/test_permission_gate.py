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
