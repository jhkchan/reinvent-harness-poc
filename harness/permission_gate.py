"""
permission_gate.py -- Rail 1, the bit: a DETERMINISTIC permission gate.

Regulator question: "Who allowed this tool call?"

This is the most safety-critical rail. It is intentionally *not* an LLM call:
the decision must be reproducible, auditable, and explainable to a regulator.

Resolution order (EXACTLY, highest priority first):

  (1) dangerous-command blocklist  -> always DENY, even if a broader rule
      (e.g. an `allow *` override) would otherwise allow it. This ordering is
      the whole point: defense-in-depth means the blocklist cannot be widened
      away by a permissive config.
  (2) glob overrides               -> fnmatch on the command string
      (e.g. "bash:npm *" -> allow).
  (3) explicit per-tool config     -> allow / ask / deny from a dict (or TOML).
  (4) built-in default posture     -> read_file/glob/grep/list_dir = allow;
      bash/write_file/edit_file/fetch = ask.

An `ask` decision invokes a human-review callback with a FAIL-CLOSED timeout
(default 60s, configurable). On timeout, exception, or an explicit "no" the
decision becomes DENY. Approved (tool, command) pairs are cached for the
session so a human is not asked twice for the same thing.

AWS covers: AgentCore Policy on Gateway (Cedar, default deny, forbid beats
permit) and IAM explicit deny. You still own tool calls that never reach the
Gateway, and the blocklist content itself. See the README rail table.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Iterator, List, Optional


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass
class GateResult:
    """The outcome of a before_tool() resolution, with an audit trail."""

    decision: Decision
    rule: str                    # which stage decided (for the audit log)
    reason: str
    tool_name: str
    command: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.decision.value.upper()} [{self.rule}] {self.reason}"


# --- Stage 1: dangerous-command blocklist -----------------------------------
# These patterns are matched against the *command text* of a tool call
# (for bash/run_bash, that is args["command"]; for other tools we also scan
# any string arg so a destructive payload cannot sneak through write_file).
# A match here ALWAYS denies, regardless of any allow override.
DANGEROUS_PATTERNS: Dict[str, str] = {
    "mkfs":                 r"mkfs\.",                  # format a filesystem
    "dd_to_disk":           r"\bdd\s[^\n;&|]{0,200}?of=/dev/",  # raw device
    "fork_bomb":            r":\(\)\s*\{",              # :(){ :|:& };:
    "chmod_777_root":       r"chmod\s+-R\s+777\s+/",    # recursive world-write on /
    "redirect_to_disk":     r">\s*/dev/sd",             # clobber a block device
}

_COMPILED_DANGEROUS = {
    name: re.compile(pat) for name, pat in DANGEROUS_PATTERNS.items()
}

# rm is checked on tokens, not with a regex: flags can come in any order or
# long form, quotes can hide the target, and any operand can be the root.
# Like every blocklist it is an example, not a complete list (a shell offers
# endless spellings), and it leans toward deny: in multi-line text an rm on
# one line is read together with flags on the next.
RM_RULE = "rm_rf_root_home_glob"
# / /* /** /./* ~ ~/* ~user $HOME ${HOME}/* * ** ./*  (not /tmp/x, ~/Downloads/*)
_ROOT_OPERAND = re.compile(
    r"^(?:(?:~[^/\s]*|\$\{?HOME\}?)[/.*?]*|[/.*?]*[/*?][/.*?]*)$")
_TOKEN_EDGE = ",[]{}"
_SHELL_PUNCTUATION = ";&|()<>`"
_SHELL_SEPARATORS = set(_SHELL_PUNCTUATION)


def _segments(text: str, depth: int = 0) -> Iterator[List[str]]:
    """Split text into command-like token lists, and look inside quoted
    strings too (``os.system('rm -rf /')``)."""
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=_SHELL_PUNCTUATION)
        lex.whitespace_split = True
        lex.commenters = ""       # sh only treats a word-initial # as a comment
        tokens = list(lex)
    except ValueError:            # unbalanced quotes: split on shell punctuation
        tokens = [t.strip("'\"") for t in
                  re.findall(r"[;&|()<>`]+|[^\s;&|()<>`]+", text)]
    seg: List[str] = []
    for raw in tokens:
        t = raw.strip(_TOKEN_EDGE) or raw
        if t and set(t) <= _SHELL_SEPARATORS:
            if seg:
                yield seg
            seg = []
        elif any(c.isspace() for c in t):
            if depth < 3:
                yield from _segments(t, depth + 1)
            else:
                seg.extend(t.split())
        else:
            seg.append(t)
    if seg:
        yield seg


def _rm_recursive_on_root(text: str) -> bool:
    for seg in _segments(text):
        for i, tok in enumerate(seg):
            if tok.rsplit("/", 1)[-1] != "rm":      # rm, /bin/rm
                continue
            args = seg[i + 1:]
            recursive = any(
                (a.startswith("--r") and "--recursive".startswith(a))  # --recur
                or (a.startswith("-") and not a.startswith("--")
                    and ("r" in a or "R" in a))
                for a in args)
            if recursive and any(_ROOT_OPERAND.match(a) for a in args
                                 if not a.startswith("-")):
                return True
            break   # a later rm's arguments are a subset of this one's
    return False


# The field a glob override matches, per tool (the field its code uses).
_GLOB_FIELDS = ("command", "cmd", "script", "path")
_GLOB_FIELD: Dict[str, str] = {
    "bash": "command", "run_bash": "command",
    "read_file": "path", "write_file": "path", "edit_file": "path",
}


# --- built-in default posture (Stage 4) -------------------------------------
DEFAULT_TOOL_POSTURE: Dict[str, Decision] = {
    "read_file": Decision.ALLOW,
    "glob":      Decision.ALLOW,
    "grep":      Decision.ALLOW,
    "list_dir":  Decision.ALLOW,
    "bash":      Decision.ASK,
    "run_bash":  Decision.ASK,
    "write_file": Decision.ASK,
    "edit_file": Decision.ASK,
    "fetch":     Decision.ASK,
}


def _approve_noninteractive(tool_name: str, command: str) -> bool:
    """Default human-review callback for non-interactive runs: deny (fail-closed).

    In a real deployment this is replaced by a Slack/PagerDuty/console prompt.
    Returning False here means an unattended `ask` becomes a DENY, which is the
    safe default for a regulated environment.
    """
    return False


class PermissionGate:
    """Deterministic before_tool() hook with a session-scoped allow cache."""

    def __init__(
        self,
        tool_config: Optional[Dict[str, str]] = None,
        glob_overrides: Optional[Dict[str, str]] = None,
        human_review: Optional[Callable[[str, str], bool]] = None,
        ask_timeout_seconds: float = 60.0,
        default_posture: Optional[Dict[str, Decision]] = None,
    ) -> None:
        # explicit per-tool config: {"write_file": "deny", "bash": "ask", ...}
        self.tool_config: Dict[str, Decision] = {
            k: Decision(v) for k, v in (tool_config or {}).items()
        }
        # glob overrides keyed on "<tool>:<glob>" matched against "<tool>:<cmd>"
        # e.g. {"bash:npm *": "allow"} or {"*": "allow"} (a broad allow override)
        self.glob_overrides: Dict[str, Decision] = {
            k: Decision(v) for k, v in (glob_overrides or {}).items()
        }
        self.human_review = human_review or _approve_noninteractive
        self.ask_timeout_seconds = ask_timeout_seconds
        self.default_posture = default_posture or DEFAULT_TOOL_POSTURE
        # session-scoped cache of approved (scope, tool, args) -> True
        self._allow_cache: Dict[str, bool] = {}
        self._lock = threading.Lock()

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _command_text(tool_name: str, args: Dict) -> str:
        """The text we scan and show the reviewer: the command first, then
        every other string arg, so an extra key cannot hide a payload."""
        if not args:
            return ""
        keys = [k for k in ("command", "cmd", "script") if k in args]
        keys += [k for k in args if k not in keys]
        return "\n".join(args[k] for k in keys if isinstance(args[k], str))

    @staticmethod
    def _cache_key(scope: str, tool_name: str, args: Dict) -> str:
        """One approval covers exactly one (scope, tool, args) call."""
        return json.dumps([scope, tool_name, args], sort_keys=True, default=str)

    def _check_blocklist(self, command: str) -> Optional[str]:
        if _rm_recursive_on_root(command):
            return RM_RULE
        for name, rx in _COMPILED_DANGEROUS.items():
            if rx.search(command):
                return name
        return None

    @staticmethod
    def _glob_text(tool_name: str, args: Dict) -> Optional[str]:
        """The one field a glob override may match: the field the tool's code
        uses (the command a shell tool runs, the path a file tool touches).
        None means "no override": a newline, a second target field, an
        absolute path or a '..' segment never gets a glob ALLOW.

        A glob ALLOW on a shell tool allows everything that program can do
        (``run_bash:git *`` also allows ``git -c core.sshCommand=...``).
        Keep shell tools on ask, or run them in rail 6's sandbox."""
        field_name = _GLOB_FIELD.get(tool_name)
        present = [k for k in _GLOB_FIELDS if k in args]
        if field_name is None:
            field_name = present[0] if present else None
        if field_name is None:
            return ""
        value = args.get(field_name)
        if not isinstance(value, str) or "\n" in value or present != [field_name]:
            return None
        if field_name == "path" and (value.startswith(("/", "~"))
                                     or ".." in value.replace("\\", "/").split("/")):
            return None
        return value

    def _glob_lookup(self, tool_name: str, args: Dict) -> Optional[Decision]:
        command = self._glob_text(tool_name, args)
        if command is None:
            return None               # no override: fall through to config
        target = f"{tool_name}:{command}"
        for pattern, decision in self.glob_overrides.items():
            # match either against "<tool>:<cmd>" or, for a bare pattern,
            # against the command alone and the tool name.
            if (
                fnmatch.fnmatch(target, pattern)
                or fnmatch.fnmatch(command, pattern)
                or fnmatch.fnmatch(tool_name, pattern)
            ):
                return decision
        return None

    # -- the hook ------------------------------------------------------------
    def before_tool(self, tool_name: str, args: Optional[Dict] = None,
                    scope: str = "") -> GateResult:
        """``scope`` (for example the tenant id) keeps one approval from
        covering the same call made for someone else. TenantScopedGate passes
        the tenant; a gate used by one session alone can leave it empty."""
        args = args or {}
        command = self._command_text(tool_name, args)

        # [snippet:rail-1]
        # Stage 1: the blocklist wins over every allow.
        hit = self._check_blocklist(command)
        if hit:
            return GateResult(
                Decision.DENY, "blocklist",
                f"matched dangerous pattern '{hit}'",
                tool_name, command,
            )
        # [/snippet]

        # session allow-cache short-circuit (only ever caches ALLOW).
        ck = self._cache_key(scope, tool_name, args)
        with self._lock:
            if self._allow_cache.get(ck):
                return GateResult(
                    Decision.ALLOW, "cache", "previously approved this session",
                    tool_name, command,
                )

        # Stage 2: glob overrides.
        g = self._glob_lookup(tool_name, args)
        if g is not None:
            return self._finalize(g, "glob-override", tool_name, command, ck)

        # Stage 3: explicit per-tool config.
        if tool_name in self.tool_config:
            return self._finalize(
                self.tool_config[tool_name], "tool-config", tool_name, command, ck
            )

        # Stage 4: built-in default posture.
        default = self.default_posture.get(tool_name, Decision.ASK)
        return self._finalize(default, "default-posture", tool_name, command, ck)

    def _finalize(
        self, decision: Decision, rule: str, tool_name: str, command: str,
        cache_key: str,
    ) -> GateResult:
        if decision is Decision.ALLOW:
            return GateResult(Decision.ALLOW, rule, "allowed by policy", tool_name, command)
        if decision is Decision.DENY:
            return GateResult(Decision.DENY, rule, "denied by policy", tool_name, command)
        # decision is ASK -> human review with a fail-closed timeout.
        return self._ask_human(rule, tool_name, command, cache_key)

    def _ask_human(self, rule: str, tool_name: str, command: str,
                   cache_key: str) -> GateResult:
        """Run the human-review callback with a fail-closed timeout.

        Timeout, exception, or an explicit False all resolve to DENY.
        A True resolves to ALLOW and is cached for the session.
        """
        # We run the reviewer on a DAEMON thread and join with a timeout.
        # A daemon thread is intentional: if the reviewer hangs, we resolve the
        # decision (DENY, fail-closed) immediately and never block the agent or
        # process exit on it. We do NOT use ThreadPoolExecutor here because its
        # shutdown()/atexit handler joins workers and would defeat the timeout.
        result_box: Dict[str, object] = {}

        def _worker() -> None:
            try:
                result_box["approved"] = bool(self.human_review(tool_name, command))
            except Exception as e:  # fail closed on any reviewer error
                result_box["error"] = str(e)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=self.ask_timeout_seconds)

        timed_out = t.is_alive()
        errored = str(result_box.get("error", "")) if "error" in result_box else ""
        approved = bool(result_box.get("approved", False))

        if timed_out:
            return GateResult(
                Decision.DENY, f"{rule}->ask-timeout",
                f"human review timed out after {self.ask_timeout_seconds}s (fail-closed)",
                tool_name, command,
            )
        if errored:
            return GateResult(
                Decision.DENY, f"{rule}->ask-error",
                f"human review raised: {errored} (fail-closed)",
                tool_name, command,
            )
        if approved:
            with self._lock:
                self._allow_cache[cache_key] = True
            return GateResult(
                Decision.ALLOW, f"{rule}->ask-approved",
                "approved by human reviewer", tool_name, command,
            )
        return GateResult(
            Decision.DENY, f"{rule}->ask-denied",
            "rejected by human reviewer", tool_name, command,
        )
