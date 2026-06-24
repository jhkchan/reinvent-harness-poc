"""
raci_gate.py -- RACI ACCOUNTABILITY GATE (ComplyKit rail 5).

A faithful open-source port of ComplyKit's "RACI Bearer Matrix v3"
(`phases/bearer.py` + `bearer_raci_matrix` table + `judge_raci` LLM fallback +
`raci_reasoning` JSONB). This REPLACES the generic eval gate's role as the
"can this action proceed / who owns it" decision: before a regulated action is
taken, the harness assigns RACI accountability (Responsible / Accountable /
Consulted / Informed) and records the reasoning + provenance to the audit trail.

How ComplyKit does it (and we mirror exactly):

  1. DETERMINISTIC matrix lookup first. The per-tenant ``bearer_raci_matrix``
     has rows (control_area_pattern, r_role, a_role, c_roles[], i_roles[],
     priority). For an action's ``control_area`` we pick the HIGHEST-priority
     row whose pattern matches (ComplyKit: `.order("priority", desc=True)` +
     SQL-LIKE `%`->`*` via fnmatch). Role names resolve to bearers.

  2. LLM JUDGE FALLBACK only on a matrix MISS or an unresolved role. ComplyKit
     calls a single `judge_raci` tool (temperature 0.1, enum-constrained bearer
     IDs). Here we call Bedrock ``converse`` (Nova micro) constrained to the
     known bearer ids, parse the assignment, and tag those roles
     ``source="llm_fallback"`` (matrix hits are ``source="matrix"``).

  3. ``raci_reasoning`` provenance. Each role entry is
     ``{bearer_id, bearer_name, reasoning, source}`` with
     ``source ∈ (matrix | llm_fallback | manual)`` -- recorded to the immutable
     audit trail, so a regulator can see WHO was made Accountable and WHY.

Determinism where it matters: the matrix is human-authored policy, evaluated
deterministically. The LLM is used only to fill a gap the policy did not cover,
and its contribution is always labelled as such. A missing Accountable bearer
is flagged (ComplyKit logs a `missing_accountable` warning) -- accountability is
mandatory in a regulated workflow.

Maps to: AWS Bedrock (`converse`, Nova micro) for the judge fallback; the
matrix is config (DynamoDB / per-tenant JSON). See README "AWS mapping".
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .audit import AuditTrail


@dataclass
class MatrixRule:
    """One row of the per-tenant bearer_raci_matrix."""
    control_area_pattern: str           # SQL-LIKE pattern; % wildcard (-> fnmatch *)
    r_role: str
    a_role: str
    c_roles: List[str] = field(default_factory=list)
    i_roles: List[str] = field(default_factory=list)
    priority: int = 50                  # higher wins (ComplyKit order priority desc)


@dataclass
class Bearer:
    """A RACI risk owner (ComplyKit `bearers` row)."""
    bearer_id: str
    name: str
    scope: str = ""


@dataclass
class RaciAssignment:
    control_area: str
    # role -> {bearer_id, bearer_name, reasoning, source} (None for unfilled A)
    raci_reasoning: Dict[str, Any]
    matrix_hit: bool
    used_llm_fallback: bool
    missing_accountable: bool

    def summary(self) -> str:
        def name(role: str) -> str:
            e = self.raci_reasoning.get(role)
            if isinstance(e, dict):
                return f"{e.get('bearer_name')}({e.get('source')})"
            if isinstance(e, list):
                return ",".join(f"{x.get('bearer_name')}" for x in e) or "-"
            return "-"
        return (
            f"control_area={self.control_area!r} "
            f"R={name('r')} A={name('a')} "
            f"matrix_hit={self.matrix_hit} llm_fallback={self.used_llm_fallback}"
            + (" [MISSING ACCOUNTABLE]" if self.missing_accountable else "")
        )


_JUDGE_SYSTEM = (
    "You are a compliance RACI assignment expert. Select bearers for each RACI "
    "role based on their scope. Responsible = does the work; Accountable = "
    "final authority. Respond with ONLY a JSON object."
)

_JUDGE_TEMPLATE = """Control area: {control_area}
Unresolved roles needing a bearer: {unresolved}
Available bearers (choose bearer_id values from these ONLY):
{bearers}

Respond with ONLY this JSON shape (bearer_id MUST be one of the ids above):
{{"r_bearer_id": "<id or null>", "a_bearer_id": "<id or null>",
  "reasoning_r": "<one sentence>", "reasoning_a": "<one sentence>"}}
"""


def _extract_json(text: str) -> Dict[str, Any]:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"judge_raci did not return JSON: {text[:160]!r}")
    return json.loads(m.group(0))


class RaciGate:
    """Deterministic matrix lookup + Bedrock judge fallback RACI assignment."""

    def __init__(
        self,
        matrix: List[MatrixRule],
        bearers: List[Bearer],
        bedrock_runtime: Any = None,
        model_id: str = "us.amazon.nova-micro-v1:0",
        audit: Optional[AuditTrail] = None,
        tenant_id: str = "",
    ) -> None:
        # highest priority first (ComplyKit `.order("priority", desc=True)`)
        self.matrix = sorted(matrix, key=lambda r: r.priority, reverse=True)
        self.bearers = bearers
        self._by_name = {b.name.lower(): b for b in bearers}
        self.client = bedrock_runtime
        self.model_id = model_id
        self.audit = audit
        self.tenant_id = tenant_id

    # -- deterministic helpers (mirror ComplyKit _find_matrix_rule / _resolve) --
    def _find_matrix_rule(self, control_area: str) -> Optional[MatrixRule]:
        ca = control_area.lower()
        for rule in self.matrix:                       # already priority-sorted
            pattern = rule.control_area_pattern.lower().replace("%", "*").replace("_", "?")
            if fnmatch.fnmatch(ca, pattern):
                return rule
        return None

    def _resolve_role_name(self, role_name: str) -> Optional[Bearer]:
        key = (role_name or "").lower().strip()
        if key in self._by_name:
            return self._by_name[key]
        for b in self.bearers:                         # scope substring fallback
            if key and key in (b.scope or "").lower():
                return b
        return None

    def _entry(self, b: Bearer, reasoning: str, source: str) -> Dict[str, Any]:
        return {"bearer_id": b.bearer_id, "bearer_name": b.name,
                "reasoning": reasoning, "source": source}

    # -- the gate ------------------------------------------------------------
    def assign(self, control_area: str, action_id: str = "") -> RaciAssignment:
        rule = self._find_matrix_rule(control_area)

        r_bearer = a_bearer = None
        c_bearers: List[Bearer] = []
        i_bearers: List[Bearer] = []
        unresolved: Dict[str, str] = {}

        if rule is not None:
            r_bearer = self._resolve_role_name(rule.r_role)
            a_bearer = self._resolve_role_name(rule.a_role)
            c_bearers = [b for rn in rule.c_roles if (b := self._resolve_role_name(rn))]
            i_bearers = [b for rn in rule.i_roles if (b := self._resolve_role_name(rn))]
            if r_bearer is None:
                unresolved["r"] = rule.r_role
            if a_bearer is None:
                unresolved["a"] = rule.a_role
        else:
            # matrix MISS -> both core roles unresolved, hand to the judge
            unresolved = {"r": "(no matching matrix rule)", "a": "(no matching matrix rule)"}

        used_llm = False
        llm = {}
        if unresolved:
            llm = self._judge_raci(control_area, unresolved)
            if llm:
                used_llm = True
                if "r" in unresolved and llm.get("r_bearer_id"):
                    r_bearer = self._bearer_by_id(llm["r_bearer_id"]) or r_bearer
                if "a" in unresolved and llm.get("a_bearer_id") and llm["a_bearer_id"] != "NONE":
                    a_bearer = self._bearer_by_id(llm["a_bearer_id"]) or a_bearer

        def _src(role: str) -> str:
            return "llm_fallback" if (role in unresolved and used_llm) else "matrix"

        raci_reasoning: Dict[str, Any] = {
            "r": self._entry(
                r_bearer,
                llm.get("reasoning_r") or (f"Matrix rule: {rule.r_role}" if rule else "LLM fallback"),
                _src("r"),
            ) if r_bearer else None,
            "a": self._entry(
                a_bearer,
                llm.get("reasoning_a") or (f"Matrix rule: {rule.a_role}" if rule else "LLM fallback"),
                _src("a"),
            ) if a_bearer else None,
            "c": [self._entry(b, f"Consulted per matrix rule for '{control_area}'", "matrix") for b in c_bearers],
            "i": [self._entry(b, f"Informed per matrix rule for '{control_area}'", "matrix") for b in i_bearers],
        }

        assignment = RaciAssignment(
            control_area=control_area,
            raci_reasoning=raci_reasoning,
            matrix_hit=rule is not None,
            used_llm_fallback=used_llm,
            missing_accountable=a_bearer is None,
        )

        if self.audit:
            self.audit.append(
                event="raci_assigned",
                actor="raci_gate",
                tenant_id=self.tenant_id,
                inputs={"control_area": control_area, "action_id": action_id,
                        "matrix_hit": assignment.matrix_hit},
                outputs={"raci_reasoning": raci_reasoning,
                         "used_llm_fallback": used_llm,
                         "missing_accountable": assignment.missing_accountable},
            )
        return assignment

    def _bearer_by_id(self, bearer_id: str) -> Optional[Bearer]:
        return next((b for b in self.bearers if b.bearer_id == bearer_id), None)

    def _judge_raci(self, control_area: str, unresolved: Dict[str, str]) -> Dict[str, Any]:
        """Bedrock judge fallback (ComplyKit's `judge_raci` tool call)."""
        if self.client is None or not self.bearers:
            return {}
        bearer_lines = "\n".join(
            f"  - id={b.bearer_id} name={b.name} scope={b.scope[:60]!r}" for b in self.bearers
        )
        prompt = _JUDGE_TEMPLATE.format(
            control_area=control_area,
            unresolved=", ".join(f"{k}={v}" for k, v in unresolved.items()),
            bearers=bearer_lines,
        )
        try:
            resp = self.client.converse(
                modelId=self.model_id,
                system=[{"text": _JUDGE_SYSTEM}],
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 200, "temperature": 0.1},
            )
            text = resp["output"]["message"]["content"][0]["text"]
            data = _extract_json(text)
            # constrain to known bearer ids (ComplyKit enum constraint)
            valid = {b.bearer_id for b in self.bearers}
            for key in ("r_bearer_id", "a_bearer_id"):
                if data.get(key) not in valid and data.get(key) != "NONE":
                    data[key] = None
            return data
        except Exception:
            return {}  # fail-safe: judge unavailable -> no fallback assignment
