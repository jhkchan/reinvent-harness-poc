"""
raci_gate.py -- Rail 3, the reins: named-human approval (RACI gate).

Regulator question: "Whose name is on this action?"

Before a regulated action is taken, the harness assigns RACI accountability
(Responsible / Accountable / Consulted / Informed) to named people and records
the reasoning and its provenance to the audit trail (rail 4).

How it works:

  1. DETERMINISTIC matrix lookup first. The per-tenant RACI matrix has rows
     (control_area_pattern, r_role, a_role, c_roles[], i_roles[], priority).
     For an action's ``control_area`` we pick the HIGHEST-priority row whose
     pattern matches (SQL-LIKE ``%`` -> fnmatch ``*``). Role names resolve to
     bearers (the named people who carry the role).

  2. LLM JUDGE FALLBACK only on a matrix MISS or an unresolved role. We call
     Bedrock ``converse`` (Nova micro, temperature 0.1) constrained to the
     known bearer ids, parse the assignment, and FLAG those roles
     ``source="llm_fallback"`` (matrix hits are ``source="matrix"``).

  3. Provenance. Each role entry is
     ``{bearer_id, bearer_name, reasoning, source}`` with
     ``source in (matrix | llm_fallback | manual)``, recorded to the
     hash-chained audit trail, so a regulator can see WHO was made
     Accountable and WHY.

  4. APPROVAL. ``approve()`` records the sign-off of the named Accountable
     bearer on the action the assignment was made for, and only that bearer
     can give it. An Accountable picked by the LLM is provisional
     (``needs_confirmation``): the LLM never approves, and that person's own
     sign-off is the confirmation. Pass ``approver_id`` from your identity
     provider (an authenticated session), never from the agent. The judge
     sees ``control_area``, which comes from your pipeline, not from the end
     user; it can only name a known bearer, and that bearer must still sign.

Determinism where it matters: the matrix is human-authored policy, evaluated
deterministically. The LLM only fills a gap the policy did not cover, and its
contribution is always labelled as such. A missing Accountable bearer is
flagged (``missing_accountable``): accountability is mandatory.

AWS covers: Step Functions ``.waitForTaskToken`` and MCP elicitation can pause
for an approval. You still own binding the approval to one named approver,
the RACI matrix and the approver record. See the README rail table.
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
    """One row of the per-tenant RACI matrix."""
    control_area_pattern: str           # SQL-LIKE pattern; % wildcard (-> fnmatch *)
    r_role: str
    a_role: str
    c_roles: List[str] = field(default_factory=list)
    i_roles: List[str] = field(default_factory=list)
    priority: int = 50                  # higher wins


@dataclass
class Bearer:
    """A named person who can carry a RACI role."""
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
    # True when the LLM picked the Accountable: provisional until that named
    # person signs off with approve().
    needs_confirmation: bool = False
    action_id: str = ""     # the one action an approval on this assignment covers

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
            + (" [A NEEDS CONFIRMATION]" if self.needs_confirmation else "")
        )


@dataclass
class Approval:
    """One recorded sign-off (or refusal) for one action."""
    action_id: str
    approver_id: str
    approved: bool
    reason: str


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
        raise ValueError(f"RACI judge did not return JSON: {text[:160]!r}")
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
        # highest priority first
        self.matrix = sorted(matrix, key=lambda r: r.priority, reverse=True)
        self.bearers = bearers
        self._by_name = {b.name.lower(): b for b in bearers}
        self.client = bedrock_runtime
        self.model_id = model_id
        self.audit = audit
        self.tenant_id = tenant_id
        self.last_error = ""   # why the last judge call returned nothing

    # -- deterministic helpers ---------------------------------------------
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

    def _from_matrix(self, rule: Optional[MatrixRule]):
        """Resolve R/A/C/I from a matrix rule; report unresolved core roles."""
        if rule is None:
            # matrix MISS -> both core roles unresolved, hand to the judge
            miss = "(no matching matrix rule)"
            return None, None, [], [], {"r": miss, "a": miss}
        r = self._resolve_role_name(rule.r_role)
        a = self._resolve_role_name(rule.a_role)
        c = [b for rn in rule.c_roles if (b := self._resolve_role_name(rn))]
        i = [b for rn in rule.i_roles if (b := self._resolve_role_name(rn))]
        unresolved: Dict[str, str] = {}
        if r is None:
            unresolved["r"] = rule.r_role
        if a is None:
            unresolved["a"] = rule.a_role
        return r, a, c, i, unresolved

    def _pick(self, llm: Dict[str, Any], role: str,
              unresolved: Dict[str, str], current: Optional[Bearer]):
        """Take the judge's bearer for an unresolved role, if it named one."""
        bid = llm.get(f"{role}_bearer_id")
        if role not in unresolved or not bid or bid == "NONE":
            return current
        return self._bearer_by_id(bid) or current

    # -- the gate ------------------------------------------------------------
    def assign(self, control_area: str, action_id: str = "") -> RaciAssignment:
        # [snippet:rail-3]
        rule = self._find_matrix_rule(control_area)  # matrix first
        r, a, c, i, unresolved = self._from_matrix(rule)
        llm: Dict[str, Any] = {}
        if unresolved:  # miss or unknown role: ask the judge
            llm = self._judge_raci(control_area, unresolved)
            r = self._pick(llm, "r", unresolved, r)
            a = self._pick(llm, "a", unresolved, a)
        src = {k: "llm_fallback" if llm else "matrix"
               for k in unresolved}  # flag every LLM pick
        # [/snippet]
        used_llm = bool(llm)

        def _why(role: str, matrix_role: str) -> str:
            text = llm.get(f"reasoning_{role}")
            if text:
                return text
            return f"Matrix rule: {matrix_role}" if rule else "LLM fallback"

        def _core(b: Optional[Bearer], role: str, matrix_role: str):
            if b is None:
                return None
            return self._entry(b, _why(role, matrix_role),
                               src.get(role, "matrix"))

        raci_reasoning: Dict[str, Any] = {
            "r": _core(r, "r", rule.r_role if rule else ""),
            "a": _core(a, "a", rule.a_role if rule else ""),
            "c": [self._entry(b, f"Consulted per matrix rule for "
                                 f"'{control_area}'", "matrix") for b in c],
            "i": [self._entry(b, f"Informed per matrix rule for "
                                 f"'{control_area}'", "matrix") for b in i],
        }

        assignment = RaciAssignment(
            control_area=control_area,
            raci_reasoning=raci_reasoning,
            matrix_hit=rule is not None,
            used_llm_fallback=used_llm,
            missing_accountable=a is None,
            needs_confirmation=a is not None and src.get("a") == "llm_fallback",
            action_id=action_id,
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
                         "missing_accountable": assignment.missing_accountable,
                         "needs_confirmation": assignment.needs_confirmation},
            )
        return assignment

    def approve(self, assignment: RaciAssignment, action_id: str,
                approver_id: str, approved: bool = True) -> Approval:
        """Record the named Accountable bearer's decision on one action.

        Only the bearer assigned as Accountable can approve or reject, and
        only for the action the assignment was made for. Anything else is
        refused. Every attempt, refused or not, goes to the audit trail."""
        a = assignment.raci_reasoning.get("a")
        if action_id != assignment.action_id:
            result = Approval(action_id, approver_id, False,
                              f"this assignment covers action "
                              f"'{assignment.action_id}', not '{action_id}'")
        elif not a:
            result = Approval(action_id, approver_id, False,
                              "no Accountable bearer: nobody can approve")
        elif approver_id != a["bearer_id"]:
            result = Approval(action_id, approver_id, False,
                              f"only {a['bearer_name']} (the Accountable) "
                              f"can approve")
        else:
            result = Approval(action_id, approver_id, approved,
                              f"{'approved' if approved else 'rejected'} by "
                              f"{a['bearer_name']} ({a['source']})")
            assignment.needs_confirmation = False  # the person has answered
        if self.audit:
            self.audit.append(
                event="approval_recorded",
                actor=approver_id or "unknown",
                tenant_id=self.tenant_id,
                inputs={"action_id": action_id,
                        "control_area": assignment.control_area},
                outputs={"approved": result.approved, "reason": result.reason},
            )
        return result

    def _bearer_by_id(self, bearer_id: str) -> Optional[Bearer]:
        return next((b for b in self.bearers if b.bearer_id == bearer_id), None)

    def _judge_raci(self, control_area: str, unresolved: Dict[str, str]) -> Dict[str, Any]:
        """Bedrock judge fallback, constrained to the known bearer ids."""
        self.last_error = ""
        if self.client is None or not self.bearers:
            self.last_error = "no Bedrock client or no bearers"
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
            # constrain to known bearer ids (enum constraint)
            valid = {b.bearer_id for b in self.bearers}
            for key in ("r_bearer_id", "a_bearer_id"):
                if data.get(key) not in valid and data.get(key) != "NONE":
                    data[key] = None
            return data
        except Exception as e:  # fail-safe: no fallback assignment
            self.last_error = type(e).__name__
            return {}
