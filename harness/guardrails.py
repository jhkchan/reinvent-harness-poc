"""
guardrails.py -- optional Bedrock Guardrails wrapper.

If a guardrail id + version is configured (constructor args or the
BEDROCK_GUARDRAIL_ID / BEDROCK_GUARDRAIL_VERSION env vars), this calls
bedrock-runtime `apply_guardrail` to screen text for PII, denied topics,
prompt-injection, etc. If nothing is configured it is a clearly-labeled NO-OP
that never blocks and never raises -- the harness still runs end to end without
a provisioned guardrail (important for a zero-cost demo).

Maps to: Amazon Bedrock Guardrails. See README "AWS mapping".

To enable for real (creates a billable resource, so it is NOT done by the demo):

    aws bedrock create-guardrail ...   # or the console
    export BEDROCK_GUARDRAIL_ID=<id>
    export BEDROCK_GUARDRAIL_VERSION=<version>
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class GuardrailResult:
    configured: bool          # was a guardrail actually applied?
    action: str               # "NONE" (no-op) | "NONE"/"GUARDRAIL_INTERVENED"
    blocked: bool
    output_text: str          # possibly-masked text to use downstream
    detail: str = ""


class Guardrails:
    def __init__(
        self,
        bedrock_runtime: Any = None,
        guardrail_id: Optional[str] = None,
        guardrail_version: Optional[str] = None,
    ) -> None:
        self.client = bedrock_runtime
        self.guardrail_id = guardrail_id or os.environ.get("BEDROCK_GUARDRAIL_ID")
        self.guardrail_version = (
            guardrail_version or os.environ.get("BEDROCK_GUARDRAIL_VERSION")
        )

    @property
    def configured(self) -> bool:
        return bool(self.client and self.guardrail_id and self.guardrail_version)

    def apply(self, text: str, source: str = "OUTPUT") -> GuardrailResult:
        """Screen `text`. No-op (pass-through) when no guardrail is configured."""
        if not self.configured:
            return GuardrailResult(
                configured=False,
                action="NONE",
                blocked=False,
                output_text=text,
                detail="NO-OP: no guardrail configured (set BEDROCK_GUARDRAIL_ID/VERSION to enable)",
            )
        resp = self.client.apply_guardrail(
            guardrailIdentifier=self.guardrail_id,
            guardrailVersion=self.guardrail_version,
            source=source,
            content=[{"text": {"text": text}}],
        )
        action = resp.get("action", "NONE")
        blocked = action == "GUARDRAIL_INTERVENED"
        out = text
        outputs = resp.get("outputs") or []
        if outputs and "text" in outputs[0]:
            out = outputs[0]["text"]
        return GuardrailResult(
            configured=True,
            action=action,
            blocked=blocked,
            output_text=out,
            detail=f"guardrail {self.guardrail_id}:{self.guardrail_version} -> {action}",
        )
