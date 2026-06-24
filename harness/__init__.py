"""
reinvent-harness-poc

An AI-agent harness for REGULATED INDUSTRIES on AWS. The governance rails are
derived from a real product -- ComplyKit, a private multi-tenant regulatory
gap-analysis platform for banks/insurers -- and distilled into a runnable,
framework-agnostic, open-source harness.

Governance rails (ComplyKit requirement -> harness rail):

  1. DURABLE + RESUMABLE pipeline   pipeline.py / checkpoint.py
     (8-phase pipeline + PipelineContext + should_skip + heartbeats + sweeper
      terminal-state guarantee + /retry vs /rerun)
  2. IMMUTABLE AUDIT TRAIL          audit.py
     (hash-chained, append-only; every gate decision / tool call / phase
      transition / RACI assignment with who/what/when/inputs/outputs)
  3. MCP-TOOL SECURITY              tenant_gate.py (+ permission_gate.py)
     (compliance MCP tool whitelist + per-tool allow/ask/deny)
  4. PER-TENANT ISOLATION           tenant_gate.py
     (tenant_id threaded through; cross-tenant access rejected)
  5. RACI GATE                      raci_gate.py
     (deterministic bearer matrix lookup + Bedrock judge fallback + reasoning)

Supporting rails kept from the generic POC: observability.py (spans),
guardrails.py (Bedrock Guardrails), agent.py (Bedrock converse tool-use loop).

ComplyKit itself is private; this is the extracted open-source harness. See
README.md for the full requirement -> rail -> AWS-service mapping.
"""

__version__ = "0.2.0"
