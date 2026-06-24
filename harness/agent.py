"""
agent.py -- a minimal Bedrock `converse` tool-use loop.

Three tools are exposed to the model: read_file, write_file, run_bash. Every
tool call is:
  1. routed through the PermissionGate.before_tool() hook (allow/ask/deny), and
  2. wrapped in an observability span (decision, latency, errors).

A DENY does not crash the loop -- the gate's reason is returned to the model as
the tool result, so the agent can adapt (or give up) rather than the process
dying. This is the "agent-accelerated, not autonomous" posture: the human
policy in the gate is always in the loop.

Maps to: AWS AgentCore Runtime (the managed loop + session isolation). Here we
run the loop locally so the POC is self-contained and free.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .observability import get_tracer, record_usage, tool_span
from .permission_gate import Decision, PermissionGate


# --- tool implementations (only run after the gate ALLOWS) ------------------
def _impl_read_file(args: Dict[str, Any]) -> str:
    path = args["path"]
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _impl_write_file(args: Dict[str, Any]) -> str:
    path = args["path"]
    content = args.get("content", "")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"wrote {len(content)} bytes to {path}"


def _impl_run_bash(args: Dict[str, Any]) -> str:
    command = args["command"]
    proc = subprocess.run(
        command, shell=True, capture_output=True, text=True, timeout=30
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return out.strip() or f"(exit {proc.returncode}, no output)"


TOOL_IMPLS = {
    "read_file": _impl_read_file,
    "write_file": _impl_write_file,
    "run_bash": _impl_run_bash,
}

# Bedrock toolConfig describing the three tools to the model.
TOOL_SPECS = [
    {
        "toolSpec": {
            "name": "read_file",
            "description": "Read a UTF-8 text file and return its contents.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "write_file",
            "description": "Write text content to a file (overwrites).",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "run_bash",
            "description": "Run a shell command and return combined stdout/stderr.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            }},
        }
    },
]


@dataclass
class ToolEvent:
    tool_name: str
    args: Dict[str, Any]
    decision: str
    rule: str
    result: str
    latency_ms: float = 0.0


@dataclass
class AgentResult:
    final_text: str
    tool_events: List[ToolEvent] = field(default_factory=list)
    usage: Dict[str, int] = field(default_factory=dict)


class Agent:
    def __init__(
        self,
        bedrock_runtime: Any,
        gate: PermissionGate,
        model_id: str = "us.amazon.nova-micro-v1:0",
        max_turns: int = 6,
    ) -> None:
        self.client = bedrock_runtime
        self.gate = gate
        self.model_id = model_id
        self.max_turns = max_turns

    def _run_tool(self, tool_name: str, args: Dict[str, Any]) -> ToolEvent:
        """Gate -> (maybe) execute -> trace. Always returns a ToolEvent."""
        with tool_span(tool_name) as span:
            result = self.gate.before_tool(tool_name, args)
            span.set_attribute("gate.decision", result.decision.value)
            span.set_attribute("gate.rule", result.rule)
            if result.decision is not Decision.ALLOW:
                span.set_attribute("tool.executed", False)
                return ToolEvent(
                    tool_name, args, result.decision.value, result.rule,
                    f"[gate {result.decision.value}] {result.reason}",
                )
            # allowed -> execute
            try:
                impl = TOOL_IMPLS[tool_name]
                out = impl(args)
                span.set_attribute("tool.executed", True)
                return ToolEvent(tool_name, args, "allow", result.rule, out)
            except Exception as e:
                span.set_attribute("tool.executed", True)
                span.set_attribute("tool.error", str(e))
                return ToolEvent(
                    tool_name, args, "allow", result.rule, f"[tool error] {e}"
                )

    def run(self, user_prompt: str, system: Optional[str] = None) -> AgentResult:
        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": [{"text": user_prompt}]}
        ]
        sys_blocks = [{"text": system}] if system else [
            {"text": "You are a careful assistant. Use tools when needed. "
                     "If a tool is denied, explain and stop."}
        ]
        events: List[ToolEvent] = []
        total_usage = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}

        for _turn in range(self.max_turns):
            with tool_span("bedrock.converse", **{"gen_ai.request.model": self.model_id}) as span:
                resp = self.client.converse(
                    modelId=self.model_id,
                    system=sys_blocks,
                    messages=messages,
                    toolConfig={"tools": TOOL_SPECS},
                    inferenceConfig={"maxTokens": 512, "temperature": 0.0},
                )
                record_usage(span, resp.get("usage"))
            for k in total_usage:
                total_usage[k] += resp.get("usage", {}).get(k, 0)

            out_msg = resp["output"]["message"]
            messages.append(out_msg)
            stop = resp.get("stopReason")

            if stop != "tool_use":
                text = _text_of(out_msg)
                return AgentResult(text, events, total_usage)

            # gather tool_use blocks, run them, feed results back
            tool_results = []
            for block in out_msg["content"]:
                if "toolUse" not in block:
                    continue
                tu = block["toolUse"]
                ev = self._run_tool(tu["name"], tu.get("input", {}) or {})
                events.append(ev)
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tu["toolUseId"],
                        "content": [{"text": ev.result}],
                    }
                })
            messages.append({"role": "user", "content": tool_results})

        return AgentResult(
            "[max turns reached]", events, total_usage
        )


def _text_of(message: Dict[str, Any]) -> str:
    parts = [b.get("text", "") for b in message.get("content", []) if "text" in b]
    return "\n".join(p for p in parts if p).strip()
