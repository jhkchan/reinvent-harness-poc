"""
observability.py -- spans for every tool call and gate decision.

If opentelemetry-sdk is installed we use a real Tracer wired to a
ConsoleSpanExporter (so you can see spans in the demo output). Otherwise we
fall back to a tiny built-in tracer with the same `start_span(...)` context
manager API, so the rest of the harness does not care which is active.

Each span carries attributes: tool name, gate decision, latency_ms, and token
usage (input/output) when the underlying Bedrock call reports it.

--- Pointing OTLP at CloudWatch -------------------------------------------
In production you replace the ConsoleSpanExporter with an OTLP exporter that
ships to the CloudWatch / X-Ray OTLP endpoint (this is exactly what AgentCore
Observability does under the hood):

    pip install opentelemetry-exporter-otlp-proto-http
    export OTEL_EXPORTER_OTLP_ENDPOINT="https://xray.us-east-1.amazonaws.com"
    export OTEL_RESOURCE_ATTRIBUTES="service.name=reinvent-harness"

    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

CloudWatch's Transaction Search / Application Signals then renders these spans
as a trace map. The attribute names below (gate.decision, tool.name,
gen_ai.usage.*) follow OpenTelemetry GenAI semantic conventions so they light
up the CloudWatch GenAI views without remapping.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when otel missing
    _OTEL_AVAILABLE = False


# --- tiny built-in fallback tracer -----------------------------------------
@dataclass
class _SimpleSpan:
    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    start_ns: int = field(default_factory=time.perf_counter_ns)
    end_ns: Optional[int] = None

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    @property
    def latency_ms(self) -> float:
        end = self.end_ns if self.end_ns is not None else time.perf_counter_ns()
        return (end - self.start_ns) / 1_000_000.0


class _SimpleTracer:
    """Minimal tracer used when opentelemetry-sdk is not installed."""

    def __init__(self) -> None:
        self.finished: List[_SimpleSpan] = []

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[_SimpleSpan]:
        span = _SimpleSpan(name=name, attributes=dict(attributes or {}))
        try:
            yield span
        finally:
            span.end_ns = time.perf_counter_ns()
            span.set_attribute("latency_ms", round(span.latency_ms, 2))
            self.finished.append(span)
            self._print(span)

    @staticmethod
    def _print(span: _SimpleSpan) -> None:
        attrs = " ".join(f"{k}={v}" for k, v in span.attributes.items())
        print(f"  [span] {span.name} | {attrs}")


# --- OpenTelemetry-backed tracer (preferred) -------------------------------
class _OtelTracer:
    def __init__(self) -> None:
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        # Don't clobber a globally-configured provider if one already exists.
        try:
            _otel_trace.set_tracer_provider(provider)
        except Exception:
            pass
        self._tracer = _otel_trace.get_tracer("reinvent-harness")
        self.finished: List[Dict[str, Any]] = []

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        start = time.perf_counter_ns()
        with self._tracer.start_as_current_span(name) as span:
            for k, v in (attributes or {}).items():
                span.set_attribute(k, v)
            try:
                yield span
            finally:
                latency_ms = round((time.perf_counter_ns() - start) / 1_000_000.0, 2)
                span.set_attribute("latency_ms", latency_ms)
                self.finished.append({"name": name, "latency_ms": latency_ms})


_TRACER: Optional[Any] = None


def get_tracer() -> Any:
    """Return a process-wide tracer (otel-backed if available, else built-in)."""
    global _TRACER
    if _TRACER is None:
        _TRACER = _OtelTracer() if _OTEL_AVAILABLE else _SimpleTracer()
    return _TRACER


def backend_name() -> str:
    return "opentelemetry-sdk (ConsoleSpanExporter)" if _OTEL_AVAILABLE else "builtin-tracer"


@contextmanager
def tool_span(tool_name: str, **attrs: Any) -> Iterator[Any]:
    """Convenience wrapper: a span named tool.<tool_name>."""
    base = {"tool.name": tool_name}
    base.update(attrs)
    with get_tracer().start_span(f"tool.{tool_name}", base) as span:
        yield span


def record_usage(span: Any, usage: Optional[Dict[str, Any]]) -> None:
    """Attach Bedrock token usage to a span using GenAI semantic conventions."""
    if not usage:
        return
    if "inputTokens" in usage:
        span.set_attribute("gen_ai.usage.input_tokens", usage["inputTokens"])
    if "outputTokens" in usage:
        span.set_attribute("gen_ai.usage.output_tokens", usage["outputTokens"])
    if "totalTokens" in usage:
        span.set_attribute("gen_ai.usage.total_tokens", usage["totalTokens"])
