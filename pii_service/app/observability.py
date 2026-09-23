"""Privacy-safe OpenTelemetry spans; payloads and identifiers are never attributes."""
from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from contextlib import nullcontext
from typing import Any

try:
    from opentelemetry import propagate, trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except ImportError:  # Allows lightweight local tests without optional tracing packages.
    propagate = trace = None


class _NoopSpan:
    def set_attribute(self, _name: str, _value: Any) -> None:
        pass


_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
if trace is not None and _ENDPOINT:
    provider = TracerProvider(resource=Resource.create({
        "service.name": "pii-api",
        "service.instance.id": socket.gethostname(),
    }))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=_ENDPOINT, timeout=2)))
    trace.set_tracer_provider(provider)

_tracer = trace.get_tracer("pii-service") if trace is not None else None


def incoming_context(headers: Mapping[str, str]):
    """Use only W3C trace headers; do not record request headers as attributes."""
    return propagate.extract({k: v for k, v in headers.items() if k.lower() in ("traceparent", "tracestate")}) if propagate is not None else None


def span(name: str, *, attributes: Mapping[str, Any] | None = None, parent=None):
    if _tracer is None:
        return nullcontext(_NoopSpan())
    return _tracer.start_as_current_span(
        name, context=parent, attributes=dict(attributes or {}),
        record_exception=False, set_status_on_exception=False,
    )
