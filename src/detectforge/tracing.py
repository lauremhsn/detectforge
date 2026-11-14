"""Tracing of agent runs: every model call and tool call as a nested observation.

Langfuse when its keys are configured, otherwise a no-op. Tracing must never change or break a
run: any failure inside the tracing backend is logged once and swallowed, and the run continues.
The run's own trace_id (32 hex characters) is reused as the Langfuse trace id, so a saved run file
and its trace in the dashboard share one id.

Only what the agent itself sees is traced (tuning data, rule text, model messages); the held-out
evaluation and secrets never go to the tracing backend.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Literal, Protocol

from detectforge.config import Settings

log = logging.getLogger(__name__)

Kind = Literal["agent", "generation", "tool", "evaluator", "span"]


class Observation(Protocol):
    def update(self, **fields: Any) -> None: ...


class Tracer(Protocol):
    def observe(self, name: str, kind: Kind, trace_id: str | None = None, **fields: Any) -> Any:
        """Context manager yielding an Observation; nested calls become children."""
        ...

    def trace_url(self, trace_id: str) -> str | None: ...

    def flush(self) -> None: ...


class _NoopObservation:
    def update(self, **fields: Any) -> None:
        pass


NOOP_OBSERVATION = _NoopObservation()


class NoopTracer:
    @contextmanager
    def observe(
        self, name: str, kind: Kind, trace_id: str | None = None, **fields: Any
    ) -> Iterator[Observation]:
        yield NOOP_OBSERVATION

    def trace_url(self, trace_id: str) -> str | None:
        return None

    def flush(self) -> None:
        pass


class _SafeObservation:
    def __init__(self, inner: Any, tracer: "LangfuseTracer"):
        self._inner = inner
        self._tracer = tracer

    def update(self, **fields: Any) -> None:
        try:
            self._inner.update(**fields)
        except Exception as e:  # tracing must never break the run
            self._tracer._failed("update", e)


class LangfuseTracer:
    def __init__(self, client: Any):
        self._client = client
        self._warned = False

    @classmethod
    def from_settings(cls, settings: Settings) -> "LangfuseTracer":
        from langfuse import Langfuse

        return cls(
            Langfuse(
                public_key=settings.langfuse_public_key.get_secret_value(),
                secret_key=settings.langfuse_secret_key.get_secret_value(),
                base_url=settings.langfuse_host,
            )
        )

    @contextmanager
    def observe(
        self, name: str, kind: Kind, trace_id: str | None = None, **fields: Any
    ) -> Iterator[Observation]:
        try:
            manager = self._client.start_as_current_observation(
                name=name,
                as_type=kind,
                trace_context={"trace_id": trace_id} if trace_id else None,
                **fields,
            )
            inner = manager.__enter__()
        except Exception as e:  # tracing must never break the run
            self._failed("start", e)
            yield NOOP_OBSERVATION
            return
        try:
            yield _SafeObservation(inner, self)
        except BaseException as exc:
            self._exit(manager, exc)
            raise
        else:
            self._exit(manager, None)

    def _exit(self, manager: Any, exc: BaseException | None) -> None:
        try:
            if exc is None:
                manager.__exit__(None, None, None)
            else:
                manager.__exit__(type(exc), exc, exc.__traceback__)
        except Exception as e:  # tracing must never break the run
            self._failed("end", e)

    def trace_url(self, trace_id: str) -> str | None:
        try:
            return self._client.get_trace_url(trace_id=trace_id)
        except Exception as e:
            self._failed("trace_url", e)
            return None

    def flush(self) -> None:
        try:
            self._client.flush()
        except Exception as e:
            self._failed("flush", e)

    def _failed(self, step: str, error: Exception) -> None:
        if not self._warned:
            log.warning("tracing problem (%s failed: %s); the run continues", step, type(error).__name__)
            self._warned = True


def make_tracer(settings: Settings) -> Tracer:
    """Langfuse if both keys are set, otherwise a no-op (the run file still records every call)."""
    keys = (settings.langfuse_public_key, settings.langfuse_secret_key)
    if any(k is None or not k.get_secret_value().strip() for k in keys):
        return NoopTracer()
    try:
        return LangfuseTracer.from_settings(settings)
    except Exception as e:
        log.warning("Langfuse unavailable (%s); continuing without tracing", type(e).__name__)
        return NoopTracer()
