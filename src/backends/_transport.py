"""Bounded exponential backoff for provider transport errors (plan 5.8).

Retries ONLY rate-limit / transient 5xx / connection-reset / timeout. Never
retries invalid schema, auth failure, refusal, or validation errors. The number
of transport retries is returned so it can be logged separately from agent
regeneration (they must never be conflated).
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable

MAX_TRANSPORT_ATTEMPTS = 6
INITIAL_DELAY_S = 1.0
MAX_DELAY_S = 60.0


def _is_retryable(exc: Exception) -> bool:
    try:
        from openai import (
            APIConnectionError,
            APITimeoutError,
            InternalServerError,
            RateLimitError,
        )
    except Exception:  # pragma: no cover - openai always present at runtime
        return False
    if isinstance(exc, (RateLimitError, APITimeoutError, APIConnectionError)):
        return True
    if isinstance(exc, InternalServerError):
        return True
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and status >= 500:
        return True
    return False


def call_with_backoff(fn: Callable[[], Any]) -> tuple[Any, int]:
    """Return (result, transport_retry_count)."""
    delay = INITIAL_DELAY_S
    retries = 0
    last_exc: Exception | None = None
    for attempt in range(MAX_TRANSPORT_ATTEMPTS):
        try:
            return fn(), retries
        except Exception as exc:  # noqa: BLE001 - classified below
            if not _is_retryable(exc) or attempt == MAX_TRANSPORT_ATTEMPTS - 1:
                raise
            last_exc = exc
            retries += 1
            sleep_s = min(delay, MAX_DELAY_S) * (1.0 + random.random() * 0.25)
            time.sleep(sleep_s)
            delay = min(delay * 2, MAX_DELAY_S)
    if last_exc:  # pragma: no cover - loop always returns or raises
        raise last_exc
    raise RuntimeError("backoff loop exited unexpectedly")
