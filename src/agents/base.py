"""Shared model-call helpers for agents and gates.

Backward-compatible facade over the new backend layer (src/backends). Existing
callers keep using `chat_completion(...)` and reading
`resp.choices[0].message.content` / `.tool_calls` and `usage_tokens(resp)`.

Routing rules:
  - gpt-5.4 (alias gpt54_low)      -> Responses API, reasoning.effort=low
  - gpt-4.1 (alias gpt41)          -> Chat Completions (unchanged behavior)
  - vllm_chat model keys           -> local vLLM endpoint (needs base_url)

For local models, set the endpoint via WAITI_VLLM_ENDPOINT / OPENAI_BASE_URL
or pass base_url explicitly (e.g. run_suite --base-url).
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from src.backends.accounting import record_turn
from src.backends.base import ChatCompletionShim
from src.backends.registry import get_backend, max_output_tokens_for

load_dotenv()


def get_client() -> OpenAI:
    """Retained for compatibility; new code uses the backend registry."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    return OpenAI(api_key=key)


def chat_completion(
    client: OpenAI | None,
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    temperature: float = 0,
    response_format: dict[str, Any] | None = None,
    base_url: str | None = None,
    request_metadata: dict[str, Any] | None = None,
) -> ChatCompletionShim:
    """Route a chat-style request through the configured backend.

    Returns a ChatCompletion-compatible shim. `client` is ignored (kept for
    signature compatibility); backends manage their own clients. `temperature`
    and `response_format` are honored only where the backend config allows.
    """
    base_url = base_url or os.environ.get("WAITI_VLLM_ENDPOINT") or os.environ.get("OPENAI_BASE_URL")
    backend = get_backend(model, base_url=base_url)
    turn = backend.generate(
        messages,
        tools or [],
        max_output_tokens=max_output_tokens_for(model),
        request_metadata=request_metadata or {},
    )
    record_turn(turn)
    return ChatCompletionShim(turn)


def usage_tokens(resp: Any) -> tuple[int, int]:
    usage = getattr(resp, "usage", None)
    if not usage:
        return 0, 0
    return int(getattr(usage, "prompt_tokens", 0) or 0), int(getattr(usage, "completion_tokens", 0) or 0)
