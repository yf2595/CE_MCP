"""Local vLLM backend (OpenAI-compatible Chat Completions on 127.0.0.1).

Thin wrapper over OpenAIChatBackend that targets a local vLLM endpoint with an
``EMPTY`` key and applies per-model request settings from configs/models.yaml
(sampling params, reasoning control, plan-and-act prefix). Targets a local
vLLM server (typically http://127.0.0.1) and is not exposed off localhost.
"""

from __future__ import annotations

from typing import Any, Mapping

from openai import OpenAI

from src.backends.openai_chat import OpenAIChatBackend


def build_vllm_backend(
    *,
    model_key: str,
    served_model_name: str,
    base_url: str,
    temperature: float | None,
    extra_params: Mapping[str, Any] | None,
    reasoning_mode: str | None,
    reasoning_control_source: str | None,
    system_prefix: str | None,
) -> OpenAIChatBackend:
    client = OpenAI(base_url=base_url.rstrip("/"), api_key="EMPTY")
    return OpenAIChatBackend(
        model_key=model_key,
        model=served_model_name,
        client=client,
        temperature=temperature,
        extra_params=dict(extra_params or {}),
        reasoning_mode=reasoning_mode,
        reasoning_control_source=reasoning_control_source,
        system_prefix=system_prefix,
    )
