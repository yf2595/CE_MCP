"""Backend registry: resolve a model_key/alias to a configured ModelBackend."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from src.common.utils import CONFIGS_DIR, load_yaml

MODELS_CONFIG_PATH = CONFIGS_DIR / "models.yaml"


@lru_cache(maxsize=1)
def _load_config() -> dict[str, Any]:
    return load_yaml(MODELS_CONFIG_PATH)


def resolve_key(model_or_key: str) -> str:
    cfg = _load_config()
    aliases = cfg.get("aliases") or {}
    if model_or_key in (cfg.get("models") or {}):
        return model_or_key
    if model_or_key in aliases:
        return aliases[model_or_key]
    return model_or_key


def model_spec(model_or_key: str) -> dict[str, Any]:
    cfg = _load_config()
    key = resolve_key(model_or_key)
    spec = (cfg.get("models") or {}).get(key)
    if not spec:
        raise KeyError(f"Unknown model key/alias: {model_or_key!r}")
    return {"model_key": key, **spec}


def paper_model_keys() -> list[str]:
    return list(_load_config().get("paper_model_keys") or [])


def secondary_model_keys() -> list[str]:
    return list(_load_config().get("secondary_model_keys") or [])


def max_output_tokens_for(model_or_key: str) -> int:
    return int(model_spec(model_or_key).get("max_output_tokens", 8192))


_BACKEND_CACHE: dict[tuple[str, str | None], Any] = {}


def get_backend(model_or_key: str, *, base_url: str | None = None) -> Any:
    """Cached backend accessor (one client per (model_key, base_url))."""
    key = resolve_key(model_or_key)
    cache_key = (key, base_url)
    if cache_key not in _BACKEND_CACHE:
        _BACKEND_CACHE[cache_key] = build_backend(model_or_key, base_url=base_url)
    return _BACKEND_CACHE[cache_key]


def build_backend(model_or_key: str, *, base_url: str | None = None) -> Any:
    """Instantiate the backend for a model key/alias.

    base_url is required for vllm_chat backends (pass the local vLLM endpoint).
    """
    spec = model_spec(model_or_key)
    provider = spec["provider"]
    key = spec["model_key"]

    if provider == "openai_responses":
        from src.backends.openai_responses import OpenAIResponsesBackend

        return OpenAIResponsesBackend(
            model_key=key,
            model=spec["model"],
            client=_openai_api_client(),
            reasoning_effort=spec.get("reasoning_effort", "low"),
            store=bool(spec.get("store", False)),
        )

    if provider == "openai_chat":
        from src.backends.openai_chat import OpenAIChatBackend

        return OpenAIChatBackend(
            model_key=key,
            model=spec["model"],
            client=_openai_api_client(),
            temperature=spec.get("temperature", 0),
            extra_params=_chat_extra_params(spec),
            reasoning_mode=spec.get("reasoning_mode"),
            system_prefix=spec.get("system_prefix"),
        )

    if provider == "vllm_chat":
        from src.backends.vllm_chat import build_vllm_backend

        if not base_url:
            base_url = os.environ.get("WAITI_VLLM_ENDPOINT") or os.environ.get("OPENAI_BASE_URL")
        if not base_url:
            raise RuntimeError(
                f"vllm_chat backend {key!r} requires --base-url (local vLLM endpoint)."
            )
        reasoning_source = "system_prompt" if spec.get("system_prefix") else "native"
        return build_vllm_backend(
            model_key=key,
            served_model_name=spec["served_model_name"],
            base_url=base_url,
            temperature=spec.get("temperature", 0),
            extra_params=_chat_extra_params(spec),
            reasoning_mode=spec.get("reasoning_mode"),
            reasoning_control_source=reasoning_source,
            system_prefix=spec.get("system_prefix"),
        )

    raise ValueError(f"Unknown provider {provider!r} for model {key!r}")


def _chat_extra_params(spec: dict[str, Any]) -> dict[str, Any]:
    """Map model.yaml fields to chat.completions.create kwargs."""
    extra: dict[str, Any] = {}
    for src_key in ("top_p", "seed", "reasoning_effort"):
        if src_key in spec and spec[src_key] is not None:
            extra[src_key] = spec[src_key]
    if spec.get("extra_body"):
        extra["extra_body"] = spec["extra_body"]
    return extra


def _require_openai_key() -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key or key == "EMPTY" or key.startswith("sk-your"):
        raise RuntimeError(
            "A real OPENAI_API_KEY is required for OpenAI API models/judges "
            "(found unset, the vLLM placeholder 'EMPTY', or the '.env' example "
            "placeholder 'sk-your-...'). Set OPENAI_API_KEY in the environment "
            "or in a local .env file (never commit secrets)."
        )
    return key


def _openai_api_client():
    """Build an OpenAI client pinned to the real API endpoint.

    The SDK otherwise inherits OPENAI_BASE_URL from the environment, which may
    point at a local vLLM server. API models/judges must never route there, so
    the base_url is set explicitly.
    """
    from openai import OpenAI

    return OpenAI(
        api_key=_require_openai_key(),
        base_url=os.environ.get("OPENAI_API_BASE_OVERRIDE", "https://api.openai.com/v1"),
    )
