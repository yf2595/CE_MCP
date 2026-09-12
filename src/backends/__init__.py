"""Model backends for the AIDC CE-MCP revision.

Provides one normalized interface over:
  - OpenAI Responses API (GPT-5.4, reasoning.effort=low)  -> openai_responses.py
  - OpenAI Chat Completions (retained GPT-4.1)             -> openai_chat.py
  - Local vLLM OpenAI-compatible endpoint (open weights)   -> vllm_chat.py

The primary experiment logic consumes only `NormalizedModelTurn`. For backward
compatibility, `src/agents/base.py` wraps a turn in a ChatCompletion-compatible
shim so the existing agents/gates keep working unchanged.
"""
