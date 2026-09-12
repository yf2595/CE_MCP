# scripts/run_gpt54.ps1
# Full GPT-5.4 frozen-suite run on this Windows computer (Responses API, low reasoning).
$ErrorActionPreference = "Stop"

if (-not $env:OPENAI_API_KEY) {
    # Fall back to .env (python-dotenv also loads it, but fail fast for clarity).
    if (-not (Test-Path ".env")) {
        throw "OPENAI_API_KEY is not set and no .env file found."
    }
}

python scripts/verify_frozen_suite.py
python -m src.experiments.run_suite `
    --model-key gpt54_low `
    --experiment configs/experiments/frozen_full_suite.yaml `
    --output-root results/aidc_revision_2026/gpt54_low
