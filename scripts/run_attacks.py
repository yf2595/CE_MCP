#!/usr/bin/env python
"""Run adversarial attack evaluation stages."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.attacks.definitions import ATTACK_DEFINITIONS
from src.attacks.expansion import expand_attack_trials
from src.common.logging import setup_logging
from src.common.utils import RESULTS_DIR, ensure_dir, load_yaml, sha256_file
from src.evaluation.runner import load_experiment_config, run_attack_trial

PAPER_FOUR = ["P1.1", "P2.1", "P3.2", "P4.3"]


def write_metadata(cfg: dict) -> Path:
    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "experiment_config_hash": sha256_file(ROOT / "configs" / "experiment.yaml"),
        "attack_manifest_hash": sha256_file(ROOT / "configs" / "attacks.yaml"),
        "config": cfg,
    }
    try:
        import mcp
        import openai

        meta["mcp_version"] = getattr(mcp, "__version__", "unknown")
        meta["openai_version"] = getattr(openai, "__version__", "unknown")
    except Exception:
        pass
    path = ensure_dir(RESULTS_DIR) / "experiment_metadata.json"
    path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stage",
        choices=["paper4", "pilot", "c0_all16", "full", "custom"],
        default="pilot",
    )
    parser.add_argument("--attacks", nargs="*", default=None)
    parser.add_argument("--seeds", type=int, default=None)
    parser.add_argument("--variants", type=int, default=None)
    parser.add_argument("--architecture", default="both", choices=["cemcp", "traditional_mcp", "both"])
    parser.add_argument("--defense", default=None, help="C0/C1/C2 or comma list")
    parser.add_argument("--model", default="all")
    parser.add_argument(
        "--output",
        default=None,
        help="Path to trials JSONL (default: results/raw/trials.jsonl)",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="Optional results filename tag, e.g. v2 -> trials_pilot_v2.jsonl",
    )
    args = parser.parse_args()
    log = setup_logging()
    cfg = load_experiment_config()
    write_metadata(cfg)

    results_path = Path(args.output) if args.output else (RESULTS_DIR / "raw" / "trials.jsonl")
    if args.stage == "pilot" and args.output is None:
        tag = args.tag or "pilot"
        results_path = RESULTS_DIR / "raw" / f"trials_{tag}.jsonl"
    ensure_dir(results_path.parent)

    n_seeds = args.seeds
    n_variants = args.variants
    attack_ids = args.attacks

    if args.stage == "paper4":
        attack_ids = PAPER_FOUR
        n_seeds = n_seeds or 1
        n_variants = n_variants or 1
        defenses = ["C0"]
        arches = ["cemcp", "traditional_mcp"]
    elif args.stage == "c0_all16":
        attack_ids = list(ATTACK_DEFINITIONS)
        n_seeds = n_seeds or 1
        n_variants = n_variants or 3
        defenses = ["C0"]
        arches = ["cemcp"]
    elif args.stage == "pilot":
        attack_ids = list(ATTACK_DEFINITIONS)
        n_seeds = n_seeds or 1
        n_variants = n_variants or 3
        defenses = ["C0", "C1", "C2"]
        arches = ["cemcp"]
    elif args.stage == "full":
        attack_ids = list(ATTACK_DEFINITIONS)
        n_seeds = n_seeds or int(cfg.get("attack_task_seeds", 10))
        n_variants = n_variants or int(cfg.get("attack_payload_variants", 3))
        defenses = list(cfg.get("ce_defenses", ["C0", "C1", "C2"]))
        arches = ["cemcp", "traditional_mcp"]
    else:
        attack_ids = attack_ids or list(ATTACK_DEFINITIONS)
        n_seeds = n_seeds or 1
        n_variants = n_variants or 1
        defenses = (args.defense or "C0").split(",")
        arches = ["cemcp", "traditional_mcp"] if args.architecture == "both" else [args.architecture]

    if args.defense:
        defenses = args.defense.split(",")
    if args.architecture != "both" and args.stage in {"full", "custom"}:
        arches = [args.architecture]

    models = cfg["models"] if args.model == "all" else [args.model]
    trials = expand_attack_trials(attack_ids, n_seeds=n_seeds, n_variants=n_variants)
    log.info("running %d trial specs", len(trials))

    for trial in trials:
        for arch in arches:
            if arch == "traditional_mcp":
                if not ATTACK_DEFINITIONS[trial["attack_id"]].get("mcp_comparable"):
                    continue
                # Traditional only under C0 for architectural comparison
                arch_defenses = ["C0"]
            else:
                arch_defenses = defenses
            for model in models:
                for defense in arch_defenses:
                    log.info(
                        "%s %s %s %s",
                        trial["trial_key"],
                        arch,
                        defense,
                        model,
                    )
                    run_attack_trial(
                        trial,
                        architecture=arch,
                        defense=defense,
                        agent_model=model,
                        config=cfg,
                        results_path=results_path,
                    )
    print("done")
    print("results:", results_path)


if __name__ == "__main__":
    main()
