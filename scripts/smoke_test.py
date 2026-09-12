#!/usr/bin/env python
"""Smoke tests for lab tools, safe executor, and optional live agents."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.cemcp.safe_executor import SafeExecutor
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner


def test_tools() -> None:
    lab = LabState.create("smoke_tools")
    runner = LabToolRunner(lab)
    assert sorted(runner.call("query_users_by_door", {"door": "C"})) == ["Alice", "Emma"]
    assert runner.call("get_pass_by_name", {"name": "Emma"}) == "P100"
    assert runner.call("read_public_file", {"name": "door_c_report.txt"}).startswith("Door C")
    assert runner.call("sim_eval", {"payload": "x"})["simulated"] is True
    assert "eval" not in str(runner.call("sim_eval", {"payload": "x"}))
    print("OK tools")


def test_executor() -> None:
    lab = LabState.create("smoke_exec")
    runner = LabToolRunner(lab)
    program = '''
users = call_tool("query_users_by_door", {"door": "C"})
final = {"answer": users}
'''
    out = SafeExecutor(lambda n, a: runner.call(n, a)).execute(program)
    assert out["answer"] == ["Alice", "Emma"]
    print("OK executor")


def test_fastmcp_import() -> None:
    from src.mcp_server.server import mcp

    assert mcp is not None
    print("OK fastmcp import")


def test_live_clean(limit: int = 1) -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        print("SKIP live clean (no OPENAI_API_KEY)")
        return
    from src.attacks.clean_tasks import load_clean_tasks
    from src.evaluation.runner import load_experiment_config, run_clean_trial

    cfg = load_experiment_config()
    model = cfg["models"][0]
    for task in load_clean_tasks()[:limit]:
        rec = run_clean_trial(task, architecture="cemcp", defense="C0", agent_model=model, config=cfg)
        print(task["task_id"], rec.correct, rec.final_answer)
    print("OK live clean")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    test_tools()
    test_executor()
    test_fastmcp_import()
    if args.live:
        test_live_clean()
    print("smoke_test passed")


if __name__ == "__main__":
    main()
