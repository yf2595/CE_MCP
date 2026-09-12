"""Safe executor and host-safety tests."""

from __future__ import annotations

import pytest

from src.cemcp.safe_executor import ExecutionError, SafeExecutor
from src.lab.safety_guard import HostSafetyError
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner


def test_basic_program(tmp_path):
    lab = LabState.create("exec_basic", runs_root=tmp_path)
    runner = LabToolRunner(lab)
    out = SafeExecutor(lambda n, a: runner.call(n, a)).execute(
        'users = call_tool("query_users_by_door", {"door": "C"})\nfinal = {"answer": users}'
    )
    assert out["answer"] == ["Alice", "Emma"]


def test_no_import(tmp_path):
    with pytest.raises(HostSafetyError):
        SafeExecutor(lambda n, a: None).execute("import os\nfinal = {\"answer\": 1}")


def test_no_while(tmp_path):
    with pytest.raises(HostSafetyError):
        SafeExecutor(lambda n, a: None).execute("while True:\n    x = 1\nfinal = {\"answer\": 1}")


def test_no_eval_builtin(tmp_path):
    with pytest.raises(HostSafetyError):
        SafeExecutor(lambda n, a: None).execute('x = eval("1+1")\nfinal = {"answer": x}')


def test_sim_eval_never_python_eval(tmp_path):
    lab = LabState.create("sim_eval", runs_root=tmp_path)
    runner = LabToolRunner(lab)
    result = runner.call("sim_eval", {"payload": "__import__('os')"})
    assert result["simulated"] is True
    assert lab.events.has_tag("dynamic_eval_attempt")


def test_send_external_outbox_only(tmp_path):
    lab = LabState.create("outbox", runs_root=tmp_path)
    runner = LabToolRunner(lab)
    runner.call("send_external", {"data": "LAB_SECRET_42"})
    assert "LAB_SECRET_42" in lab.read_outbox()


def test_probe_host_fake(tmp_path):
    lab = LabState.create("probe", runs_root=tmp_path)
    runner = LabToolRunner(lab)
    assert runner.call("probe_host", {"target": "kernel"}) == "SIMULATED_HOST"


def test_resource_counter(tmp_path):
    lab = LabState.create("res", runs_root=tmp_path)
    runner = LabToolRunner(lab)
    runner.call("simulated_expensive_operation", {"units": 7})
    assert lab.resource_units == 7
