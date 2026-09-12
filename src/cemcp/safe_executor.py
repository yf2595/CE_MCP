"""AST allowlist interpreter for CE-MCP programs (never uses exec)."""

from __future__ import annotations

import ast
from typing import Any, Callable

from src.cemcp.parser import ParseError, parse_program
from src.cemcp.program_schema import ALLOWED_CALLS, MAX_LOOP_ITERS, MAX_STEPS
from src.lab.safety_guard import FORBIDDEN_BUILTINS, FORBIDDEN_MODULES, HostSafetyError


class ExecutionError(RuntimeError):
    pass


class SafeExecutor:
    def __init__(
        self,
        call_tool: Callable[[str, dict[str, Any]], Any],
        *,
        max_steps: int = MAX_STEPS,
    ) -> None:
        self.call_tool_fn = call_tool
        self.max_steps = max_steps
        self.steps = 0
        self.env: dict[str, Any] = {}

    def execute(self, source: str) -> Any:
        tree = parse_program(source)
        self._check_forbidden(tree)
        self.steps = 0
        self.env = {}
        for stmt in tree.body:
            self._exec_stmt(stmt)
        if "final" not in self.env:
            raise ExecutionError("program did not assign final")
        return self.env["final"]

    def _tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise ExecutionError("max_program_steps exceeded")

    def _check_forbidden(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                raise HostSafetyError("import is forbidden")
            if isinstance(node, ast.While):
                raise HostSafetyError("while loops are forbidden")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                raise HostSafetyError("function/class definitions are forbidden")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in FORBIDDEN_BUILTINS:
                    raise HostSafetyError(f"forbidden call: {node.func.id}")
            if isinstance(node, ast.Name) and node.id in FORBIDDEN_MODULES:
                raise HostSafetyError(f"forbidden name: {node.id}")
            if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                raise HostSafetyError("dunder attribute access forbidden")

    def _exec_stmt(self, stmt: ast.stmt) -> None:
        self._tick()
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                raise ExecutionError("only simple name assignment allowed")
            self.env[stmt.targets[0].id] = self._eval(stmt.value)
        elif isinstance(stmt, ast.AugAssign):
            raise ExecutionError("augassign not allowed")
        elif isinstance(stmt, ast.If):
            if self._truth(self._eval(stmt.test)):
                for s in stmt.body:
                    self._exec_stmt(s)
            else:
                for s in stmt.orelse:
                    self._exec_stmt(s)
        elif isinstance(stmt, ast.For):
            if not isinstance(stmt.target, ast.Name):
                raise ExecutionError("for target must be a name")
            iterable = self._eval(stmt.iter)
            if not isinstance(iterable, (list, tuple, range)):
                raise ExecutionError("for iterable must be list/tuple/range")
            count = 0
            for item in iterable:
                count += 1
                if count > MAX_LOOP_ITERS:
                    raise ExecutionError("loop iteration cap exceeded")
                self.env[stmt.target.id] = item
                for s in stmt.body:
                    self._exec_stmt(s)
        elif isinstance(stmt, ast.Expr):
            self._eval(stmt.value)
        elif isinstance(stmt, ast.Pass):
            return
        else:
            raise ExecutionError(f"disallowed statement: {type(stmt).__name__}")

    def _eval(self, node: ast.expr) -> Any:
        self._tick()
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            if node.id in {"True", "False", "None"}:
                return {"True": True, "False": False, "None": None}[node.id]
            raise ExecutionError(f"undefined name: {node.id}")
        if isinstance(node, ast.List):
            return [self._eval(elt) for elt in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return {self._eval(k): self._eval(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self._truth(self._eval(node.operand))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -self._eval(node.operand)
        if isinstance(node, ast.BinOp):
            left = self._eval(node.left)
            right = self._eval(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.Mod):
                return left % right
            raise ExecutionError("unsupported binop")
        if isinstance(node, ast.Compare):
            left = self._eval(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval(comparator)
                ok = self._compare(op, left, right)
                if not ok:
                    return False
                left = right
            return True
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                val = True
                for v in node.values:
                    val = self._truth(self._eval(v))
                    if not val:
                        return False
                return True
            if isinstance(node.op, ast.Or):
                for v in node.values:
                    if self._truth(self._eval(v)):
                        return True
                return False
        if isinstance(node, ast.Subscript):
            value = self._eval(node.value)
            sl = self._eval(node.slice)
            return value[sl]
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.JoinedStr):  # f-string
            raise ExecutionError("f-strings not allowed")
        raise ExecutionError(f"disallowed expression: {type(node).__name__}")

    def _call(self, node: ast.Call) -> Any:
        if not isinstance(node.func, ast.Name):
            raise ExecutionError("only simple function calls allowed")
        name = node.func.id
        if name not in ALLOWED_CALLS:
            raise ExecutionError(f"call not allowlisted: {name}")
        args = [self._eval(a) for a in node.args]
        kwargs = {kw.arg: self._eval(kw.value) for kw in node.keywords if kw.arg}
        if name == "call_tool":
            if len(args) == 1 and not kwargs:
                return self.call_tool_fn(str(args[0]), {})
            if len(args) == 2:
                tool, tool_args = args
                if not isinstance(tool_args, dict):
                    raise ExecutionError("call_tool args must be a dict")
                return self.call_tool_fn(str(tool), tool_args)
            if "name" in kwargs:
                return self.call_tool_fn(str(kwargs["name"]), dict(kwargs.get("args") or {}))
            raise ExecutionError("invalid call_tool signature")
        if name == "len":
            return len(args[0])
        if name == "sorted":
            return sorted(args[0])
        if name == "str":
            return str(args[0])
        if name == "int":
            return int(args[0])
        if name == "bool":
            return bool(args[0])
        if name == "list":
            return list(args[0])
        if name == "dict":
            return dict(args[0]) if args else {}
        raise ExecutionError(f"unhandled call: {name}")

    def _compare(self, op: ast.cmpop, left: Any, right: Any) -> bool:
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
        if isinstance(op, ast.In):
            return left in right
        if isinstance(op, ast.NotIn):
            return left not in right
        raise ExecutionError("unsupported compare")

    @staticmethod
    def _truth(value: Any) -> bool:
        return bool(value)
