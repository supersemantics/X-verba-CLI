"""
VSL gate recognition: identifies gates built with VSL (VERBA Specification
Language) and the code each one guards.

A VSL gate is declared once (``PreNode``/``Invariant`` from vsl-core),
compiled by a framework adapter (``compile_pre_node`` /
``compile_invariant``), and wired in front of the code it guards: a graph
node (``gated_node(gate, node)`` in vsl-langgraph), a tool
(``VSLToolMiddleware`` in vsl-langchain), or an explicit ``await gate(...)``.

One repo-wide pass over the parsed Python files records:

- every declared gate (``PreNode``/``Invariant``/``ClusterPreNode``), with
  its declared ``name``;
- every compiled gate variable;
- which functions run behind a gate: the node a ``gated_node`` wraps, tool
  functions run by a gated ``ToolNode``, tools gated by
  ``VSLToolMiddleware``, and the code after an explicit ``await gate(...)``;
- which graph nodes are gated (for agent handovers into them);
- whether a gated node invokes a model (for AI integrations);
- whether gate decisions are recorded (``write_gate_decision``);
- the graph nodes a denial is routed to (``route_on_denial``): governance's
  own response, not an ungated stage.

It also records human-authorisation mechanisms, with or without VSL: an
action that cannot run without a vsl-core ``HumanAuthorisedTransition``
(a parameter of that type), and LangGraph's human-in-the-loop
(``interrupt()``, ``interrupt_before``/``interrupt_after``).

The scan reads the wiring only; it does not evaluate the gates themselves.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VSL_MODULE_ROOTS = ("vsl_core", "vsl_langgraph", "vsl_langchain")
GATE_CONSTRUCTORS = {"PreNode": "PreNode", "Invariant": "Invariant", "ClusterPreNode": "PreNode"}
COMPILE_METHODS = {"compile_pre_node": "PreNode", "compile_invariant": "Invariant"}
MODEL_CALL_METHODS = {"invoke", "ainvoke", "stream", "astream", "batch", "abatch"}

# Strength given to a decision point / handover a VSL gate covers. Above
# GOVERNANCE_STRENGTH_THRESHOLD (0.7): a compiled gate is an enforced,
# pre-commitment check, the strongest shape X-Verba recognises.
VSL_GATE_STRENGTH = 0.9


@dataclass
class VslGate:
    kind: str  # "PreNode" or "Invariant"
    name: Optional[str]
    location: str


@dataclass
class _GatedScope:
    file: str
    function: str
    start: int
    end: int
    gate: str  # human-readable label of the gate covering it


@dataclass
class VslReport:
    detected: bool = False
    gates: List[VslGate] = field(default_factory=list)
    compiled_gates: Set[str] = field(default_factory=set)
    gated_scopes: List[_GatedScope] = field(default_factory=list)
    gated_graph_nodes: Dict[str, Dict[str, str]] = field(default_factory=dict)  # file -> {node: gate}
    gated_tools: Dict[str, str] = field(default_factory=dict)  # tool function -> gate
    gates_model_call: bool = False
    model_call_gate: Optional[str] = None  # label of the gate in front of the model call
    records_gate_decisions: bool = False
    denial_nodes: Dict[str, Dict[str, str]] = field(default_factory=dict)  # file -> {node: label}
    human_authorisations: List[Dict[str, str]] = field(default_factory=list)

    # ── queries the engine asks ──────────────────────────────────────────

    def covering_gate(self, rel_path: str, line: int) -> Optional[str]:
        """The gate covering ``rel_path:line``, if any."""
        rel = _norm(rel_path)
        for scope in self.gated_scopes:
            if scope.file == rel and scope.start <= line <= scope.end:
                return scope.gate
        return None

    def pre_node_for(self, rel_path: str, line: int) -> Optional[dict]:
        gate = self.covering_gate(rel_path, line)
        if gate is None:
            return None
        return {"type": "vsl_gate", "strength": VSL_GATE_STRENGTH, "evidence_line": gate}

    def gated_node_gate(self, rel_path: str, node_name: str) -> Optional[str]:
        return self.gated_graph_nodes.get(_norm(rel_path), {}).get(node_name)

    def denial_node(self, rel_path: str, node_name: str) -> Optional[str]:
        """The label for a graph node that only runs when a gate denies."""
        return self.denial_nodes.get(_norm(rel_path), {}).get(node_name)

    def to_dict(self) -> dict:
        by_kind: Dict[str, int] = {}
        for gate in self.gates:
            by_kind[gate.kind] = by_kind.get(gate.kind, 0) + 1
        return {
            "detected": self.detected,
            "gates_total": len(self.gates),
            "gates_by_kind": by_kind,
            "gates": [
                {"kind": g.kind, "name": g.name, "location": g.location} for g in self.gates
            ],
            "gated": sorted({f"{s.file}:{s.function}" for s in self.gated_scopes}),
            "gated_graph_nodes": sorted(
                f"{file}:{node}" for file, nodes in self.gated_graph_nodes.items() for node in nodes
            ),
            "gated_tools": sorted(self.gated_tools),
            "gates_model_call": self.gates_model_call,
            "records_gate_decisions": self.records_gate_decisions,
            "denial_nodes": sorted(
                f"{file}:{node}" for file, nodes in self.denial_nodes.items() for node in nodes
            ),
            "human_authorisations": list(self.human_authorisations),
            "note": (
                "VSL gates are credited as governance checkpoints from their wiring. "
                "This does not verify their declared F1/F2 assurance, their Gamma "
                "monitors, or that they fire at runtime."
            ),
        }


def _norm(path: str) -> str:
    return str(path).replace("\\", "/")


def _call_name(func: ast.AST) -> Optional[str]:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _imports_vsl(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in VSL_MODULE_ROOTS:
                return True
        elif isinstance(node, ast.Import):
            if any(a.name.split(".")[0] in VSL_MODULE_ROOTS for a in node.names):
                return True
    return False


def _gate_label(kind: str, name: Optional[str]) -> str:
    return f"VSL {kind} '{name}'" if name else f"VSL {kind}"


def _is_tool_function(fn: ast.AST) -> bool:
    """Decorated with LangChain's @tool (bare or called)."""
    for dec in getattr(fn, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        if _call_name(target) == "tool":
            return True
    return False


def _literal_name(call: ast.Call) -> Optional[str]:
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


class _File:
    def __init__(self, rel: str, tree: ast.AST):
        self.rel = rel
        self.tree = tree
        self.functions: Dict[str, ast.AST] = {}
        self.list_vars: Dict[str, List[str]] = {}
        self.imports: Dict[str, str] = {}  # local name -> "module.name"
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    names = [e.id for e in node.value.elts if isinstance(e, ast.Name)]
                    if names:
                        self.list_vars[node.targets[0].id] = names
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"


def _annotation_name(annotation: Optional[ast.AST]) -> Optional[str]:
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return annotation.value.rsplit(".", 1)[-1].strip()
    return _call_name(annotation) if annotation is not None else None


def _human_authorisations(f: _File) -> List[Dict[str, str]]:
    """Human-authorisation mechanisms in one file (see module docstring)."""
    found: List[Dict[str, str]] = []
    hat_imported = any(
        target.split(".")[0] in VSL_MODULE_ROOTS and target.endswith(".HumanAuthorisedTransition")
        for target in f.imports.values()
    )
    if hat_imported:
        for fn in f.functions.values():
            params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
            if any(_annotation_name(a.annotation) == "HumanAuthorisedTransition" for a in params):
                found.append({
                    "kind": "VSL Human-Authorised Transition",
                    "location": f"{f.rel}:{fn.lineno}",
                    "evidence": f"{fn.name}() requires a HumanAuthorisedTransition",
                })
    interrupt_name = next(
        (local for local, target in f.imports.items() if target == "langgraph.types.interrupt"), None
    )
    for node in ast.walk(f.tree):
        if not isinstance(node, ast.Call):
            continue
        if interrupt_name and isinstance(node.func, ast.Name) and node.func.id == interrupt_name:
            found.append({
                "kind": "LangGraph interrupt",
                "location": f"{f.rel}:{node.lineno}",
                "evidence": "interrupt() pauses the graph for a person",
            })
        elif _call_name(node.func) == "compile" and any(
            k.arg in ("interrupt_before", "interrupt_after") for k in node.keywords
        ) and any(t.startswith("langgraph.") for t in f.imports.values()):
            found.append({
                "kind": "LangGraph interrupt",
                "location": f"{f.rel}:{node.lineno}",
                "evidence": "graph compiled with interrupt_before/interrupt_after",
            })
    return found


def analyse(parsed_files: List[dict], base_path: Path) -> VslReport:
    """One repo-wide pass over the parsed Python files (see module docstring)."""
    report = VslReport()
    all_files: List[_File] = []
    files: List[_File] = []  # the ones that use VSL
    for fd in parsed_files:
        if fd.get("extension") != ".py":
            continue
        try:
            rel = _norm(Path(fd["path"]).relative_to(base_path))
        except ValueError:
            rel = _norm(fd["path"])
        try:
            tree = ast.parse(fd["content"])
        except (SyntaxError, ValueError, RecursionError):
            continue
        parsed = _File(rel, tree)
        all_files.append(parsed)
        report.human_authorisations.extend(_human_authorisations(parsed))
        if _imports_vsl(tree):
            report.detected = True
            files.append(parsed)
    if not report.detected:
        return report

    # Pass A: declared gates, compiled-gate variables, gate-decision records.
    # Declarations are read from every file first, so a gate compiled in one
    # file from a PreNode declared in another keeps its declared name.
    gate_kinds: Dict[str, str] = {}  # variable holding a gate (declared or compiled) -> label
    for f in files:
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in GATE_CONSTRUCTORS:
                    report.gates.append(VslGate(
                        kind=GATE_CONSTRUCTORS[name],
                        name=_literal_name(node),
                        location=f"{f.rel}:{node.lineno}",
                    ))
                if name == "write_gate_decision":
                    report.records_gate_decisions = True
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                target = node.targets[0] if node.targets else None
                name = _call_name(node.value.func)
                if isinstance(target, ast.Name) and name in GATE_CONSTRUCTORS:
                    gate_kinds[target.id] = _gate_label(GATE_CONSTRUCTORS[name], _literal_name(node.value))
    for f in files:
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                target = node.targets[0] if node.targets else None
                if not isinstance(target, ast.Name):
                    continue
                name = _call_name(node.value.func)
                if name in COMPILE_METHODS:
                    report.compiled_gates.add(target.id)
                    arg = node.value.args[0] if node.value.args else None
                    kind = COMPILE_METHODS[name]
                    label = gate_kinds.get(arg.id) if isinstance(arg, ast.Name) else None
                    if label is None and isinstance(arg, ast.Call):
                        label = _gate_label(kind, _literal_name(arg))
                    gate_kinds[target.id] = label or _gate_label(kind, arg.id if isinstance(arg, ast.Name) else None)

    def label_for(expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return gate_kinds.get(expr.id, f"VSL gate '{expr.id}'")
        return "VSL gate"

    # Tool lists, repo-wide by name (e.g. TOOLS = [search, create] in tools.py).
    tool_lists: Dict[str, Tuple[str, List[str]]] = {}  # list var -> (defining file, names)
    for f in all_files:
        for var, names in f.list_vars.items():
            tool_lists[var] = (f.rel, names)
    gated_tool_files: Dict[str, Set[str]] = {}  # tool name -> files it may be credited in

    def add_scope(f: _File, func_name: str, gate: str, start: Optional[int] = None, guards: bool = True) -> None:
        fn = f.functions.get(func_name)
        if fn is None:
            return
        report.gated_scopes.append(_GatedScope(
            file=f.rel, function=func_name,
            start=start or fn.lineno, end=getattr(fn, "end_lineno", fn.lineno), gate=gate,
        ))
        if guards and gate.startswith("VSL PreNode") and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in MODEL_CALL_METHODS
            for n in ast.walk(fn)
        ):
            report.gates_model_call = True
            report.model_call_gate = report.model_call_gate or gate

    # Pass B: what each gate guards.
    for f in files:
        tool_node_vars: Dict[str, List[str]] = {}
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _call_name(node.value.func) == "ToolNode" and node.value.args:
                    arg = node.value.args[0]
                    target = node.targets[0] if node.targets else None
                    if isinstance(target, ast.Name) and isinstance(arg, ast.Name) and arg.id in tool_lists:
                        tool_node_vars[target.id] = tool_lists[arg.id]

        for node in ast.walk(f.tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)

            # gated_node(gate, inner) — vsl-langgraph.
            if name == "gated_node":
                args = list(node.args)
                kw = {k.arg: k.value for k in node.keywords if k.arg}
                gate_expr = args[0] if args else kw.get("gate")
                inner = args[1] if len(args) > 1 else kw.get("node")
                if gate_expr is None or not isinstance(inner, ast.Name):
                    continue
                gate = label_for(gate_expr)
                add_scope(f, inner.id, gate)
                inner_fn = f.functions.get(inner.id)
                if inner_fn is not None:
                    for sub in ast.walk(inner_fn):
                        if isinstance(sub, ast.Name) and sub.id in tool_node_vars:
                            list_file, tools = tool_node_vars[sub.id]
                            for tool in tools:
                                report.gated_tools[tool] = gate
                                gated_tool_files.setdefault(tool, set()).add(list_file)

            # builder.add_node("name", gated_node(...)) — the graph node is gated.
            if name == "add_node" and len(node.args) >= 2:
                node_name, wrapped = node.args[0], node.args[1]
                if (
                    isinstance(node_name, ast.Constant) and isinstance(node_name.value, str)
                    and isinstance(wrapped, ast.Call) and _call_name(wrapped.func) == "gated_node"
                    and wrapped.args
                ):
                    report.gated_graph_nodes.setdefault(f.rel, {})[node_name.value] = label_for(wrapped.args[0])

            # route_on_denial("denial_node", ...) — vsl-langgraph: that node
            # only runs when a gate denies.
            if name == "route_on_denial" and node.args:
                target = node.args[0]
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    report.denial_nodes.setdefault(f.rel, {})[target.value] = (
                        f"VSL denial route to '{target.value}'"
                    )

            # VSLToolMiddleware({"tool": gate}) — vsl-langchain.
            if name == "VSLToolMiddleware":
                mapping = node.args[0] if node.args else next(
                    (k.value for k in node.keywords if k.arg == "gates_by_tool_name"), None)
                if isinstance(mapping, ast.Dict):
                    for key, value in zip(mapping.keys, mapping.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            report.gated_tools[key.value] = label_for(value)

        # await gate(...) inside a function — code after it is guarded.
        for fn_name, fn in f.functions.items():
            for sub in ast.walk(fn):
                if (
                    isinstance(sub, ast.Await) and isinstance(sub.value, ast.Call)
                    and isinstance(sub.value.func, ast.Name)
                    and sub.value.func.id in report.compiled_gates
                ):
                    add_scope(f, fn_name, label_for(sub.value.func), start=sub.lineno)

    # Gate monitors and rules are the governance check itself: code inside
    # them counts as governance logic, not as ungoverned decision points.
    by_module = {f.rel[:-3].replace("/", "."): f for f in all_files if f.rel.endswith(".py")}
    for f in files:
        for node in ast.walk(f.tree):
            if not (isinstance(node, ast.Call) and _call_name(node.func) in GATE_CONSTRUCTORS):
                continue
            kind = GATE_CONSTRUCTORS[_call_name(node.func)]
            label = f"{_gate_label(kind, _literal_name(node))} (its own check)"
            for kw in node.keywords:
                if kw.arg not in ("monitor", "rule") or not isinstance(kw.value, ast.Name):
                    continue
                name = kw.value.id
                if name in f.functions:
                    add_scope(f, name, label, guards=False)
                elif name in f.imports:
                    module, _, attr = f.imports[name].rpartition(".")
                    target = next(
                        (t for mod, t in by_module.items() if mod == module or mod.endswith("." + module)),
                        None,
                    )
                    if target is not None:
                        add_scope(target, attr, label, guards=False)

    # Credit each gated tool in the file that defines it: the file its tool
    # list lives in (ToolNode), or any file defining it as an @tool function
    # (VSLToolMiddleware names tools, not files). A same-named helper in an
    # unrelated module is not credited.
    for f in all_files:
        for tool, gate in report.gated_tools.items():
            fn = f.functions.get(tool)
            if fn is None:
                continue
            if f.rel in gated_tool_files.get(tool, set()) or _is_tool_function(fn):
                add_scope(f, tool, gate)

    return report
