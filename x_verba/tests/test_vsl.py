"""
VSL gate recognition (x_verba/vsl.py) and agent actions as consequential
decision points (0.7.0).

Each test writes a small agent repo to a temp folder and scans it with the
real engine. The same agent appears without and with VSL gates, so the tests
pin down exactly what VSL earns in the scorecard.
"""
from pathlib import Path
from textwrap import dedent

import pytest

from x_verba.engine import ScanEngine

TOOLS = '''
    from langchain_core.tools import tool

    from app import store


    @tool
    def lookup_order(order_id: str) -> str:
        """Look up an order."""
        if not order_id:
            return "missing id"
        return store.get(order_id)


    @tool
    def issue_refund(order_id: str, amount: float) -> str:
        """Issue a refund."""
        if amount <= 0:
            return "invalid amount"
        return store.refund(order_id, amount)


    TOOLS = [lookup_order, issue_refund]
'''

STORE = '''
    _orders = {}


    def get(order_id):
        if order_id in _orders:
            return _orders[order_id]
        return "not found"


    def refund(order_id, amount):
        # Same name as the tool above, in an unrelated module: never credited.
        if order_id not in _orders:
            return "not found"
        _orders[order_id]["refunded"] = amount
        return "ok"
'''

UNGOVERNED_GRAPH = '''
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition

    from app.tools import TOOLS

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0).bind_tools(TOOLS)


    async def call_agent(state):
        return {"messages": [await model.ainvoke(state["messages"])]}


    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_agent)
    builder.add_node("tools", ToolNode(TOOLS))
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition)
    builder.add_edge("tools", "agent")
    graph = builder.compile()
'''

GOVERNANCE = '''
    from vsl_core import AssuranceBasis, F2Modification, GammaEstimate, Invariant, PreNode
    from vsl_langgraph import LangGraphAdapter


    async def refund_headroom(state):
        """PreNode monitor: refund amount against the policy limit."""
        calls = state["messages"][-1].tool_calls
        amount = sum(c["args"].get("amount", 0) for c in calls)
        if amount <= 0:
            return GammaEstimate(gamma_hat=2.0)
        return GammaEstimate(gamma_hat=500.0 / amount)


    async def request_in_scope(state):
        """PreNode monitor before the model call."""
        text = state["messages"][-1].content
        if "password" in text:
            return GammaEstimate(gamma_hat=0.0)
        return GammaEstimate(gamma_hat=2.0)


    async def answer_is_safe(state):
        """Invariant rule: no card numbers in the answer."""
        return "card number" not in state["messages"][-1].content


    adapter = LangGraphAdapter()
    model_gate = adapter.compile_pre_node(PreNode(
        name="request-in-scope", description="...", monitor=request_in_scope,
        assurance_basis=AssuranceBasis(f1_pre_commitment=True, f2_modification=F2Modification.PARTIAL),
    ))
    tool_gate = adapter.compile_pre_node(PreNode(
        name="refund-within-policy", description="...", monitor=refund_headroom,
        assurance_basis=AssuranceBasis(f1_pre_commitment=True, f2_modification=F2Modification.NONE),
    ))
    answer_gate = adapter.compile_invariant(Invariant(
        name="no-card-numbers", description="...", rule=answer_is_safe,
        assurance_basis=AssuranceBasis(f1_pre_commitment=True, f2_modification=F2Modification.NONE),
    ))
'''

GOVERNED_GRAPH = '''
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition
    from vsl_langgraph import gated_node, route_on_denial

    from app.governance import answer_gate, model_gate, tool_gate
    from app.tools import TOOLS

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0).bind_tools(TOOLS)
    tool_node = ToolNode(TOOLS)


    async def call_agent(state):
        return {"messages": [await model.ainvoke(state["messages"])]}


    async def run_tools(state):
        return await tool_node.ainvoke(state)


    def release(state):
        return {}


    builder = StateGraph(MessagesState)
    builder.add_node("agent", gated_node(model_gate, call_agent))
    builder.add_node("tools", gated_node(tool_gate, run_tools))
    builder.add_node("release", gated_node(answer_gate, release))
    builder.add_node("blocked", lambda state: {})
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: "release"})
    builder.add_edge("tools", "agent")
    builder.add_conditional_edges("release", route_on_denial("blocked", END))
    graph = builder.compile()
'''


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text).lstrip(), encoding="utf-8")
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def ungoverned(tmp_path_factory):
    root = _write(tmp_path_factory.mktemp("ungoverned"), {
        "app/tools.py": TOOLS, "app/store.py": STORE, "app/graph.py": UNGOVERNED_GRAPH,
    })
    return ScanEngine().scan(str(root))


@pytest.fixture(scope="module")
def governed(tmp_path_factory):
    root = _write(tmp_path_factory.mktemp("governed"), {
        "app/tools.py": TOOLS, "app/store.py": STORE, "app/graph.py": GOVERNED_GRAPH,
        "app/governance.py": GOVERNANCE,
    })
    return ScanEngine().scan(str(root))


def _actions(results):
    return results["summary"]["agent_actions"]


def _dp(results, suffix):
    return next(d for d in results["primitives"]["decision_points"] if d["location"].replace("\\", "/").endswith(suffix))


# ── Agent actions count, with or without VSL ───────────────────────────────


def test_tools_and_model_calls_are_agent_actions(ungoverned):
    actions = _actions(ungoverned)
    assert actions["tools"] == {"governed": 0, "total": 2}
    assert actions["model_calls"] == {"governed": 0, "total": 1}
    types = {d["type"] for d in ungoverned["primitives"]["decision_points"]}
    assert {"agent_tool_call", "model_call"} <= types


def test_ungoverned_agent_has_no_vsl_section(ungoverned):
    assert ungoverned["vsl"]["detected"] is False
    assert ungoverned["summary"]["vsl"] == {
        "detected": False, "gates_total": 0, "gates_by_kind": {}, "human_authorisations": [],
    }


# ── VSL gates are recognised and credited ──────────────────────────────────


def test_vsl_gates_are_recognised(governed):
    vsl = governed["vsl"]
    assert vsl["detected"] is True
    assert vsl["gates_by_kind"] == {"PreNode": 2, "Invariant": 1}
    assert {g["name"] for g in vsl["gates"]} == {"request-in-scope", "refund-within-policy", "no-card-numbers"}
    assert vsl["records_gate_decisions"] is False
    assert "not verify" in vsl["note"]


def test_gated_tools_and_model_call_are_governed(governed):
    assert _actions(governed)["tools"] == {"governed": 2, "total": 2}
    assert _actions(governed)["model_calls"] == {"governed": 1, "total": 1}
    tool_dp = _dp(governed, "app/tools.py:15")  # issue_refund's def line
    assert tool_dp["pre_node"]["type"] == "vsl_gate"
    assert "refund-within-policy" in tool_dp["pre_node"]["evidence_line"]


def test_vsl_raises_structural_gamma(ungoverned, governed):
    before = ungoverned["summary"]["structural_gamma"]
    after = governed["summary"]["structural_gamma"]
    assert after > before


def test_handovers_into_gated_nodes_are_governed(governed):
    into = {h["to_agent"]: h["pre_node_exists"] for h in governed["primitives"]["agent_handovers"]}
    assert into.get("agent") is True  # START -> agent, gated by request-in-scope


def test_same_named_helper_in_another_module_is_not_credited(governed):
    gated = governed["vsl"]["gated"]
    assert "app/tools.py:issue_refund" in gated
    assert "app/store.py:refund" not in gated
    assert not any(s.startswith("app/store.py:") for s in gated)


def test_gate_monitors_and_rules_count_as_governance_logic(governed):
    dp = _dp(governed, "app/governance.py:9")  # `if amount <= 0:` inside refund_headroom
    assert dp["pre_node"]["type"] == "vsl_gate"
    assert "its own check" in dp["pre_node"]["evidence_line"]


def test_scorecard_states_what_is_not_verified(governed):
    from x_verba.engine import _agent_action_lines

    lines = "\n".join(_agent_action_lines(governed["summary"]))
    assert "Agent Actions Governed:            3 / 3" in lines
    assert "VSL Gates Recognised:              3" in lines
    assert "Not verified" in lines


# ── vsl-langchain middleware ───────────────────────────────────────────────


def test_vsl_tool_middleware_gates_named_tools(tmp_path):
    root = _write(tmp_path, {
        "app/tools.py": TOOLS, "app/store.py": STORE,
        "app/agent.py": '''
            from langchain.agents import create_agent
            from langchain_openai import ChatOpenAI
            from vsl_core import AssuranceBasis, F2Modification, PreNode
            from vsl_langchain import LangChainAdapter, VSLToolMiddleware

            from app.tools import issue_refund, lookup_order


            async def headroom(request):
                return request


            refund_gate = LangChainAdapter().compile_pre_node(PreNode(
                name="refund-within-policy", description="...", monitor=headroom,
                assurance_basis=AssuranceBasis(f1_pre_commitment=True, f2_modification=F2Modification.NONE),
            ))
            agent = create_agent(
                ChatOpenAI(model="gpt-4o-mini"),
                tools=[issue_refund, lookup_order],
                middleware=[VSLToolMiddleware({"issue_refund": refund_gate})],
            )
        ''',
    })
    results = ScanEngine().scan(str(root))
    assert results["vsl"]["gated_tools"] == ["issue_refund"]
    assert _actions(results)["tools"] == {"governed": 1, "total": 2}
