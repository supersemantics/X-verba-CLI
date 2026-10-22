"""
Human-authorisation mechanisms and VSL denial routes (x_verba/vsl.py).

A missing_human_gate gap is satisfied by a structural mechanism, not by a
keyword: an action that cannot run without a vsl-core
HumanAuthorisedTransition, or LangGraph's interrupt.
"""
import ast
from pathlib import Path
from textwrap import dedent

import pytest

from x_verba import vsl
from x_verba.engine import ScanEngine

GRAPH = '''
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, START, MessagesState, StateGraph

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0)


    async def call_agent(state):
        return {"messages": [await model.ainvoke(state["messages"])]}


    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_agent)
    builder.add_edge(START, "agent")
    builder.add_edge("agent", END)
    graph = builder.compile()
'''

APPROVAL_STORE = '''
    from vsl_core.governance import HumanAuthorisedTransition

    _orders = {}


    def send_order(order_id: str, transition: HumanAuthorisedTransition):
        _orders[order_id]["sent_by"] = transition.authorised_by
'''

INTERRUPT_GRAPH = '''
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.types import interrupt

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0)


    async def call_agent(state):
        return {"messages": [await model.ainvoke(state["messages"])]}


    def approve(state):
        decision = interrupt({"draft": state["messages"][-1].content})
        return {"approved": decision}


    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_agent)
    builder.add_node("approve", approve)
    builder.add_edge(START, "agent")
    builder.add_edge("agent", "approve")
    builder.add_edge("approve", END)
    graph = builder.compile()
'''


def _scan(root: Path, files: dict) -> dict:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text).lstrip(), encoding="utf-8")
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    return ScanEngine().scan(str(root))


def _human_gaps(results):
    return [g for g in results["gaps"] if g["type"] == "missing_human_gate"]


def _authorisations(source: str) -> list:
    return vsl._human_authorisations(vsl._File("app/x.py", ast.parse(dedent(source))))


def test_without_a_mechanism_the_gap_is_reported(tmp_path):
    results = _scan(tmp_path, {"app/graph.py": GRAPH})
    assert results["summary"]["vsl"]["human_authorisations"] == []
    assert len(_human_gaps(results)) == 1


def test_action_requiring_a_human_authorised_transition_satisfies_it(tmp_path):
    results = _scan(tmp_path, {"app/graph.py": GRAPH, "app/store.py": APPROVAL_STORE})
    (human,) = results["summary"]["vsl"]["human_authorisations"]
    assert human["kind"] == "VSL Human-Authorised Transition"
    assert human["location"].endswith("app/store.py:6")
    assert "send_order()" in human["evidence"]
    assert _human_gaps(results) == []


def test_langgraph_interrupt_satisfies_it(tmp_path):
    results = _scan(tmp_path, {"app/graph.py": INTERRUPT_GRAPH})
    (human,) = results["summary"]["vsl"]["human_authorisations"]
    assert human["kind"] == "LangGraph interrupt"
    assert _human_gaps(results) == []


def test_interrupt_before_at_compile_counts():
    found = _authorisations('''
        from langgraph.graph import StateGraph
        graph = StateGraph(dict).compile(interrupt_before=["send"])
    ''')
    assert [h["kind"] for h in found] == ["LangGraph interrupt"]


@pytest.mark.parametrize("source", [
    # Same class name, not vsl-core's.
    '''
    from myapp.approvals import HumanAuthorisedTransition

    def send(transition: HumanAuthorisedTransition): ...
    ''',
    # vsl-core's class imported but never required by an action.
    '''
    from vsl_core.governance import HumanAuthorisedTransition

    def send(order_id: str): ...
    ''',
    # A function named interrupt that is not LangGraph's.
    '''
    def interrupt(x): ...

    def node(state):
        interrupt(state)
    ''',
    # Keywords alone are not a mechanism.
    '''
    def send(order):
        # TODO: human review and approve before sending
        return order
    ''',
])
def test_lookalikes_do_not_count(source):
    assert _authorisations(source) == []


def test_route_on_denial_target_is_a_denial_node():
    source = dedent('''
        from langgraph.graph import END, StateGraph
        from vsl_langgraph import route_on_denial

        builder = StateGraph(dict)
        builder.add_conditional_edges("release", route_on_denial("blocked", END))
    ''')
    report = vsl.analyse([{"extension": ".py", "path": "app/graph.py", "content": source}], Path("."))
    assert report.denial_node("app/graph.py", "blocked") == "VSL denial route to 'blocked'"
    assert report.denial_node("app/graph.py", "release") is None


def test_gate_compiled_in_another_file_keeps_its_declared_name():
    gates = dedent('''
        from vsl_langgraph import LangGraphAdapter, gated_node
        from app.policies import consent_prenode

        consent_gate = LangGraphAdapter().compile_pre_node(consent_prenode)

        def run_tools(state):
            return state

        node = gated_node(consent_gate, run_tools)
    ''')
    policies = dedent('''
        from vsl_core import PreNode

        consent_prenode = PreNode(name="Patient Consent Tool Gate", description="...", monitor=None, assurance_basis=None)
    ''')
    # gates.py is read before policies.py, as in a sorted file walk.
    report = vsl.analyse(
        [
            {"extension": ".py", "path": "app/gates.py", "content": gates},
            {"extension": ".py", "path": "app/policies.py", "content": policies},
        ],
        Path("."),
    )
    assert report.covering_gate("app/gates.py", 8) == "VSL PreNode 'Patient Consent Tool Gate'"
