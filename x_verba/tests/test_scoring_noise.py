"""
Scoring noise (0.7.1): things that were read as checkpoints, consequences or
missing model calls when they aren't, found by scanning public agent repos
(TradingAgents, TaskWeaver, AutoGPT).
"""
from textwrap import dedent

from x_verba.engine import (
    ASTAnalyser,
    ScanEngine,
    _assess_pre_node_strength,
    _find_caller_guard,
    _find_decorator_guard,
    _find_preceding_guard,
    _has_authorisation_gate,
    _link_gaps_to_breakdown,
    _mutates_local_container,
)


def _lines(text):
    return dedent(text).strip("\n").splitlines()


# ── Decorators ───────────────────────────────────────────────────────────────

def test_registering_and_utility_decorators_are_not_checkpoints():
    for decorator in ["@tool", "@func_retry", "@asynccontextmanager", "@dataclass",
                      '@router.post("/run")', "@main.command()", "@traceable"]:
        lines = _lines(f'''
            {decorator}
            def act(x):
                return send(x)
        ''')
        assert _find_decorator_guard(lines, 3) is None, decorator


def test_decorators_that_name_a_check_still_count():
    for decorator in ["@require_permission('orders')", "@validate_input", "@rate_limit(5)",
                      "@auth.requires_role('admin')", "@consent_gate"]:
        lines = _lines(f'''
            {decorator}
            def act(x):
                return send(x)
        ''')
        assert _find_decorator_guard(lines, 3) is not None, decorator


def test_tool_function_has_no_checkpoint_from_its_tool_decorator():
    lines = _lines('''
        @tool
        def get_news(ticker: str) -> str:
            """Fetch news."""
            return fetch_news(ticker)
    ''')
    assert _assess_pre_node_strength(lines, 3) is None


# ── Comments and docstrings ──────────────────────────────────────────────────

def test_keyword_in_docstring_or_comment_is_not_evidence():
    lines = _lines('''
        def run(cmd):
            """Display auto-approved command execution."""
            # confirm with the user later
            return execute(cmd)
    ''')
    assert _assess_pre_node_strength(lines, 4) is None
    assert not _has_authorisation_gate(lines, 4)


def test_keyword_in_code_still_counts():
    lines = _lines('''
        def run(cmd, user_confirmed):
            ok = user_confirmed
            return execute(cmd)
    ''')
    assert _has_authorisation_gate(lines, 3)
    pre_node = _assess_pre_node_strength(lines, 3)
    assert pre_node is not None and pre_node["type"] == "legacy_keyword"


def test_multiline_docstring_is_skipped():
    lines = _lines('''
        def run(cmd):
            """
            Callers must approve this first.
            """
            return execute(cmd)
    ''')
    assert not _has_authorisation_gate(lines, 5)


# ── Conditions that check nothing ────────────────────────────────────────────

def test_main_and_type_checking_blocks_are_not_guards():
    for condition in ['__name__ == "__main__"', "__name__ == '__main__'", "TYPE_CHECKING",
                      "typing.TYPE_CHECKING"]:
        lines = _lines(f'''
            if {condition}:
                os.remove(path)
        ''')
        assert _find_preceding_guard(lines, 2) is None, condition


def test_ordinary_condition_is_still_a_guard():
    lines = _lines('''
        if not allowed:
            raise PermissionError()
        os.remove(path)
    ''')
    assert _find_preceding_guard(lines, 3) is not None


# ── Local containers ─────────────────────────────────────────────────────────

def test_tuple_unpacked_local_container_is_not_a_mutation():
    lines = _lines('''
        def grid(start):
            dates, cursor = [], start
            while cursor:
                dates.append(cursor)
            return dates
    ''')
    assert _mutates_local_container(lines, 4, lines[3].strip())


def test_copied_container_and_own_kwargs_are_local():
    lines = _lines('''
        def call(params, **kwargs):
            api_params = params.copy()
            api_params.pop("entitlement", None)
            kwargs.pop("name", None)
    ''')
    assert _mutates_local_container(lines, 3, lines[2].strip())
    assert _mutates_local_container(lines, 4, lines[3].strip())


def test_tuple_unpacked_non_container_still_counts():
    lines = _lines('''
        def grid(store, start):
            dates, cursor = store.dates, start
            dates.append(cursor)
    ''')
    assert not _mutates_local_container(lines, 3, lines[2].strip())


# ── Model calls through an llm object ────────────────────────────────────────

def _ai_calls(source):
    return [c["call"] for c in ASTAnalyser().analyse(dedent(source), "a.py")["ai_calls"]]


def test_llm_runnable_calls_are_model_calls():
    calls = _ai_calls('''
        def create_researcher(llm):
            def node(state):
                return llm.invoke(state["prompt"])
            return node

        def structured(structured_llm, prompt):
            return structured_llm.invoke(prompt)

        class Agent:
            async def step(self, msgs):
                return await self.llm.ainvoke(msgs)

        def take_turn(prompt, llm, tools, messages):
            if not tools:
                return (prompt | llm).invoke(messages)
            return (prompt | llm.bind_tools(tools)).invoke(messages)
    ''')
    assert calls.count("llm.invoke") >= 2
    assert "structured_llm.invoke" in calls
    assert "self.llm.ainvoke" in calls


def test_other_invoke_calls_are_not_model_calls():
    calls = _ai_calls('''
        def run(graph, session, client, inputs):
            graph.invoke(inputs)
            session.invoke("x")
            client.stream(inputs)
            (step_a | step_b).invoke(inputs)
    ''')
    assert calls == []


# ── Caller guards ────────────────────────────────────────────────────────────

def test_def_line_and_same_named_method_are_not_callers():
    lines = _lines('''
        def start():
            pid = get_pid()
            if pid and exists(pid):
                exit(1)
            elif pid:
                print("stale")
                MainApp().start(background=True)
            os.remove(path)
    ''')
    # The only "calls" to start() are its own def line and a different
    # object's .start(): neither is a caller of this function.
    assert _find_caller_guard(lines, 8) is None


def test_real_bare_caller_behind_a_guard_still_counts():
    lines = _lines('''
        def outer(result):
            def save_cache():
                write_cache()
            if result is not None:
                save_cache()
    ''')
    assert _find_caller_guard(lines, 3) is not None


def test_method_called_on_an_instance_still_counts_with_multiline_class_header():
    lines = _lines('''
        class Component(
            Base,
        ):
            def run(self, url):
                if url:
                    return self.generate(url)

            def generate(
                self,
                url,
            ):
                return post(url)
    ''')
    assert _find_caller_guard(lines, 12) is not None


# ── Gaps linked to the breakdown ─────────────────────────────────────────────

def test_gaps_record_their_decision_point():
    breakdown = [
        {"location": "app\\a.py:10", "action_location": "app/a.py:12", "governed": True},
        {"location": "app\\b.py:5", "action_location": None, "governed": False},
    ]
    gaps = [
        {"location": "app/a.py:12"},   # an action: matched through action_location
        {"location": "app\\b.py:5"},   # a model call: matched on its own line
        {"location": "app/c.py:1"},    # e.g. an informal invariant: no decision point
    ]
    _link_gaps_to_breakdown(gaps, breakdown)
    assert gaps[0]["decision_location"] == "app\\a.py:10" and gaps[0]["decision_governed"] is True
    assert gaps[1]["decision_location"] == "app\\b.py:5" and gaps[1]["decision_governed"] is False
    assert gaps[2]["decision_location"] is None and gaps[2]["decision_governed"] is None


# ── End to end ───────────────────────────────────────────────────────────────

def test_langgraph_style_agent_counts_its_model_calls(tmp_path):
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "researcher.py").write_text(dedent('''
        def create_researcher(llm):
            def node(state):
                response = llm.invoke(state["prompt"])
                return {"answer": response.content}
            return node
    ''').lstrip(), encoding="utf-8")
    (tmp_path / "agents" / "tools.py").write_text(dedent('''
        from langchain_core.tools import tool

        @tool
        def get_news(ticker: str) -> str:
            """Fetch news for a ticker."""
            return fetch_news(ticker)
    ''').lstrip(), encoding="utf-8")
    results = ScanEngine().scan(str(tmp_path))
    actions = results["summary"]["agent_actions"]
    assert actions["model_calls"]["total"] == 1
    assert actions["tools"]["total"] == 1
    tool_item = next(i for i in results["gamma_breakdown"] if i["kind"] == "agent_tool")
    assert tool_item["checkpoint"] is None  # @tool is not a checkpoint
    for gap in results["gaps"]:
        assert "decision_location" in gap and "decision_governed" in gap
