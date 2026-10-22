"""
Consequence precision: adding to a function's own working list and a front
end calling its own backend are not consequential actions.
"""
from x_verba.engine import _is_same_origin_fetch, _mutates_local_container


def _lines(text):
    return text.strip("\n").splitlines()


def test_append_to_list_created_in_same_function_is_not_a_mutation():
    lines = _lines('''
def build(rows):
    out = []
    for row in rows:
        out.append(row)
    return out
''')
    assert _mutates_local_container(lines, 4, lines[3].strip())


def test_append_to_attribute_or_parameter_still_counts():
    lines = _lines('''
def save(self, items, row):
    self.items.append(row)
    items.append(row)
''')
    assert not _mutates_local_container(lines, 2, lines[1].strip())
    assert not _mutates_local_container(lines, 3, lines[2].strip())


def test_list_created_in_another_function_still_counts():
    lines = _lines('''
def make():
    out = []

def add(row):
    out.append(row)
''')
    assert not _mutates_local_container(lines, 5, lines[4].strip())


def test_relative_fetch_is_same_origin():
    line = 'const r = await fetch("/api/patients");'
    assert _is_same_origin_fetch([line], line)


def test_absolute_and_protocol_relative_fetch_are_external():
    for line in ['fetch("https://api.example.com/x")', 'fetch("//cdn.example.com/x")']:
        assert not _is_same_origin_fetch([line], line)


def test_fetch_through_constant():
    call = "fetch(`${API_BASE}${path}`, {"
    same = [
        "const API_BASE = '/api';",
        'const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";',
        'const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";',
    ]
    for decl in same:
        assert _is_same_origin_fetch([decl, call], call), decl
    external = 'const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";'
    assert not _is_same_origin_fetch([external, call], call)


def test_try_finally_is_not_a_silent_failure(tmp_path):
    from x_verba.engine import ScanEngine

    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "def run(lock):\n"
        "    lock.acquire()\n"
        "    try:\n"
        "        return client.chat.completions.create(model='m', messages=[])\n"
        "    finally:\n"
        "        lock.release()\n"
        "\n"
        "def swallow():\n"
        "    try:\n"
        "        return client.chat.completions.create(model='m', messages=[])\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    results = ScanEngine().scan(str(tmp_path))
    locations = [t["location"].replace("\\", "/") for t in results["terminal_states"]]
    assert locations == ["app.py:12"]
