"""
X-Verba Scan Engine v0.2.0

AI-integration-centric governance analysis.

Governance gaps are only meaningful in the context of AI calls.
Non-AI code with file writes is a compiler.
AI code with ungated file writes is a Knight Capital.

Four passes:
  1. Primitive Detection — find AI calls (AST for Python, regex for JS/TS)
  2. DC Pattern Matching — map to Drift Class taxonomy
  3. Gap Analysis — Pre-Node, Human Gate, Invariant, Terminal State gaps
  4. Structural Gamma — governed / total decision points

Context profiles:
  ai-app        — full governance analysis, irreversible actions only when AI-adjacent (default)
  system-utility — suppresses IA-GAPs for local file ops in non-AI files
  general       — scan all files, legacy v0.1 behaviour

v0.2.0 changes:
  - Irreversible actions flagged only when AI-adjacent (fixes TypeScript false positive problem)
  - Context profile support via --context-profile flag
  - Fixed Gamma calculation (was always 0 for irreversible actions)
  - Robust error handling throughout (no more crash on malformed files)
  - ai_only mode: non-AI files skipped from governance analysis
"""
import os
import re
import ast
import json
import hashlib
import warnings
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import (
    TendencyState,
    EnhancedConsequence,
    AgentNode, AgentEdge, AgentGraph,
    DecisionNode, DecisionEdge, DecisionGraph,
    AIInventory, AgentInventory, DecisionInventory,
    GovernanceCoverage, TendencyIndicators, GammaValue, GammaVariants,
    PreNode, TerminalState, Invariant, GovernanceGap,
    EvidenceNode, Legion,
)
from .graph import pagerank as _pagerank, critical_path as _critical_path
from .graph import reachability_from as _reachability_from
from .graph import propagation_potential as _propagation_potential
from .graph import PAGERANK_DAMPING, PAGERANK_ITERATIONS
from . import vsl as _vsl

console = Console()


def _ast_parse_quiet(source: str, filepath: str):
    """ast.parse() with the scanned file's own path attached (so any
    SyntaxWarning points at the real file, not '<unknown>') and the
    scanned repo's own lint-level warnings suppressed — X-Verba reports
    structural governance gaps, not third-party code-quality issues."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source, filename=filepath)


TAXONOMY_PATH = Path(__file__).parent.parent / "taxonomy"

# v0.3.0 data files — Drift Class / Legion / Stabilisation Operator taxonomy
# and heuristic Legion detection patterns. Both live alongside engine.py.
DATA_PATH = Path(__file__).parent

# ── AI provider detection ─────────────────────────────────────────────────────
# Only actual LLM provider SDKs and their adapters.
# Agent frameworks (crewai, autogen, haystack) are NOT listed here —
# we detect them via their underlying LLM calls.

AI_PROVIDER_IMPORTS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google.generativeai": "google",
    "google.cloud.aiplatform": "google",
    "cohere": "cohere",
    "boto3": "aws_bedrock",
    "langchain_openai": "langchain",
    "langchain_anthropic": "langchain",
    "langchain_google_genai": "langchain",
    "langchain_cohere": "langchain",
    "langchain_community.llms": "langchain",
    "langchain_community.chat_models": "langchain",
    "llama_index.llms": "llama_index",
    # LlamaIndex's agent/workflow orchestration submodules — distinct from
    # llama_index.llms above; a framework partially recognised via one
    # submodule is not necessarily recognised via another.
    "llama_index.core.agent": "llama_index",
    "llama_index.core.workflow": "llama_index",
    "transformers": "huggingface",
    # Meta AI / Llama — direct SDKs and common Llama-hosting providers.
    "llama_api_client": "meta_llama",
    "llama_stack_client": "meta_llama",
    "replicate": "replicate",
    "together": "together_ai",
    # Modern LangChain (v1.x) top-level API — distinct from the legacy
    # langchain_openai/langchain_community.* surface above.
    "langchain.chat_models": "langchain",
    "langchain.agents": "langchain",
    # Google's Agent Development Kit and the newer unified Gemini SDK
    # (replacing google.generativeai).
    "google.adk": "google",
    "google.genai": "google",
    # Anthropic's own Claude Agent SDK (Python).
    "claude_agent_sdk": "anthropic",
    # AWS's own open-source agent framework — distinct from boto3 and from
    # bedrock_agentcore (a separate runtime/deployment SDK).
    "strands": "aws_bedrock",
    # Agency Swarm (VRSEN).
    "agency_swarm": "agency_swarm",
}

# Module names too generic to safelist outright as an AI-provider import —
# "agents" in particular could be an unrelated local package. Only registered
# as an AI import if the file's source also contains one of the listed
# corroborating call-site signals, confirming this really is the OpenAI
# Agents SDK and not a coincidentally named local module.
_GUARDED_PROVIDER_IMPORTS = {
    "agents": ("openai_agents_sdk", ("Agent(", "Runner.run(", "handoff(")),
}

# Raw-HTTP AI-provider calls — no SDK import, no distinctive method name,
# only a known provider hostname inside a generic fetch/httpx/requests/
# custom-wrapper HTTP call. Confirmed 3 times this session: JS `fetch()`
# (open-agent-sdk-typescript), Python `httpx` (omnigent), and a 20-file hit
# via a custom `fetchWithCache()` wrapper (promptfoo) — the wrapper
# function name is arbitrary and can't be enumerated; the hostname string
# literal is the only signal common to all three. Language-agnostic (plain
# string match), so this runs on every file regardless of extension.
_AI_PROVIDER_HOSTNAMES = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "api.cohere.com": "cohere",
    "api.together.xyz": "together_ai",
    "api.deepseek.com": "deepseek",
    "api.mistral.ai": "mistral",
    "generativelanguage.googleapis.com": "google",
    "api.groq.com": "groq",
    "api.perplexity.ai": "perplexity",
    "api.fireworks.ai": "fireworks",
    "openrouter.ai": "openrouter",
    "api.x.ai": "xai",
    "bedrock-runtime": "aws_bedrock",
}
_AI_HOSTNAME_RE = re.compile(
    r'https?://[\w.-]*(' + '|'.join(re.escape(h) for h in _AI_PROVIDER_HOSTNAMES) + r')'
)

# Corroboration: an AI-provider hostname string by itself isn't enough —
# confirmed false positive on a real repo where it was just a base_url
# preset *value* passed through to an externally-spawned process, never
# used to issue a request in that codebase at all (ClawTeam-OpenClaw's
# spawn/presets.py). Require the file to also contain some HTTP-call-
# shaped token somewhere — not necessarily near the URL (the 3 confirmed
# real positives all have the URL and the eventual call in different
# functions), just present *somewhere* in the file.
_HTTP_CALL_VERB_RE = re.compile(
    r'fetch\w*\s*\(|requests\.(get|post|put|delete)\s*\(|httpx\.|urlopen\s*\(|axios\.|urllib\.request'
)


def _detect_raw_http_ai_calls(content: str) -> list:
    """Scan a file's raw content for a known AI-provider hostname as a
    string literal, regardless of what function ultimately issues the
    HTTP call. Only meaningful as a fallback when normal import/pattern
    detection found nothing in this file (see call site).

    Second corroboration, beyond _HTTP_CALL_VERB_RE: requires exactly ONE
    distinct provider hostname in the whole file. Confirmed false positive
    on two real repos otherwise — a multi-provider preset/config list
    (ClawTeam-OpenClaw's spawn/presets.py, base_url values passed through
    to an externally-spawned process) and a multi-provider CLI menu
    (TradingAgents' cli/utils.py, a tuple list of provider display names)
    both had a corroborating HTTP-call verb present *somewhere* in the
    file, but were never themselves a real call site — they were
    enumerating multiple providers, not implementing one. Every confirmed
    real positive (omnigent, promptfoo) is a file dedicated to exactly one
    provider."""
    findings = []
    if not _HTTP_CALL_VERB_RE.search(content):
        return findings
    matches = []
    seen_providers = set()
    for m in _AI_HOSTNAME_RE.finditer(content):
        provider = _AI_PROVIDER_HOSTNAMES.get(m.group(1))
        if not provider:
            continue
        seen_providers.add(provider)
        if provider not in {p for p, _ in matches}:
            line_num = content[:m.start()].count("\n") + 1
            matches.append((provider, line_num))
    if len(seen_providers) != 1:
        return findings
    for provider, line_num in matches:
        findings.append({"line": line_num, "provider": provider})
    return findings

AI_CALL_METHODS = [
    "chat.completions.create", "completions.create",
    "ChatCompletion.create", "Completion.create",
    "client.chat", "openai.ChatCompletion",
    "messages.create", "client.messages",
    "anthropic.Anthropic", "AsyncAnthropic",
    "chain.run", "chain.invoke", "chain.stream",
    "agent.run", "agent.invoke",
    "LLMChain", "AgentExecutor",
    "ChatOpenAI", "ChatAnthropic", "ChatGoogleGenerativeAI",
    ".generate(", ".complete(", ".predict(",
    ".chat(", ".ask(", ".query(",
    "pipeline(", "AutoModelForCausalLM",
    "invoke_model(", "invoke_model_with_response_stream(",
]

# Method names generic enough to appear on non-AI objects (a DB client's
# .query(), an HTTP client's .complete()) — only count as an AI call if the
# call's root object is also a recognised AI import. See _identify_provider().
_GENERIC_AI_CALL_METHODS = {
    ".generate(", ".complete(", ".predict(",
    ".chat(", ".ask(", ".query(", "pipeline(",
}

# AI_CALL_METHODS entries that read as ordinary English on any "agent" or
# "chain" object with no LangChain involvement at all (an insurance/travel
# agent's .run(), a CI runner agent, a workflow "chain" object's .invoke()).
# Unlike _GENERIC_AI_CALL_METHODS above, these aren't gated on the call's
# own root being a recognised import — a bare local variable named `agent`
# or `chain` was never going to be import-tracked. Instead they require the
# whole file to show LangChain corroboration (see ASTAnalyser._langchain_corroborated).
_AMBIGUOUS_AI_CALL_METHODS = {
    "chain.run", "chain.invoke", "chain.stream",
    "agent.run", "agent.invoke",
}

# AI_CALL_METHODS entries generic enough to belong to an unrelated
# non-AI SDK's own API shape, keyed to which provider's import must be
# present somewhere in the file to corroborate them. Confirmed false
# positive: Twilio's Python SDK uses the identical call shape
# `client.messages.create(...)` for sending SMS — nothing to do with
# Anthropic at all, but "messages.create" alone reads as generically
# plausible AI vocabulary. "client.chat" is the same story for any
# chat-capable client object (support-desk SDKs, chat-bot frameworks)
# with no OpenAI involvement. Checked against self.ai_imports.values()
# (the file's own precisely-tracked imports) rather than a regex scan,
# since ASTAnalyser already collects that.
_PROVIDER_AMBIGUOUS_AI_CALL_METHODS = {
    "client.chat": "openai",
    "messages.create": "anthropic",
    "client.messages": "anthropic",
}


def _call_matches_pattern(call_str: str, pattern: str) -> bool:
    """Match an AI_CALL_METHODS / AGENT_FRAMEWORK_PATTERNS / CONSEQUENCE_TYPE_PATTERNS
    entry against a dotted call expression (e.g. "chain.invoke", "db.delete",
    "Agent") extracted from Python's AST.

    Anchored, not a bare substring check: "chain.run" matches "chain.run" or
    "obj.chain.run" (as a trailing ".chain.run" segment) but NOT
    "supply_chain.run_pipeline" — the substring "chain.run" occurs inside that
    call string but isn't the actual attribute chain being called. Likewise
    "Agent(" (rstripped to "Agent") matches a bare `Agent(...)` call or
    `x.Agent(...)`, not an identifier that merely contains the letters
    "Agent" (e.g. "MyAgentWrapper.create()").

    Patterns already written with a leading dot (e.g. ".generate(") are
    themselves the trailing segment to match — used as-is via endswith()
    rather than prefixed with another dot.

    Mirrors PatternDecisionPointAnalyser._pattern_matches_call, which already
    applies this same anchoring for the JS/TS/Go/Rust/C# pattern-based path;
    this keeps the Python AST path (nominally the "full" analysis) at least
    as precise, not looser.
    """
    p = pattern.rstrip("(")
    if not p:
        return False
    if p.startswith("."):
        return call_str.endswith(p)
    return call_str == p or call_str.endswith("." + p)

IRREVERSIBLE_ACTION_PATTERNS = {
    "email_send": [
        "send_mail", "send_message", "smtp.sendmail", "ses.send_email",
        "mailgun", "sendgrid",
    ],
    "database_delete": [
        "db.delete", "collection.drop", "session.delete",
        ".delete_many", ".drop_collection", "DELETE FROM",
    ],
    "database_write": [
        "db.insert", "db.update", "db.save",
        "collection.insert", ".commit()",
    ],
    "external_api": [
        "requests.post", "requests.put", "requests.delete",
        "httpx.post", "urllib.request",
    ],
    "file_system": ["os.remove", "os.unlink", "shutil.rmtree"],
    "system_command": [
        "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
    ],
    "payment": [
        "stripe.charge", "stripe.PaymentIntent", "payment.create",
        "transaction.create",
    ],
}

# ── v0.3.0: decision-point-centric detection ──────────────────────────────────

# Agent orchestration framework call patterns — used to flag a function call as
# an agent handover (Pass 1) rather than a plain function call.
AGENT_FRAMEWORK_PATTERNS = {
    "crewai": ["Crew(", "crew.kickoff", "Agent(", "Task(", "execute_task", "kickoff("],
    "autogen": ["UserProxyAgent", "AssistantAgent", "initiate_chat", "groupchat"],
    "langchain": ["AgentExecutor", "agent.invoke", "agent.run", "create_agent", "chain.run", "chain.invoke"],
    # snake_case (add_node/add_edge) is LangGraph's Python API; camelCase
    # (addNode/addEdge) is LangGraph.js's — genuinely different identifiers,
    # not a case-folding difference, so both must be listed explicitly for
    # this shared dict to cover both of LangGraph's two official languages.
    # create_react_agent (langgraph.prebuilt) is LangGraph's high-level
    # "quick start" agent factory — confirmed real-world miss: a real
    # LangGraph MCP-agents repo (braincrew-lab/langgraph-mcp-agents) uses
    # only this, never StateGraph/add_node/add_edge directly, and had zero
    # langgraph decision points before this entry was added. Distinctive
    # compound name, no corroboration needed, same tier as StateGraph.
    # create_swarm / create_handoff_tool (langgraph_swarm) are the
    # official langgraph-ai/langgraph-swarm-py package's top-level API —
    # confirmed real-world miss: its own documented usage example (a
    # downstream caller building a swarm of agents with handoff tools,
    # never touching StateGraph/add_node directly) produced zero langgraph
    # findings before these entries were added.
    "langgraph": [
        "StateGraph", "graph.invoke", "add_node", "add_edge", "addNode", "addEdge",
        "create_react_agent", "create_swarm", "create_handoff_tool",
    ],
}

# Some AGENT_FRAMEWORK_PATTERNS entries are call shapes that legitimate,
# entirely unrelated code also uses verbatim — most notably LangGraph's
# add_node()/add_edge()/graph.invoke(), which are also NetworkX's own
# graph-building API (a far more widely used general-purpose graph library
# with no agent framework involved at all; `G.add_node()` / `G.add_edge()`
# is standard NetworkX idiom). Anchored call-string matching (see
# _call_matches_pattern) rules out substring collisions like
# "batch_add_node_safely", but it can't distinguish two libraries that
# genuinely share a method name. These entries only count as a real
# framework match when the file also shows a corroborating signal for that
# framework — an import, or a call to that framework's own distinctive,
# unambiguous API (its "StateGraph" entry above, no corroboration needed).
_AMBIGUOUS_FRAMEWORK_PATTERNS = {
    "langgraph": {"graph.invoke", "add_node", "add_edge", "addNode", "addEdge"},
    # LangChain's own generic method names collide with unrelated, very
    # common vocabulary: "agent.run()" / "agent.invoke()" also read on any
    # domain "agent" object (insurance/travel/customer-service agents, CI
    # runner agents, monitoring agents), and "create_agent(" is a plausible
    # factory-function name outside LangChain entirely. "AgentExecutor" and
    # "LLMChain" are left out of this set deliberately — real LangChain
    # class names, not generic English, safe to match unconditionally (and
    # doing so also corroborates the ambiguous ones below in the same file).
    "langchain": {"agent.invoke", "agent.run", "chain.run", "chain.invoke", "create_agent"},
}

_FRAMEWORK_CORROBORATION_RE = {
    "langgraph": re.compile(
        # Python: `import langgraph`, `from langgraph.graph import ...`,
        # `from langgraph_sdk import ...`, `from langgraph_checkpoint...`.
        # JS/TS (LangGraph.js ships as the single scoped package
        # "@langchain/langgraph", no unscoped "langgraph" on npm):
        # `import { StateGraph } from "@langchain/langgraph"`,
        # `require("@langchain/langgraph")`.
        r'^\s*(?:import|from)\s+langgraph(?:[._]\w+)*\b'
        r'|[\'"]@langchain/langgraph(?:[\w/-]*)[\'"]'
        r'|\bStateGraph\b',
        re.MULTILINE,
    ),
    "langchain": re.compile(
        # Python: `import langchain`, `import langchain_openai`,
        # `from langchain.chat_models import ...`,
        # `from langchain_community.llms import ...` — "langchain"
        # optionally followed by more `.foo`/`_foo` module-path segments.
        # JS/TS (LangChain.js ships both the unscoped "langchain" package
        # and scoped "@langchain/*" ones — core, openai, anthropic, etc.):
        # `import { AgentExecutor } from "langchain/agents"`,
        # `import { ChatOpenAI } from "@langchain/openai"`,
        # `require("langchain")` / `require("@langchain/core")`.
        r'^\s*(?:import|from)\s+langchain(?:[._]\w+)*\b'
        r'|[\'"](?:langchain(?:/[\w-]+)?|@langchain/[\w-]+)[\'"]'
        r'|\bAgentExecutor\b|\bLLMChain\b',
        re.MULTILINE,
    ),
}


# Providers/frameworks X-Verba scans for by default. Everything outside
# this set (crewai, autogen, google, cohere, aws_bedrock, huggingface,
# llama_index, etc.) still has detection code — it's only suppressed from
# the default report, not deleted — because those detectors range from
# thoroughly precision-audited (this set) to varying, unaudited quality.
# See ScanEngine(all_frameworks=True) to scan everything.
#
# "ai_framework" (the generic fallback label for an AI call whose specific
# provider couldn't be identified) is deliberately never filtered here —
# it doesn't claim to be any particular out-of-scope framework, so hiding
# it would mask real, unclassified AI usage rather than narrow scope.
#
# "openai_agents_sdk" (OpenAI's own official agent framework — Agent(),
# Runner.run(), function_tool(), handoff(), tagged separately from plain
# "openai" client calls via _GUARDED_PROVIDER_IMPORTS) is included here
# even though it's a distinct label from "openai" — it's still squarely
# "OpenAI SDK", the same way "langgraph" sits alongside "langchain" as its
# own entry rather than being folded in or left out. Confirmed real-world
# gap before this was added: on 3 real repos built on this SDK (including
# openai/openai-agents-python itself), every finding was suppressed by
# default — one repo built entirely around it showed only 1 generic
# finding with nothing else visible.
DEFAULT_FRAMEWORK_SCOPE = frozenset({"openai", "langchain", "langgraph", "openai_agents_sdk"})


def _framework_corroborated(source: str, framework: str) -> bool:
    """True if `framework` needs no corroboration for this pattern (default),
    or the file's source shows the corroborating import/distinctive-API
    signal registered for it in _FRAMEWORK_CORROBORATION_RE."""
    pattern = _FRAMEWORK_CORROBORATION_RE.get(framework)
    if pattern is None:
        return True
    return bool(pattern.search(source))

# Method names that hand control (and data) from one agent object to another —
# used by Pass 4 (AgentHandoverAnalyser) to detect agent-to-agent transfers.
AGENT_HANDOVER_METHODS = {
    "run", "execute", "invoke", "predict", "kickoff", "initiate_chat", "send",
}

# Consequential action patterns — used by Pass 2 (ConsequenceClassifier) to
# classify what happens after a decision point commits.
CONSEQUENCE_TYPE_PATTERNS = {
    "external_api": [
        "requests.post", "requests.put", "requests.delete", "requests.get",
        "httpx.post", "httpx.put", "httpx.delete", "httpx.get",
        "urllib.request", "fetch(", "axios.",
    ],
    "database": [
        "db.insert", "db.update", "db.delete", "db.save",
        "collection.insert", "collection.update", "collection.delete", "collection.drop",
        "session.delete", "session.commit", "session.add",
        ".save(", ".commit()", "DELETE FROM", "INSERT INTO", "UPDATE ",
    ],
    "deployment": ["deploy(", "release(", "publish(", "kubectl", "docker push"],
    "file_system": ["os.remove", "os.unlink", "shutil.rmtree", "open(", "os.system", "subprocess."],
    "payment_action": ["stripe.charge", "stripe.PaymentIntent", "payment.create", "transaction.create"],
    "agent_invocation": [
        "agent.run", "agent.invoke", "crew.kickoff", "execute_task",
        "initiate_chat", "graph.invoke",
    ],
    "state_mutation": [".append(", ".update(", ".pop(", ".extend("],
}

# Legacy keyword categories — fallback only. Matched patterns score 0.4
# (below the 0.5 governed threshold) so they surface as ungoverned in reports.
# Structural detection (three-signal pipeline) takes priority; these only fire
# when no structural guard is found.
_LEGACY_KEYWORD_CATEGORIES = {
    "approval": {
        "keywords": [
            "approve", "confirm", "human_review", "require_approval",
            "awaiting_approval", "manual_approval", "human_authorised",
        ],
        "base_strength": 0.9,
    },
    "authorization": {
        "keywords": [
            "is_authorized", "is_authorised", "has_permission", "require_auth",
            "check_permission", "authorised", "authorized", "authenticated", "can_",
        ],
        "base_strength": 0.85,
    },
    "schema": {
        "keywords": ["jsonschema", "pydantic", ".validate()", "schema.validate", "basemodel"],
        "base_strength": 0.8,
    },
    "allow_list": {
        "keywords": ["allow_list", "allowlist", "whitelist", "blocklist", "blacklist"],
        "base_strength": 0.75,
    },
    "validation": {
        "keywords": [
            "validate_", "validate(", "is_valid", "check_", "verify_", "verify(",
            "sanitize", "sanitise", "assert ", "pre_node", "invariant", "eligibility",
        ],
        "base_strength": 0.7,
    },
    "uncertainty": {
        "keywords": ["confidence", "uncertainty", "probability", "threshold"],
        "base_strength": 0.55,
    },
}

# Structural guard detection constants
_CONDITIONAL_RE = re.compile(
    r"^\s*(if\b|elif\b|else\s+if\b|unless\b|guard\b|when\b|match\b|switch\b)",
    re.IGNORECASE,
)

_NON_GOVERNANCE_DECORATORS = frozenset([
    "staticmethod", "classmethod", "property", "abstractmethod", "override",
    "cache", "cached_property", "lru_cache", "wraps", "functools",
    "parametrize", "fixture", "mark", "patch", "mock", "pytest",
    "login_required",  # auth decorator — too generic, structural check is correct
])

# R4: Patterns that indicate framework-level governance in a function signature.
# Checked against the full (possibly multi-line) parameter list of the containing
# function. A match means validation/auth runs before the function body executes.
_SIGNATURE_GOVERNANCE_RE = re.compile(
    r"""
    \bDepends\s*\(              # FastAPI: dependency injection (auth, rate-limit, DB session …)
    | \bSecurity\s*\(           # FastAPI: security dependency (OAuth2, API key …)
    | \bBody\s*\(               # FastAPI: validated request body
    | \bQuery\s*\(              # FastAPI: validated query parameter
    | \bHeader\s*\(             # FastAPI: validated header parameter
    | \bForm\s*\(               # FastAPI: validated form field
    | :\s*(?:\w+\.)?BaseModel\b # Pydantic: typed parameter enforces schema validation
    """,
    re.VERBOSE,
)

_IDENTIFIER_RE = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b')
_BUILTIN_NAMES = frozenset([
    "true", "false", "none", "null", "undefined", "self", "this",
    "int", "str", "bool", "float", "list", "dict", "set", "tuple",
    "len", "range", "print", "return", "if", "else", "elif",
    "and", "or", "not", "in", "is", "for", "while", "def", "class",
    "import", "from", "try", "except", "with", "pass", "raise",
])

# Display names for Pre-Node checkpoint types (used in terminal report).
CHECKPOINT_TYPE_DISPLAY = {
    "control_flow": "Control Flow",
    "decorator": "Decorator",
    "dependency_injection": "Dependency Injection",
    "caller_guard": "Caller Guard",
    "legacy_keyword": "Legacy Keyword",
}


SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".cs", ".php", ".rs",
}

# Extensions for which decision-point/consequence/agent-handover/governance
# detection (Passes 1, 2, 4, 5) run: AST-based for Python, pattern-based
# (PatternDecisionPointAnalyser subclasses) for TS/JS/Go/Rust/C#.
DECISION_ANALYSIS_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".cs"}

# Extensions for which only AI-integration call detection runs
# (pattern-based, no decision/governance analysis). Currently empty —
# retained for languages that may get AI-only detection in the future.
AI_ONLY_EXTENSIONS = set()

# Below this fraction of files receiving full decision/governance analysis,
# the report surfaces a language-coverage warning.
LANGUAGE_COVERAGE_WARNING_THRESHOLD = 0.5

SKIP_DIRS = {
    ".git", ".verba", "node_modules", "__pycache__",
    ".venv", "venv", "env", "dist", "build", ".next",
    "coverage", ".pytest_cache", ".mypy_cache",
    "test", "tests", "spec", "specs", "__tests__",
    "docs", "examples", "fixtures", "mocks", "__mocks__",
    "notebooks", "tutorials", "demo", "demos", "samples",
    "benchmark", "benchmarks", "eval", "evals", "cookbook",
}

# Colocated config/test helper filenames that are never production code.
SKIP_FILENAMES = frozenset({"conftest.py", "setup.cfg", "setup.py"})

# Colocated test files (Vitest/Jest `*.test.ts`/`*.spec.tsx`, Go
# `*_test.go`, pytest `test_*.py`/`*_test.py`) — these sit alongside
# production source rather than in a SKIP_DIRS test directory, but their
# decision points (assertions, mocked branches, etc.) skew governance
# metrics and PageRank/critical-path toward test code.
TEST_FILE_RE = re.compile(
    r'\.(test|spec)(-d)?\.[\w.]*[jt]sx?$|_test\.go$|_test\.py$|^test_.*\.py$',
    re.IGNORECASE,
)

# Minified/bundled JS shipped inside a source tree (e.g. a CLI tool's own
# bundled web UI) — content-hashed build artifacts, not hand-written source.
# Matches `*.min.js` and webpack/esbuild-style hashed chunk filenames like
# `main-3CUQG2IN.js` / `chunk-NALL4A3P.js`.
MINIFIED_BUNDLE_RE = re.compile(
    r'\.min\.[jt]s$|^(?:main|chunk|vendor|runtime|polyfills?)[-.][A-Za-z0-9]{6,}\.[jt]s$',
    re.IGNORECASE,
)

# Context profiles — control which checks fire in which scenarios
CONTEXT_PROFILES = {
    "ai-app": {
        "description": (
            "Full governance analysis. Irreversible actions flagged only when "
            "AI-adjacent. Default profile for AI-integrated applications."
        ),
        "flag_irrev_outside_ai": False,
        "require_ai_for_scan": True,
        "suppress_informal_invariants": False,
    },
    "system-utility": {
        "description": (
            "Suppresses IA-GAPs for local file ops in non-AI files. "
            "For compilers, build tools, CLI utilities with some AI features."
        ),
        "flag_irrev_outside_ai": False,
        "require_ai_for_scan": False,
        "suppress_informal_invariants": True,
    },
    "general": {
        "description": (
            "Legacy behaviour — scans all files regardless of AI presence. "
            "Use when you want maximum coverage including non-AI code."
        ),
        "flag_irrev_outside_ai": True,
        "require_ai_for_scan": False,
        "suppress_informal_invariants": False,
    },
}


# ── AST analyser (Python only) ────────────────────────────────────────────────

class ASTAnalyser:
    """
    AST-based analysis for Python files.
    Detects actual AI API calls — not strings, not comments,
    not import statements used as type hints.
    """

    def __init__(self):
        self.ai_imports = {}
        self.ai_calls = []
        self.assignments = {}
        self._langchain_corroborated = True

    def analyse(self, source: str, filepath: str) -> dict:
        self.ai_imports = {}
        self.ai_calls = []
        self.assignments = {}
        # See _AMBIGUOUS_AI_CALL_METHODS: a plain agent.run()/chain.invoke()
        # call only counts as LangChain if this file also shows a
        # corroborating LangChain import or distinctive class name.
        self._langchain_corroborated = _framework_corroborated(source, "langchain")

        try:
            tree = _ast_parse_quiet(source, filepath)
        except (SyntaxError, ValueError, RecursionError):
            return {"ai_calls": [], "imports": {}, "parse_error": True}

        self._collect_imports(tree, source)
        self._collect_calls(tree, source.splitlines())

        return {
            "ai_calls": self.ai_calls,
            "imports": self.ai_imports,
            "parse_error": False,
        }

    def _collect_imports(self, tree: ast.AST, source: str) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for pkg, provider in AI_PROVIDER_IMPORTS.items():
                        if alias.name == pkg or alias.name.startswith(pkg + "."):
                            local = alias.asname or alias.name.split(".")[0]
                            self.ai_imports[local] = provider
                    for pkg, (provider, signals) in _GUARDED_PROVIDER_IMPORTS.items():
                        if (alias.name == pkg or alias.name.startswith(pkg + ".")) and any(
                            sig in source for sig in signals
                        ):
                            local = alias.asname or alias.name.split(".")[0]
                            self.ai_imports[local] = provider

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                matched = False
                for pkg, provider in AI_PROVIDER_IMPORTS.items():
                    if module == pkg or module.startswith(pkg + "."):
                        for alias in node.names:
                            local = alias.asname or alias.name
                            self.ai_imports[local] = provider
                        matched = True
                        break
                if not matched:
                    for pkg, (provider, signals) in _GUARDED_PROVIDER_IMPORTS.items():
                        if (module == pkg or module.startswith(pkg + ".")) and any(
                            sig in source for sig in signals
                        ):
                            for alias in node.names:
                                local = alias.asname or alias.name
                                self.ai_imports[local] = provider
                            break

    def _collect_calls(self, tree: ast.AST, lines: list) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Call, ast.Expr)):
                continue

            call_node = node if isinstance(node, ast.Call) else None
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call_node = node.value

            if not call_node:
                continue

            func = call_node.func
            call_str = self._get_call_string(func)
            if not call_str:
                continue

            provider = self._identify_provider(call_str)
            if not provider:
                continue

            line_num = getattr(call_node, "lineno", 0)
            line_content = (
                lines[line_num - 1].strip()
                if line_num > 0 and line_num <= len(lines)
                else ""
            )

            temperature = None
            max_tokens = None
            streaming = False
            for kw in call_node.keywords:
                if kw.arg == "temperature" and isinstance(kw.value, ast.Constant):
                    temperature = kw.value.value
                if kw.arg in ("max_tokens", "max_new_tokens") and isinstance(kw.value, ast.Constant):
                    max_tokens = kw.value.value
                if kw.arg == "stream" and isinstance(kw.value, ast.Constant):
                    streaming = bool(kw.value.value)

            self.ai_calls.append({
                "line": line_num,
                "line_content": line_content[:120],
                "call": call_str[:80],
                "provider": provider,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "streaming": streaming,
            })

    def _get_call_string(self, func_node) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            obj = self._get_call_string(func_node.value)
            if obj:
                return f"{obj}.{func_node.attr}"
        return None

    def _identify_provider(self, call_str: str) -> Optional[str]:
        call_lower = call_str.lower()
        root = call_str.split(".")[0]
        if root in self.ai_imports:
            return self.ai_imports[root]

        for method in AI_CALL_METHODS:
            if _call_matches_pattern(call_str, method):
                # Generic method names (.chat(, .query(, .predict(, pipeline(, ...)
                # appear on plenty of non-AI objects (a DB client's .query(), an
                # HTTP client's .complete(), a Workflow's pipeline()). Without a
                # recognised AI import as the call's root, matching one of these
                # alone isn't real evidence of an AI call — skip rather than
                # guess "ai_framework". The more specific method names below
                # (chat.completions.create, LLMChain, ChatOpenAI, etc.) are
                # distinctive enough to stand on their own.
                if method in _GENERIC_AI_CALL_METHODS and root not in self.ai_imports:
                    continue
                if method in _AMBIGUOUS_AI_CALL_METHODS and not self._langchain_corroborated:
                    continue
                needed_provider = _PROVIDER_AMBIGUOUS_AI_CALL_METHODS.get(method)
                if needed_provider and needed_provider not in self.ai_imports.values():
                    continue
                if any(x in call_lower for x in ["openai", "chatcompletion", "completion"]):
                    return "openai"
                if any(x in call_lower for x in ["anthropic", "claude"]):
                    return "anthropic"
                if any(x in call_lower for x in ["langchain", "chain", "agent"]):
                    return "langchain"
                return "ai_framework"

        return None


# ── JS/TS detection ───────────────────────────────────────────────────────────

# AI-call patterns by language, used by _detect_ai_calls_pattern.
JS_AI_PATTERNS = [
    (r'openai\.(chat|completions?|beta)', "openai"),
    (r'new\s+OpenAI\s*\(', "openai"),
    (r'client\.chat\.completions\.create', "openai"),
    (r'anthropic\.messages\.create', "anthropic"),
    (r'new\s+Anthropic\s*\(', "anthropic"),
    (r'new\s+ChatOpenAI\s*\(', "langchain"),
    (r'new\s+ChatAnthropic\s*\(', "langchain"),
    (r'chain\.invoke\s*\(', "langchain"),
    (r'agent\.invoke\s*\(', "langchain"),
    # LangChain.js's "universal model loader" (`langchain/chat_models/
    # universal`) — dynamically instantiates whichever provider the caller
    # names at runtime, so there's no `new ChatOpenAI(...)`/etc. call site
    # to match. Confirmed real-world miss: a production LangGraph.js repo
    # (mayooear/ai-pdf-chatbot-langchain) routes every model load through
    # this exact function and had zero ai_integrations findings before this
    # pattern was added — the fluent-chained StateGraph.addNode/addEdge
    # calls were still correctly detected, only the LLM-call side was blind.
    # Distinctive name, no import-corroboration needed.
    (r'\binitChatModel\s*\(', "langchain"),
    (r'generateText\s*\(', "vercel_ai"),
    (r'streamText\s*\(', "vercel_ai"),
    (r'generateObject\s*\(', "vercel_ai"),
    (r'streamObject\s*\(', "vercel_ai"),
    (r'embed(Many)?\s*\(', "vercel_ai"),
    (r'createAnthropic\s*\(', "anthropic"),
    (r'createOpenAI\s*\(', "openai"),
    (r'\.generate\s*\(\s*\{', "ai_framework"),
    # Vercel AI SDK React hooks — client-side AI integration call sites.
    (r'useChat\s*\(', "vercel_ai"),
    (r'useCompletion\s*\(', "vercel_ai"),
    (r'useObject\s*\(', "vercel_ai"),
    (r'useAssistant\s*\(', "vercel_ai"),
    # Meta AI / Llama and common Llama-hosting providers.
    (r'new\s+LlamaAPIClient\s*\(', "meta_llama"),
    (r'createLlamaApi\s*\(', "meta_llama"),
    (r'new\s+Together\s*\(', "together_ai"),
    (r'together\.chat\.completions\.create', "together_ai"),
    (r'new\s+Replicate\s*\(', "replicate"),
    (r'replicate\.run\s*\(', "replicate"),
    # Anthropic's own Claude Agent SDK (JS/TS) — distinct package name from
    # the Python claude_agent_sdk; same vendor, separate fix required.
    (r'@anthropic-ai/claude-agent-sdk', "anthropic"),
    # AWS SDK for JavaScript v3 — Bedrock clients (distinct from Python's
    # boto3, which is already recognised).
    (r'@aws-sdk/client-bedrock-runtime', "aws_bedrock"),
    (r'@aws-sdk/client-bedrock-agent-runtime', "aws_bedrock"),
    (r'new\s+BedrockRuntimeClient\s*\(', "aws_bedrock"),
    (r'\bConverseCommand\b', "aws_bedrock"),
    (r'\bInvokeModelCommand\b', "aws_bedrock"),
]

# JS_AI_PATTERNS entries generic enough that unrelated code uses the exact
# same call shape with no LangChain involvement (any JS/TS object named
# `chain` or `agent` with an `.invoke()` method) — same ambiguity as
# AGENT_FRAMEWORK_PATTERNS' langchain entries, applied here to the separate
# AI-integration-call pattern list. See _detect_ai_calls_pattern.
_AMBIGUOUS_AI_PATTERNS = {
    r'chain\.invoke\s*\(',
    r'agent\.invoke\s*\(',
}

# github.com/sashabaranov/go-openai, anthropic-sdk-go, langchaingo, google genai SDK, ollama.
GO_AI_PATTERNS = [
    (r'openai\.NewClient\s*\(', "openai"),
    (r'\.CreateChatCompletion\s*\(', "openai"),
    (r'\.CreateCompletion\s*\(', "openai"),
    (r'anthropic\.NewClient\s*\(', "anthropic"),
    (r'\.Messages\.New\s*\(', "anthropic"),
    (r'genai\.NewClient\s*\(', "google_genai"),
    (r'\.GenerateContent\s*\(', "google_genai"),
    (r'llms\.GenerateFromSinglePrompt\s*\(', "langchain"),
    (r'llms\.GenerateContent\s*\(', "langchain"),
    (r'ollama\.', "ollama"),
]

# async-openai, anthropic-sdk-rust-like crates, generic Client::new() builders.
RUST_AI_PATTERNS = [
    (r'async_openai::', "openai"),
    (r'\.chat\(\)\.create\s*\(', "openai"),
    (r'\.completions\(\)\.create\s*\(', "openai"),
    (r'anthropic[_-]sdk', "anthropic"),
    (r'\.messages\(\)\.create\s*\(', "anthropic"),
    (r'async_anthropic::', "anthropic"),
    # Raw HTTP clients (reqwest etc.) hitting documented LLM API endpoints —
    # common in Rust, which lacks a dominant provider SDK.
    (r'\.post\s*\(\s*["\'][^"\']*/chat/completions["\']', "openai"),
    (r'\.post\s*\(\s*["\'][^"\']*/responses["\']', "openai"),
    (r'\.post\s*\(\s*["\'][^"\']*/messages["\']', "anthropic"),
    (r':generateContent["\']', "google_genai"),
]

# OpenAI .NET SDK, Azure OpenAI SDK, Semantic Kernel.
CSHARP_AI_PATTERNS = [
    (r'new\s+OpenAIClient\s*\(', "openai"),
    (r'new\s+AzureOpenAIClient\s*\(', "azure_openai"),
    (r'\.GetChatClient\s*\(', "openai"),
    (r'\.CompleteChatAsync\s*\(', "openai"),
    (r'Kernel\.CreateBuilder\s*\(', "semantic_kernel"),
    (r'\.AddOpenAIChatCompletion\s*\(', "semantic_kernel"),
    (r'\.AddAzureOpenAIChatCompletion\s*\(', "semantic_kernel"),
    # `.InvokeAsync(` alone is a generic C# async convention (ASP.NET
    # middleware, MediatR, ICommand, etc.) — only treat it as an SK call
    # site when the receiver looks like a kernel/agent/function/plugin.
    (r'(?i)\w*(?:kernel|agent|function|plugin|chat)\w*\.InvokeAsync\s*\(', "semantic_kernel"),
    (r'new\s+AnthropicClient\s*\(', "anthropic"),
]


def _js_balanced_brace_span(content: str, start_after_open_brace: int) -> str:
    """Given an index just after an opening '{', return the substring up to
    (not including) its matching closing '}', respecting nested braces.
    Used where JS/TS pattern detection needs an object literal's exact
    extent rather than a fixed character window."""
    depth = 1
    i = start_after_open_brace
    n = len(content)
    while i < n and depth > 0:
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
        i += 1
    return content[start_after_open_brace:i - 1]


def _detect_ai_calls_pattern(
    content: str, lines: list, ai_patterns: list,
    temp_params: tuple = ("temperature",), token_params: tuple = ("maxTokens", "max_tokens", "MaxTokens"),
) -> list:
    """
    Generic pattern-based AI call detection, shared across non-Python
    languages. Skips comments and obvious string contexts.
    """
    calls = []
    _corroboration_cache: dict = {}

    def _corroborated(provider: str) -> bool:
        if provider not in _corroboration_cache:
            _corroboration_cache[provider] = _framework_corroborated(content, provider)
        return _corroboration_cache[provider]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        for pattern, provider in ai_patterns:
            if re.search(pattern, line):
                if pattern in _AMBIGUOUS_AI_PATTERNS and not _corroborated(provider):
                    continue
                if line.count('"') % 2 == 0 and line.count("'") % 2 == 0:
                    calls.append({
                        "line": i,
                        "line_content": stripped[:120],
                        "call": pattern,
                        "provider": provider,
                        "temperature": _extract_param(lines, i, temp_params),
                        "max_tokens": _extract_param(lines, i, token_params),
                        "streaming": "stream" in content[
                            max(0, content.find(line) - 100):content.find(line) + 200
                        ].lower(),
                    })
                    break

    return calls


def _detect_ai_calls_js(content: str, lines: list) -> list:
    """JavaScript/TypeScript AI call detection."""
    return _detect_ai_calls_pattern(content, lines, JS_AI_PATTERNS, ("temperature",), ("maxTokens", "max_tokens"))


def _detect_ai_calls_go(content: str, lines: list) -> list:
    """Go AI call detection."""
    return _detect_ai_calls_pattern(content, lines, GO_AI_PATTERNS, ("Temperature", "temperature"), ("MaxTokens", "max_tokens"))


def _detect_ai_calls_rust(content: str, lines: list) -> list:
    """Rust AI call detection."""
    return _detect_ai_calls_pattern(content, lines, RUST_AI_PATTERNS, ("temperature",), ("max_tokens",))


def _detect_ai_calls_csharp(content: str, lines: list) -> list:
    """C# AI call detection."""
    return _detect_ai_calls_pattern(content, lines, CSHARP_AI_PATTERNS, ("Temperature", "temperature"), ("MaxTokens", "max_tokens"))


def _extract_param(lines: list, line_num: int, param_names: tuple) -> Optional[float]:
    context = "\n".join(lines[max(0, line_num - 1):min(len(lines), line_num + 10)])
    for param in param_names:
        match = re.search(rf'{param}\s*[:=]\s*([0-9.]+)', context)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
    return None


def _compute_language_coverage(parsed: list) -> dict:
    """
    Summarise how much of the scanned codebase received full
    decision/consequence/agent-handover/governance analysis
    (DECISION_ANALYSIS_EXTENSIONS) versus AI-integration-only analysis
    (AI_ONLY_EXTENSIONS) versus no primitive analysis at all.

    Used to surface a language-coverage warning so governance/Gamma/
    tendency metrics aren't mistaken for whole-repo coverage when most
    files are in a language without decision-point detection.
    """
    total = len(parsed)
    decision_analysed = 0
    ai_only = 0
    by_extension: Dict[str, int] = {}

    for file_data in parsed:
        ext = file_data.get("extension", "")
        by_extension[ext] = by_extension.get(ext, 0) + 1
        if ext in DECISION_ANALYSIS_EXTENSIONS:
            decision_analysed += 1
        elif ext in AI_ONLY_EXTENSIONS:
            ai_only += 1

    return {
        "total_files": total,
        "decision_analysed_files": decision_analysed,
        "ai_only_files": ai_only,
        "unanalysed_files": total - decision_analysed - ai_only,
        "decision_analysed_fraction": _safe_ratio(decision_analysed, total),
        "by_extension": by_extension,
    }


# ── Decision-point detection (Pass 1 enhancement) ─────────────────────────────

# A handler body line matching this is a logging call and nothing else —
# logging an exception is not recovery: it doesn't halt execution, re-raise,
# return a failure sentinel, or escalate. Execution proceeds as if nothing
# happened either way, so a handler whose only content is logging calls is
# still a Terminal State, not a governed recovery path.
_LOGGING_ONLY_RE = re.compile(
    r'^(logger\.|logging\.|log\.|console\.|print\()',
    re.IGNORECASE,
)


def _is_genuine_recovery(body_lines: list) -> bool:
    """True only if at least one non-empty handler line does something
    beyond logging (re-raise, return a failure value, compensating call,
    retry, escalation, etc.). A handler whose only non-empty lines are
    logging calls returns False — it swallows the error and continues."""
    non_empty = [bl for bl in body_lines if bl and bl not in ("pass", "...")]
    if not non_empty:
        return False
    return not all(_LOGGING_ONLY_RE.match(bl.strip()) for bl in non_empty)


class DecisionPointAnalyser:
    """
    AST-based detection of ALL decision points in Python source —
    not just AI calls. Covers conditionals, ternaries, loops, error
    handling, and consequential function calls (agent invocations,
    API/DB/file/system operations).

    AI call detection remains in ASTAnalyser; this class is additive
    and feeds the v0.3.0 decision-point-centric passes.
    """

    def analyse(self, source: str, filepath: str) -> list:
        try:
            tree = _ast_parse_quiet(source, filepath)
        except (SyntaxError, ValueError, RecursionError):
            return []

        lines = source.splitlines()
        points = []

        # Computed once per file: which ambiguous-pattern frameworks (see
        # _AMBIGUOUS_FRAMEWORK_PATTERNS) have a corroborating signal here.
        framework_corroboration = {
            fw: _framework_corroborated(source, fw)
            for fw in _FRAMEWORK_CORROBORATION_RE
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                points.append(self._conditional(node, lines, filepath))
            elif isinstance(node, ast.IfExp):
                points.append(self._conditional(node, lines, filepath, ternary=True))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                points.append(self._loop(node, lines, filepath))
            elif isinstance(node, ast.Try):
                points.append(self._try_except(node, lines, filepath))
            elif isinstance(node, ast.Call):
                call_point = self._function_call(node, lines, filepath, framework_corroboration)
                if call_point:
                    points.append(call_point)

        return points

    def _line_text(self, lines: list, line_num: int) -> str:
        return lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""

    def _conditional(self, node, lines: list, filepath: str, ternary: bool = False) -> dict:
        line_num = getattr(node, "lineno", 0)
        branches = 2 if getattr(node, "orelse", None) else 1
        return {
            "type": "ternary" if ternary else "conditional_branch",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": self._line_text(lines, line_num)[:120],
            "branches": branches,
            "severity": "low",
        }

    def _loop(self, node, lines: list, filepath: str) -> dict:
        line_num = getattr(node, "lineno", 0)
        return {
            "type": "loop",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": self._line_text(lines, line_num)[:120],
            "branches": 1,
            "severity": "low",
        }

    def _try_except(self, node: ast.Try, lines: list, filepath: str) -> dict:
        line_num = getattr(node, "lineno", 0)
        bare_except = False
        has_recovery = False
        for handler in node.handlers:
            if handler.type is None:
                bare_except = True
            body_lines = [
                self._line_text(lines, getattr(stmt, "lineno", 0)).lower()
                for stmt in handler.body
            ]
            if _is_genuine_recovery(body_lines):
                has_recovery = True

        return {
            "type": "try_except",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": self._line_text(lines, line_num)[:120],
            "branches": len(node.handlers),
            "bare_except": bare_except,
            "has_recovery": has_recovery,
            "severity": "medium" if not has_recovery else "low",
        }

    def _function_call(
        self, node: ast.Call, lines: list, filepath: str,
        framework_corroboration: Optional[dict] = None,
    ) -> Optional[dict]:
        call_str = self._get_call_string(node.func)
        if not call_str:
            return None

        line_num = getattr(node, "lineno", 0)
        line_text = self._line_text(lines, line_num)
        framework_corroboration = framework_corroboration or {}

        is_agent_call = False
        framework = None
        for fw, patterns in AGENT_FRAMEWORK_PATTERNS.items():
            ambiguous = _AMBIGUOUS_FRAMEWORK_PATTERNS.get(fw, frozenset())
            for p in patterns:
                if not _call_matches_pattern(call_str, p):
                    continue
                if p.rstrip("(") in ambiguous and not framework_corroboration.get(fw, True):
                    continue
                is_agent_call = True
                framework = fw
                break
            if is_agent_call:
                break

        is_consequential = is_agent_call or any(
            _call_matches_pattern(call_str, p)
            for patterns in CONSEQUENCE_TYPE_PATTERNS.values()
            for p in patterns
        )

        if not is_consequential:
            return None

        return {
            "type": "agent_invocation" if is_agent_call else "function_call",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": line_text[:120],
            "call": call_str[:80],
            "is_agent_call": is_agent_call,
            "framework": framework,
            "branches": 1,
            "severity": "high" if is_agent_call else "medium",
        }

    def _get_call_string(self, func_node) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            obj = self._get_call_string(func_node.value)
            if obj:
                return f"{obj}.{func_node.attr}"
            return func_node.attr
        return None


# ── Decision-point detection for TS/JS (TASK-020) ──────────────────────────────

class PatternDecisionPointAnalyser:
    """
    Generic pattern-based detection of decision points in non-Python
    source — the shared counterpart to DecisionPointAnalyser (AST-based,
    Python only).

    Produces the same dict shape (type, location, line, condition,
    branches, severity, ...) as the Python AST analyser, so output flows
    unchanged into ConsequenceClassifier, _detect_terminal_states,
    DecisionGraphBuilder, and all v0.4.0 metrics.

    Pattern-based rather than AST-based: no parser is available for these
    languages, so detection is line-oriented and trades some precision for
    coverage. Language-specific subclasses configure the class-level
    regexes below; analyse() and the dict-building helpers are shared.

    Regex hooks (None = construct not checked for that language):
      IF_RE, SWITCH_RE, CASE_RE, LOOP_RE, CATCH_RE, TERNARY_RE,
      OPTIONAL_PROP_RE, ERROR_CHECK_RE (Go-style `if err != nil`),
      NORECOVERY_RE (Rust-style `.unwrap()`/`.expect(`).
    """

    COMMENT_PREFIXES = ("//", "*", "/*")

    IF_RE: Optional[re.Pattern] = None
    SWITCH_RE: Optional[re.Pattern] = None
    CASE_RE: Optional[re.Pattern] = None
    LOOP_RE: Optional[re.Pattern] = None
    CATCH_RE: Optional[re.Pattern] = None
    TERNARY_RE: Optional[re.Pattern] = None
    OPTIONAL_PROP_RE: Optional[re.Pattern] = None
    ERROR_CHECK_RE: Optional[re.Pattern] = None
    NORECOVERY_RE: Optional[re.Pattern] = None
    TEST_BLOCK_RE: Optional[re.Pattern] = None

    _CALL_RE = re.compile(r'([A-Za-z_$][\w$]*(?:(?:\.|::)[A-Za-z_$][\w$]*)*)\s*\(')

    def analyse(self, source: str, filepath: str) -> list:
        lines = source.splitlines()
        points = []

        # Computed once per file: which ambiguous-pattern frameworks (see
        # _AMBIGUOUS_FRAMEWORK_PATTERNS) have a corroborating signal here.
        framework_corroboration = {
            fw: _framework_corroborated(source, fw)
            for fw in _FRAMEWORK_CORROBORATION_RE
        }

        i = 0
        n = len(lines)
        while i < n:
            raw_line = lines[i]
            stripped = raw_line.strip()
            line_num = i + 1

            if not stripped or stripped.startswith(self.COMMENT_PREFIXES):
                i += 1
                continue

            if self.TEST_BLOCK_RE and self.TEST_BLOCK_RE.search(stripped):
                # Skip inline test modules (e.g. Rust's `#[cfg(test)] mod
                # tests { ... }`) — idiomatic colocated test code, not
                # production decision points.
                j = i
                while j < n and "{" not in lines[j]:
                    j += 1
                if j < n:
                    end_idx, _ = self._block_extent(lines, j, max_lines=n)
                    i = end_idx + 1
                else:
                    i += 1
                continue

            if self.SWITCH_RE and self.SWITCH_RE.search(stripped):
                points.append(self._switch(stripped, lines, line_num, filepath))
            elif self.ERROR_CHECK_RE and self.ERROR_CHECK_RE.search(stripped):
                points.append(self._error_check(stripped, lines, line_num, filepath))
            elif self.IF_RE and self.IF_RE.search(stripped):
                points.append(self._conditional(stripped, line_num, filepath))
            elif self.LOOP_RE and self.LOOP_RE.search(stripped):
                points.append(self._loop(stripped, line_num, filepath))
            elif self.CATCH_RE and self.CATCH_RE.match(stripped):
                points.append(self._try_except(stripped, lines, line_num, filepath))
            elif self.NORECOVERY_RE and self.NORECOVERY_RE.search(stripped):
                points.append(self._no_recovery(stripped, line_num, filepath))
            elif self.TERNARY_RE and self._is_ternary(stripped):
                points.append(self._ternary(stripped, line_num, filepath))

            call_point = self._function_call(stripped, line_num, filepath, framework_corroboration)
            if call_point:
                points.append(call_point)

            i += 1

        return points

    @staticmethod
    def _block_extent(lines: list, start_idx: int, max_lines: int = 300) -> tuple:
        """
        Return (end_idx, block_lines) for the brace-delimited block opened
        on lines[start_idx] (0-based indices). Heuristic brace counting —
        does not account for braces inside strings/comments/regex literals.
        """
        depth = 0
        started = False
        block = []
        last_idx = start_idx
        for idx in range(start_idx, min(len(lines), start_idx + max_lines)):
            line = lines[idx]
            for ch in line:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            block.append(line)
            last_idx = idx
            if started and depth <= 0:
                break
        return last_idx, block

    def _conditional(self, stripped: str, line_num: int, filepath: str) -> dict:
        branches = 2 if re.search(r'\belse\b', stripped) else 1
        return {
            "type": "conditional_branch",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": branches,
            "severity": "low",
        }

    def _switch(self, stripped: str, lines: list, line_num: int, filepath: str) -> dict:
        _, block = self._block_extent(lines, line_num - 1)
        branches = sum(1 for bl in block if self.CASE_RE.search(bl.strip())) or 1
        return {
            "type": "conditional_branch",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": branches,
            "severity": "low",
        }

    def _loop(self, stripped: str, line_num: int, filepath: str) -> dict:
        return {
            "type": "loop",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": 1,
            "severity": "low",
        }

    def _try_except(self, stripped: str, lines: list, line_num: int, filepath: str) -> dict:
        bare_except = not re.search(r'catch\s*\([^)]+\)', stripped)

        _, block = self._block_extent(lines, line_num - 1)
        body_lines = [
            bl.strip() for bl in block[1:-1]
        ] if len(block) > 1 else []
        non_comment_lines = [
            bl for bl in body_lines
            if bl and not bl.startswith(("//", "*", "/*")) and bl not in ("{", "}")
        ]
        has_recovery = _is_genuine_recovery(non_comment_lines)

        return {
            "type": "try_except",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": 1,
            "bare_except": bare_except,
            "has_recovery": has_recovery,
            "severity": "medium" if not has_recovery else "low",
        }

    def _is_ternary(self, stripped: str) -> bool:
        if re.match(r'^(export\s+)?(interface|type)\b', stripped):
            return False
        check = stripped.replace("?.", "").replace("??", "")
        if "?" not in check:
            return False
        if self.OPTIONAL_PROP_RE and self.OPTIONAL_PROP_RE.search(check) and "=" not in check:
            return False
        return bool(self.TERNARY_RE.search(check))

    def _ternary(self, stripped: str, line_num: int, filepath: str) -> dict:
        return {
            "type": "ternary",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": 2,
            "severity": "low",
        }

    def _error_check(self, stripped: str, lines: list, line_num: int, filepath: str) -> dict:
        """
        Go-style `if err != nil { ... }` guard. Treated as the try/except
        equivalent: has_recovery is False if the block only propagates the
        error (`return ...err`), panics, or only logs — True if it does a
        genuine recovery action (retry, fallback value, compensating call).
        """
        _, block = self._block_extent(lines, line_num - 1)
        body_lines = [
            bl.strip() for bl in block[1:-1]
        ] if len(block) > 1 else []
        non_propagation_lines = [
            bl for bl in body_lines
            if bl and not bl.startswith(self.COMMENT_PREFIXES)
            and not re.match(r'^(return\b.*\berr\w*\b|panic\()', bl)
        ]
        has_recovery = _is_genuine_recovery(non_propagation_lines)
        return {
            "type": "try_except",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": 1,
            "bare_except": False,
            "has_recovery": has_recovery,
            "severity": "medium" if not has_recovery else "low",
        }

    def _no_recovery(self, stripped: str, line_num: int, filepath: str) -> dict:
        """
        Rust-style `.unwrap()` / `.expect(...)` on a Result/Option — panics
        on the error/None path with no recovery, the try/except equivalent
        of a bare except with no handling.
        """
        return {
            "type": "try_except",
            "location": f"{filepath}:{line_num}",
            "line": line_num,
            "condition": stripped[:120],
            "branches": 1,
            "bare_except": True,
            "has_recovery": False,
            "severity": "medium",
        }

    # Set True for languages where PascalCase is the *mandatory* convention
    # for exported/public identifiers (Go, C#) — not a style choice like
    # JS camelCase vs snake_case. CONSEQUENCE_TYPE_PATTERNS/
    # AGENT_FRAMEWORK_PATTERNS are written lowercase (db.delete,
    # agent.invoke); without case-insensitive matching, every exported
    # Go/C# call (Db.Delete, Agent.Invoke) would be invisible to Pass 1/2.
    CASE_INSENSITIVE_CALLS = False

    # Trailing segments to strip from the final identifier of a call before
    # matching (lowercase). E.g. C#'s near-universal "...Async" suffix on
    # async methods: "Agent.InvokeAsync" should still match "agent.invoke".
    STRIP_CALL_SUFFIXES: tuple = ()

    def _pattern_matches_call(self, call_str: str, pattern: str) -> bool:
        """
        Match a CONSEQUENCE_TYPE_PATTERNS / AGENT_FRAMEWORK_PATTERNS entry
        against an extracted call expression (e.g. "agent.invoke",
        "db.delete", "Agent"). Requires an exact match or a trailing
        ".pattern"/"::pattern" segment — not an arbitrary substring — so
        identifiers like "runAgent" don't falsely match a pattern like
        "Agent(". Patterns that aren't call-shaped (e.g. "DELETE FROM")
        never match a call expression and are intentionally skipped here;
        they're still applied to raw line text elsewhere
        (ConsequenceClassifier).
        """
        p = pattern.rstrip("(")
        if not p or not re.match(r'^[\w$.]+$', p):
            return False
        c = call_str
        if self.CASE_INSENSITIVE_CALLS:
            c, p = c.lower(), p.lower()
        for suffix in self.STRIP_CALL_SUFFIXES:
            suffix = suffix.lower() if self.CASE_INSENSITIVE_CALLS else suffix
            if c.endswith(suffix) and len(c) > len(suffix):
                c = c[:-len(suffix)]
                break
        return c == p or c.endswith("." + p) or c.endswith("::" + p)

    def _function_call(
        self, stripped: str, line_num: int, filepath: str,
        framework_corroboration: Optional[dict] = None,
    ) -> Optional[dict]:
        framework_corroboration = framework_corroboration or {}
        for match in self._CALL_RE.finditer(stripped):
            call_str = match.group(1)

            is_agent_call = False
            framework = None
            for fw, patterns in AGENT_FRAMEWORK_PATTERNS.items():
                ambiguous = _AMBIGUOUS_FRAMEWORK_PATTERNS.get(fw, frozenset())
                for p in patterns:
                    if not self._pattern_matches_call(call_str, p):
                        continue
                    if p.rstrip("(") in ambiguous and not framework_corroboration.get(fw, True):
                        continue
                    is_agent_call = True
                    framework = fw
                    break
                if is_agent_call:
                    break

            is_consequential = is_agent_call or any(
                self._pattern_matches_call(call_str, p)
                for patterns in CONSEQUENCE_TYPE_PATTERNS.values()
                for p in patterns
            )

            if not is_consequential:
                continue

            return {
                "type": "agent_invocation" if is_agent_call else "function_call",
                "location": f"{filepath}:{line_num}",
                "line": line_num,
                "condition": stripped[:120],
                "call": call_str[:80],
                "is_agent_call": is_agent_call,
                "framework": framework,
                "branches": 1,
                "severity": "high" if is_agent_call else "medium",
            }
        return None


class JSDecisionPointAnalyser(PatternDecisionPointAnalyser):
    """
    JavaScript/TypeScript. Ternary detection is conservative, to avoid
    false positives from TS optional chaining (?.), nullish coalescing
    (??), optional properties/parameters (name?: Type), and conditional
    types (T extends U ? X : Y).
    """

    IF_RE = re.compile(r'(?:\}\s*)?\belse\s+if\s*\(|(?<![.\w$])if\s*\(')
    SWITCH_RE = re.compile(r'\bswitch\s*\(')
    CASE_RE = re.compile(r'^(case\s+.+|default\s*):')
    LOOP_RE = re.compile(r'(?<![.\w$])(for|while)\s*\(')
    CATCH_RE = re.compile(r'^\}?\s*catch\s*(\([^)]*\))?\s*\{?')
    TERNARY_RE = re.compile(r'[^?]\?(?![.?])[^?:{};]*:[^:{};]*')
    OPTIONAL_PROP_RE = re.compile(r'[\w$]\?\s*:\s*[\w$<>\[\].,\s|&\'"]+[;,)]?\s*$')


class GoDecisionPointAnalyser(PatternDecisionPointAnalyser):
    """
    Go. Go has no try/catch — `if err != nil { ... }` is the idiomatic
    error-handling equivalent and is treated as a try_except node
    (ERROR_CHECK_RE, checked before IF_RE so it isn't double-counted as
    a plain conditional). Go has no ternary operator.
    """

    IF_RE = re.compile(r'(?:\}\s*)?\belse\s+if\b|(?<![.\w])if\b')
    SWITCH_RE = re.compile(r'(?<![.\w])switch\b')
    CASE_RE = re.compile(r'^(case\s+.+|default)\s*:')
    LOOP_RE = re.compile(r'(?<![.\w])for\b')
    ERROR_CHECK_RE = re.compile(r'^\}?\s*if\s+\w*[Ee]rr\w*\s*(!=|==)\s*nil\b')
    CASE_INSENSITIVE_CALLS = True


class RustDecisionPointAnalyser(PatternDecisionPointAnalyser):
    """
    Rust. `match` is the switch equivalent (arms detected via `=>`).
    Rust has no try/catch; `.unwrap()`/`.expect(...)` on a Result/Option
    is treated as the "bare except, no recovery" equivalent
    (NORECOVERY_RE). Rust has no ternary operator (if/else are
    expressions instead).
    """

    IF_RE = re.compile(r'(?:\}\s*)?\belse\s+if\b|(?<![.\w])if\b')
    SWITCH_RE = re.compile(r'(?<![.\w])match\b')
    CASE_RE = re.compile(r'=>')
    LOOP_RE = re.compile(r'(?<![.\w])(for|while|loop)\b')
    NORECOVERY_RE = re.compile(r'\.unwrap\(\)|\.expect\(')
    TEST_BLOCK_RE = re.compile(r'#\[cfg\(test\)\]')


class CSharpDecisionPointAnalyser(PatternDecisionPointAnalyser):
    """
    C#. Syntactically close to JS/Java: parenthesised if/switch/for,
    try/catch, and a `?:` ternary (plus `?.`/`??`/nullable `T?` which the
    inherited _is_ternary() guards against, same as TS).
    """

    IF_RE = re.compile(r'(?:\}\s*)?\belse\s+if\s*\(|(?<![.\w])if\s*\(')
    SWITCH_RE = re.compile(r'\bswitch\s*\(')
    CASE_RE = re.compile(r'^(case\s+.+|default\s*):')
    LOOP_RE = re.compile(r'(?<![.\w])(for|while|foreach)\s*\(')
    CATCH_RE = re.compile(r'^\}?\s*catch\s*(\([^)]*\))?\s*\{?')
    TERNARY_RE = re.compile(r'[^?]\?(?![.?])[^?:{};]*:[^:{};]*')
    OPTIONAL_PROP_RE = re.compile(r'[\w]\?\s*:\s*[\w<>\[\].,\s|&\'"]+[;,)]?\s*$')
    CASE_INSENSITIVE_CALLS = True
    STRIP_CALL_SUFFIXES = ("Async",)


# Maps a non-Python source extension to its AI-call detector function, the
# ScanEngine instance-attribute name of its PatternDecisionPointAnalyser
# subclass, and a short label for diagnostics.
PATTERN_LANGUAGE_CONFIG = {
    ".js": (_detect_ai_calls_js, "js_decision_analyser", "JS"),
    ".ts": (_detect_ai_calls_js, "js_decision_analyser", "TS"),
    ".jsx": (_detect_ai_calls_js, "js_decision_analyser", "JSX"),
    ".tsx": (_detect_ai_calls_js, "js_decision_analyser", "TSX"),
    ".go": (_detect_ai_calls_go, "go_decision_analyser", "Go"),
    ".rs": (_detect_ai_calls_rust, "rust_decision_analyser", "Rust"),
    ".cs": (_detect_ai_calls_csharp, "csharp_decision_analyser", "C#"),
}


# ── Consequence classification (Pass 2, NEW) ──────────────────────────────────

_MUTATION_RECEIVER_RE = re.compile(r"(?<![\w.)\]])([A-Za-z_$][\w$]*)\s*\.\s*(?:append|update|pop|extend)\s*\(")
_FUNCTION_START_RE = re.compile(r"^\s*(?:async\s+def|def|class|(?:export\s+)?(?:async\s+)?function)\b")


def _mutates_local_container(lines: list, line_num: int, stripped: str) -> bool:
    """True when every mutation on this line targets a list/dict/set that
    was created in the same function: adding to a local working list is
    not a consequential action. Attributes (``self.items.append``),
    parameters and module-level containers still count."""
    receivers = _MUTATION_RECEIVER_RE.findall(stripped)
    if not receivers:
        return False
    for name in set(receivers):
        creation = re.compile(
            rf"^\s*(?:(?:const|let|var)\s+)?{re.escape(name)}\s*(?::[^=]+)?=\s*"
            r"(?:\[|\{|list\(|dict\(|set\(|defaultdict\(|Counter\(|OrderedDict\()"
        )
        found = False
        for i in range(line_num - 2, max(-1, line_num - 200), -1):
            text = lines[i]
            if creation.search(text):
                found = True
                break
            if _FUNCTION_START_RE.search(text):
                break  # reached the start of the enclosing function
        if not found:
            return False
    return True


def _is_same_origin_fetch(lines: list, stripped: str) -> bool:
    """True for a browser ``fetch`` to a relative URL ('/api/...', or a
    template starting with a constant that holds one, directly or as the
    ``??`` default of a configurable value): a front end calling its own
    backend is not an external API call."""
    m = re.search(r"\bfetch\s*\(\s*([`'\"])([^`'\"]*)", stripped)
    if not m:
        return False
    url = m.group(2)
    if url.startswith("/") and not url.startswith("//"):
        return True
    const = re.match(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}", url)
    if const:
        decl = re.compile(
            rf"\b(?:const|let|var)\s+{re.escape(const.group(1))}\s*(?::[^=]+)?=\s*"
            r"(?:[^;\n]*\?\?\s*)?([`'\"])(?:/(?!/)|\1)"
        )
        return any(decl.search(text) for text in lines)
    return False


class ConsequenceClassifier:
    """
    Maps each decision point to the consequential action that follows it
    (if any), classifying its type, reversibility, and severity.

    "Consequential" actions are those identified in CONSEQUENCE_TYPE_PATTERNS:
    external API calls, database writes, deployments, file-system ops,
    payments, agent invocations, and state mutation.
    """

    IRREVERSIBLE_TYPES = {
        "external_api", "database", "deployment", "file_system", "payment_action",
    }

    def classify(self, decision_points: list, lines: list, window: int = 10) -> list:
        consequences = []
        for dp in decision_points:
            consequence = self._find_consequence(dp, lines, window)
            if consequence:
                consequences.append(consequence)
        return consequences

    def _find_consequence(self, dp: dict, lines: list, window: int) -> Optional[dict]:
        line_num = dp["line"]
        filepath = dp["location"].rsplit(":", 1)[0]
        search_lines = lines[line_num:min(len(lines), line_num + window)]

        dp_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
        dp_indent = len(dp_line) - len(dp_line.lstrip())

        for offset, line in enumerate(search_lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Stop searching once we leave the enclosing scope — a new
            # definition at or below the decision point's indentation
            # belongs to a different function/class.
            indent = len(line) - len(line.lstrip())
            if indent <= dp_indent and stripped.startswith(("def ", "class ", "@")):
                break

            for c_type, patterns in CONSEQUENCE_TYPE_PATTERNS.items():
                if any(pattern in stripped for pattern in patterns):
                    abs_line = line_num + offset + 1
                    if c_type == "state_mutation" and _mutates_local_container(lines, abs_line, stripped):
                        continue
                    if c_type == "external_api" and _is_same_origin_fetch(lines, stripped):
                        continue
                    return {
                        "decision_location": dp["location"],
                        "decision_type": dp["type"],
                        "consequence_type": c_type,
                        "location": f"{filepath}:{line_num + offset + 1}",
                        "action": stripped[:120],
                        "reversible": c_type not in self.IRREVERSIBLE_TYPES,
                        "severity": "critical" if c_type in self.IRREVERSIBLE_TYPES else "medium",
                    }
        return None


# ── Agent handover detection (Pass 4, NEW) ────────────────────────────────────

_GRAPH_BUILDER_CONSTRUCTORS = {
    "StateGraph", "WorkflowBuilder", "DiGraphBuilder", "GraphBuilder",
    "Pipeline", "Graph",
}
_GRAPH_EDGE_METHODS = {"add_edge", "connect"}

# JS/TS family 5 (agent-as-tool, LangChain.js's manual-wrap sub-variant):
# ``const scheduleEvent = tool(async (...) => { ... await calendarAgent
# .invoke(...) ... }, {...})`` then ``createAgent({ tools: [scheduleEvent] })``.
# Windowed (character-distance) matching, not balanced-brace parsing — JS/TS
# detection in this engine is pattern-based throughout, not AST-based.
_JS_TOOL_WRAP_DECL_RE = re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*tool\s*\(')
_JS_AGENT_CALL_RE = re.compile(r'(\w+)\.(?:invoke|run)\s*\(')
_JS_CREATE_AGENT_DECL_RE = re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*createAgent\s*\(')
_JS_TOOLS_LIST_RE = re.compile(r'tools\s*:\s*\[([^\]]*)\]')
_JS_WRAP_WINDOW = 800

# JS/TS family 7 (named subagent registry, open-agent-sdk-typescript):
# ``const BUILTIN_AGENTS: Record<string, AgentDefinition> = { Explore: {...},
# Plan: {...} }``. Uses proper brace-balance (_js_balanced_brace_span) rather
# than a character window, since a fixed window risks spilling past the
# object's closing brace into unrelated declarations.
_JS_AGENT_RECORD_DECL_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*:\s*Record<\s*string\s*,\s*AgentDefinition\s*>\s*=\s*\{'
)
_JS_RECORD_KEY_RE = re.compile(r'^\s{2,4}["\']?(\w+)["\']?\s*:\s*\{', re.MULTILINE)

# Family 3 (recursive self-delegation, depth-capped runtime spawn): a tool
# function — usually literally named one of these — recursively spawns a
# child instance of the same agent. Requires a depth-cap signal elsewhere in
# the file to corroborate; the depth cap, not the call itself, is this
# family's structural signature (see .claude/skills/agent-handover-detection).
_DELEGATION_TOOL_NAMES = {"delegate_task", "delegate_agent", "spawn_agent", "spawn_subagent"}
_DEPTH_PARAM_RE = re.compile(r'\b(max_spawn_depth|spawn_depth|max_depth|child_depth)\b')

# JS/TS equivalent (OpenClaw's own source: src/agents/subagent-spawn.ts /
# subagent-depth.ts — spawnSubagentDirect(...) with spawnDepth/childDepth
# tracking). Same two-signal requirement: depth-param presence corroborates
# the spawn-call name, since the call name alone is too easily an unrelated
# function of the same name.
_JS_DELEGATION_CALL_RE = re.compile(
    r'\b(?:spawnSubagentDirect|spawnSubagent|delegateTask|delegateAgent|spawnAgent)\s*\('
)
_JS_DEPTH_PARAM_RE = re.compile(r'\b(spawnDepth|childDepth|maxDepth|maxSpawnDepth)\b')
_JS_ENCLOSING_FUNCTION_RE = re.compile(
    r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\('
)

# Family 8 (team registry + publish/subscribe messaging): the handover
# signature is a publish + subscribe PAIR of definitions, not a call site —
# and confirmed real examples split that pair across multiple files
# (MetaGPT: Environment.publish_message in one file, Role._watch/
# set_addresses in another; open-agent-sdk-typescript: TeamCreateTool and
# SendMessageTool in separate files). Detected as a repo-wide pass, not a
# per-file detector, since neither half alone is the signature.
_PUBLISH_METHOD_NAMES = {"publish_message"}
_SUBSCRIBE_METHOD_NAMES = {"_watch", "set_addresses", "add_subscription"}
_JS_TEAM_TOOL_NAME_RE = re.compile(r"""name\s*:\s*['"]TeamCreate['"]""")
_JS_SEND_MESSAGE_TOOL_NAME_RE = re.compile(r"""name\s*:\s*['"]SendMessage['"]""")

# Family 1 variant (Semantic Kernel's Process Framework): a fluent
# edge-builder chain spelled with "event" terminology —
# ``step.on_event("X").send_event_to(target=other_step)`` — but this is a
# *declared* edge between two specific steps, not a decoupled broadcast to
# an unknown set of subscribers, so it's family 1 (graph/builder), not
# family 8 (pub/sub) despite the "event" naming. Confirmed real shape uses
# target= as a keyword, not a positional arg.
_SK_EVENT_TRIGGER_METHODS = {"on_event", "on_input_event", "on_function_result"}

# Constructor keyword arguments whose value is a list of agents — the
# list-composition family (CrewAI's agents=, AutoGen's participants=,
# Google ADK's sub_agents=, Semantic Kernel's members=) AND family 6's
# constructor-keyword handoff list (OpenAI Agents SDK's / Swarms'
# handoffs=) — structurally the same AST shape (a constructor keyword
# whose value is a list), just a different semantic label.
_LIST_COMPOSITION_KEYWORDS = {"agents", "participants", "sub_agents", "members", "handoffs"}


class AgentHandoverAnalyser:
    """
    AST-based detection of agent-to-agent handovers. Four independent
    detection passes, each matching a different real-world framework shape
    (see .claude/skills/agent-handover-detection for the source evidence):

    1. Variable-passing — the output of one agent call (e.g. ``agent_a.run(x)``)
       becomes the input of another agent call (e.g. ``agent_b.run(output_a)``).
    2. Graph/builder edges — ``StateGraph().add_node(...).add_edge(a, b)``
       (LangGraph, Microsoft Agent Framework, AutoGen) or
       ``pipeline.connect(sender, receiver)`` (Haystack).
    3. List-composition — ``Crew(agents=[...])``, ``RoundRobinGroupChat(
       participants=[...])``, ``Agent(sub_agents=[...])``,
       ``HandoffOrchestration(members=...)``.
    4. Constructor-keyword handoff list (family 6) — ``Agent(handoffs=[
       handoff(agent=faq_agent, on_handoff=..., tool_name_override=...),
       ...])`` (OpenAI Agents SDK's wrapper-object sub-variant) or
       ``Agent(handoffs=[agent1, agent2])`` (Swarms' flat-list sub-variant),
       plus the post-construction mutation
       ``faq_agent.handoffs.append(handoff(agent=triage_agent, ...))``.

    For each handover, checks whether a Pre-Node (validation/authorization/
    schema/approval) guards the receiving call — i.e. fires BEFORE the
    handover commits. Missing or weak Pre-Nodes here are the structural
    signature of CLUSTER-HANDOVER / DC-E13 (Propagating Corruption).
    """

    def analyse(self, source: str, filepath: str, lines: list) -> list:
        try:
            tree = _ast_parse_quiet(source, filepath)
        except (SyntaxError, ValueError, RecursionError):
            return []

        handovers = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                handovers.extend(self._scan_body(node.body, lines, filepath))
        handovers.extend(self._detect_graph_edges(tree, lines, filepath))
        handovers.extend(self._detect_list_composition(tree, lines, filepath))
        handovers.extend(self._detect_handoff_appends(tree, lines, filepath))
        handovers.extend(self._detect_agent_as_tool(tree, lines, filepath))
        handovers.extend(self._detect_decorator_tool_wrapping(tree, lines, filepath))
        handovers.extend(self._detect_named_registry(tree, lines, filepath))
        handovers.extend(self._detect_recursive_delegation(tree, source, lines, filepath))
        handovers.extend(self._detect_remote_agent_calls(tree, lines, filepath))
        handovers.extend(self._detect_sk_event_edges(tree, lines, filepath))
        return handovers

    # ── Family 1: graph/builder edges ─────────────────────────────────────

    def _chain_has_graph_builder_root(self, node) -> bool:
        """
        Does this (possibly fluent-chained) expression originate from a
        recognised graph-builder constructor, e.g.
        ``StateGraph().add_node(...).add_edge(...)``?
        """
        while True:
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in _GRAPH_BUILDER_CONSTRUCTORS:
                    return True
                if isinstance(func, ast.Attribute):
                    node = func.value
                    continue
                return False
            if isinstance(node, ast.Attribute):
                node = node.value
                continue
            return False

    def _collect_graph_builder_vars(self, tree: ast.AST) -> set:
        """Variables assigned the result of a recognised graph-builder
        constructor — e.g. ``workflow = StateGraph(AgentState)``."""
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if self._chain_has_graph_builder_root(node.value):
                    target = node.targets[0] if node.targets else None
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    def _literal_or_name(self, node) -> Optional[str]:
        """Best-effort readable label for an AST expression: a string
        constant's value, a bare name's identifier, or (for an inline
        constructor/wrapper call like ``Agent(name="x")`` or
        ``handoff(agent=faq_agent, ...)``) its name/agent/role keyword,
        resolved recursively — falling back to ``ast.unparse`` for
        anything else."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("name", "agent_name", "role", "agent"):
                    resolved = self._literal_or_name(kw.value)
                    if resolved:
                        return resolved
            if isinstance(node.func, (ast.Name, ast.Attribute)):
                return self._get_call_string(node.func)
        try:
            return ast.unparse(node)
        except Exception:
            return None

    def _detect_graph_edges(self, tree: ast.AST, lines: list, filepath: str) -> list:
        graph_vars = self._collect_graph_builder_vars(tree)
        handovers = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in _GRAPH_EDGE_METHODS:
                continue
            root = node.func.value
            is_graph_call = (
                self._chain_has_graph_builder_root(node)
                or (isinstance(root, ast.Name) and root.id in graph_vars)
            )
            if not is_graph_call:
                continue
            if len(node.args) < 2:
                continue
            from_label = self._literal_or_name(node.args[0])
            to_label = self._literal_or_name(node.args[1])
            if not from_label or not to_label:
                continue
            line_num = getattr(node, "lineno", 0)
            handovers.append(self._build_handover(
                {"agent": from_label, "line": line_num}, to_label, "", line_num, lines, filepath,
            ))
        return handovers

    # ── Family 2: list-composition ────────────────────────────────────────

    def _collect_assigned_names(self, tree: ast.AST) -> dict:
        """Map id(call_node) -> assigned variable name, e.g. for
        ``root_agent = Agent(...)`` maps the Agent(...) call to 'root_agent'.
        Preferred over the bare constructor name as a more readable label."""
        assigned = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                target = node.targets[0] if node.targets else None
                if isinstance(target, ast.Name):
                    assigned[id(node.value)] = target.id
        return assigned

    def _collect_list_vars(self, tree: ast.AST) -> dict:
        """Map variable name -> element nodes for ``agent_list = [a, b, c]``
        assignments — lets list-composition detection follow one level of
        same-file variable indirection (assign-then-pass), e.g.
        ``agents = [a, b]; Crew(agents=agents)``. Does not trace values
        returned from a function call (e.g. ``agents = get_agents()``) —
        that needs interprocedural analysis, out of scope here."""
        lists = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                target = node.targets[0] if node.targets else None
                if isinstance(target, ast.Name):
                    lists[target.id] = node.value.elts
        return lists

    def _detect_list_composition(self, tree: ast.AST, lines: list, filepath: str) -> list:
        assigned_names = self._collect_assigned_names(tree)
        list_vars = self._collect_list_vars(tree)
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg not in _LIST_COMPOSITION_KEYWORDS:
                    continue
                if isinstance(kw.value, ast.List):
                    elts = kw.value.elts
                elif isinstance(kw.value, ast.Name) and kw.value.id in list_vars:
                    elts = list_vars[kw.value.id]
                else:
                    continue
                members = [self._literal_or_name(el) for el in elts]
                members = [m for m in members if m]
                if not members:
                    continue
                orchestrator = (
                    assigned_names.get(id(node))
                    or self._get_call_string(node.func)
                    or "Orchestrator"
                )
                line_num = getattr(node, "lineno", 0)
                for member in members:
                    handovers.append(self._build_handover(
                        {"agent": orchestrator, "line": line_num}, member, "", line_num, lines, filepath,
                    ))
        return handovers

    def _detect_handoff_appends(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """Family 6's post-construction mutation form —
        ``faq_agent.handoffs.append(handoff(agent=triage_agent, ...))``."""
        handovers = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "append" or not node.args:
                continue
            target = node.func.value
            if not (isinstance(target, ast.Attribute) and target.attr == "handoffs"):
                continue
            from_agent = self._literal_or_name(target.value)
            to_agent = self._literal_or_name(node.args[0])
            if not from_agent or not to_agent:
                continue
            line_num = getattr(node, "lineno", 0)
            handovers.append(self._build_handover(
                {"agent": from_agent, "line": line_num}, to_agent, "", line_num, lines, filepath,
            ))
        return handovers

    # ── Family 5: agent-as-tool ────────────────────────────────────────────

    def _detect_agent_as_tool(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """OpenAI Agents SDK's built-in sub-variant — a sub-agent wrapped via
        its own ``.as_tool(...)`` method and passed straight into another
        agent's ``tools=[...]``: ``Agent(tools=[spanish_agent.as_tool(...),
        ...])``."""
        assigned_names = self._collect_assigned_names(tree)
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "tools" or not isinstance(kw.value, ast.List):
                    continue
                orchestrator = (
                    assigned_names.get(id(node))
                    or self._get_call_string(node.func)
                    or "Orchestrator"
                )
                line_num = getattr(node, "lineno", 0)
                for el in kw.value.elts:
                    if not (isinstance(el, ast.Call) and isinstance(el.func, ast.Attribute)):
                        continue
                    if el.func.attr != "as_tool":
                        continue
                    to_agent = self._literal_or_name(el.func.value)
                    if to_agent:
                        handovers.append(self._build_handover(
                            {"agent": orchestrator, "line": line_num}, to_agent, "", line_num, lines, filepath,
                        ))
        return handovers

    def _detect_decorator_tool_wrapping(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """Pydantic AI's decorator sub-variant — ``@triage_agent.tool``
        applied to a function whose body calls a *different* agent's
        ``.run(``/``.invoke(``, e.g.
        ``@triage_agent.tool\\nasync def consult_specialist(ctx, ...):
        result = await specialist_agent.run(...)``."""
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            orchestrator = None
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and dec.attr == "tool" and isinstance(dec.value, ast.Name):
                    orchestrator = dec.value.id
                    break
            if not orchestrator:
                continue
            for inner in ast.walk(node):
                if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)):
                    continue
                if inner.func.attr not in ("run", "invoke"):
                    continue
                root = inner.func.value
                if isinstance(root, ast.Name) and root.id != orchestrator:
                    line_num = getattr(inner, "lineno", 0)
                    handovers.append(self._build_handover(
                        {"agent": orchestrator, "line": line_num}, root.id, "", line_num, lines, filepath,
                    ))
        return handovers

    # ── Family 7: named subagent registry ─────────────────────────────────

    def _detect_named_registry(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """Claude Agent SDK's shape — a dict keyed by name on a single
        options object: ``ClaudeAgentOptions(agents={"code-reviewer":
        AgentDefinition(...)})``. Distinct from family 2's same-named
        ``agents=`` keyword by value type: family 2 requires a List,
        this requires a Dict."""
        assigned_names = self._collect_assigned_names(tree)
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "agents" or not isinstance(kw.value, ast.Dict):
                    continue
                orchestrator = (
                    assigned_names.get(id(node))
                    or self._get_call_string(node.func)
                    or "Orchestrator"
                )
                line_num = getattr(node, "lineno", 0)
                for key_node in kw.value.keys:
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        handovers.append(self._build_handover(
                            {"agent": orchestrator, "line": line_num}, key_node.value, "", line_num, lines, filepath,
                        ))
        return handovers

    # ── Family 3: recursive self-delegation ───────────────────────────────

    def _build_parent_map(self, tree: ast.AST) -> dict:
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        return parents

    def _enclosing_def_name(self, node, parent_map: dict) -> Optional[str]:
        current = parent_map.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return current.name
            current = parent_map.get(current)
        return None

    def _detect_recursive_delegation(self, tree: ast.AST, source: str, lines: list, filepath: str) -> list:
        """Hermes/OpenClaw/Omnigent's shape — a tool function
        (``delegate_task``/``spawn_agent``/...) recursively spawns a child
        instance of the same agent, bounded by a depth-cap parameter. The
        depth cap (``max_spawn_depth``/``MAX_DEPTH``/...) must be present
        somewhere in the file to corroborate — the call name alone is too
        easily an unrelated function of the same name."""
        if not _DEPTH_PARAM_RE.search(source):
            return []
        parent_map = self._build_parent_map(tree)
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_str = self._get_call_string(node.func)
            if not call_str:
                continue
            if call_str.split(".")[-1] not in _DELEGATION_TOOL_NAMES:
                continue
            from_agent = self._enclosing_def_name(node, parent_map) or "Orchestrator"
            line_num = getattr(node, "lineno", 0)
            handovers.append(self._build_handover(
                {"agent": from_agent, "line": line_num}, "<delegated subagent>", "", line_num, lines, filepath,
            ))
        return handovers

    # ── Family 4: protocol/server (network handshake) ─────────────────────

    def _detect_remote_agent_calls(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """A client object calling a remotely, independently-deployed
        agent/workflow over a network boundary — distinct from every other
        family, no in-process call chain. Three confirmed shapes:

        - AP2's ``PaymentRemoteA2aClient(name="merchant_agent",
          base_url="http://...", ...)`` — any ``*Client(...)`` constructor
          carrying both a ``name=`` and a ``base_url=`` keyword.
        - llama_deploy's ``WorkflowClient.run_workflow(workflow_name,
          ...)`` — a ``.run_workflow(`` call, naming its target by string.
        - CrewAI's ``execute_a2a_delegation(endpoint=..., agent_id=...,
          from_agent=..., ...)`` / ``aexecute_a2a_delegation(...)`` — a
          bare function call (not a method on a client object), naming
          its target via ``agent_id=`` rather than ``name=``.
        """
        assigned_names = self._collect_assigned_names(tree)
        handovers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if isinstance(node.func, ast.Name) and node.func.id.endswith("Client"):
                kw_values = {kw.arg: kw.value for kw in node.keywords}
                if "name" in kw_values and "base_url" in kw_values:
                    to_agent = self._literal_or_name(kw_values["name"])
                    if to_agent:
                        from_agent = assigned_names.get(id(node)) or node.func.id
                        line_num = getattr(node, "lineno", 0)
                        handovers.append(self._build_handover(
                            {"agent": from_agent, "line": line_num}, to_agent, "", line_num, lines, filepath,
                        ))

            if isinstance(node.func, ast.Attribute) and node.func.attr == "run_workflow" and node.args:
                to_agent = self._literal_or_name(node.args[0])
                if to_agent:
                    from_agent = self._literal_or_name(node.func.value) or "Orchestrator"
                    line_num = getattr(node, "lineno", 0)
                    handovers.append(self._build_handover(
                        {"agent": from_agent, "line": line_num}, to_agent, "", line_num, lines, filepath,
                    ))

            if isinstance(node.func, ast.Name) and node.func.id in (
                "execute_a2a_delegation", "aexecute_a2a_delegation",
            ):
                kw_values = {kw.arg: kw.value for kw in node.keywords}
                to_agent = None
                for key in ("agent_id", "agent_role", "endpoint"):
                    if key in kw_values:
                        to_agent = self._literal_or_name(kw_values[key])
                        if to_agent:
                            break
                if to_agent:
                    from_agent = (
                        self._literal_or_name(kw_values["from_agent"])
                        if "from_agent" in kw_values else None
                    ) or "Orchestrator"
                    line_num = getattr(node, "lineno", 0)
                    handovers.append(self._build_handover(
                        {"agent": from_agent, "line": line_num}, to_agent, "", line_num, lines, filepath,
                    ))
        return handovers

    def _detect_sk_event_edges(self, tree: ast.AST, lines: list, filepath: str) -> list:
        """Semantic Kernel's Process Framework — ``step.on_event("X")
        .send_event_to(target=other_step, ...)``. A fluent edge-builder
        chain spelled with event terminology, but the edge is a *declared*
        link between two specific steps (family 1), not a decoupled
        broadcast to an unknown set of subscribers (family 8)."""
        handovers = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "send_event_to":
                continue
            target_node = None
            for kw in node.keywords:
                if kw.arg == "target":
                    target_node = kw.value
                    break
            if target_node is None and node.args:
                target_node = node.args[0]
            if target_node is None:
                continue

            trigger_call = node.func.value
            if not (isinstance(trigger_call, ast.Call) and isinstance(trigger_call.func, ast.Attribute)):
                continue
            if trigger_call.func.attr not in _SK_EVENT_TRIGGER_METHODS:
                continue

            from_step = self._literal_or_name(trigger_call.func.value)
            to_step = self._literal_or_name(target_node)
            if from_step and to_step:
                line_num = getattr(node, "lineno", 0)
                handovers.append(self._build_handover(
                    {"agent": from_step, "line": line_num}, to_step, "", line_num, lines, filepath,
                ))
        return handovers

    def _scan_body(self, body: list, lines: list, filepath: str) -> list:
        handovers = []
        produced = {}  # var_name -> {"agent": agent_name, "line": line_num}

        for stmt in body:
            call_node, target_var = self._extract_call(stmt)
            if call_node is None:
                continue

            call_str = self._get_call_string(call_node.func)
            if not call_str or "." not in call_str:
                continue

            agent_name, method = call_str.rsplit(".", 1)
            if method not in AGENT_HANDOVER_METHODS:
                continue

            line_num = getattr(call_node, "lineno", 0)

            for arg_name in self._arg_names(call_node):
                if arg_name in produced:
                    handovers.append(
                        self._build_handover(produced[arg_name], agent_name, arg_name, line_num, lines, filepath)
                    )

            if target_var:
                produced[target_var] = {"agent": agent_name, "line": line_num}

        return handovers

    def _extract_call(self, stmt) -> tuple:
        """Return (Call node, assigned variable name or None) for a top-level statement."""
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            target = stmt.targets[0] if stmt.targets else None
            target_var = target.id if isinstance(target, ast.Name) else None
            return stmt.value, target_var
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return stmt.value, None
        return None, None

    def _arg_names(self, call_node: ast.Call) -> list:
        names = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name):
                names.append(arg.id)
        for kw in call_node.keywords:
            if isinstance(kw.value, ast.Name):
                names.append(kw.value.id)
        return names

    def _get_call_string(self, func_node) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            obj = self._get_call_string(func_node.value)
            if obj:
                return f"{obj}.{func_node.attr}"
            return func_node.attr
        return None

    def _build_handover(self, source_info: dict, to_agent: str, data_var: str, line_num: int, lines: list, filepath: str) -> dict:
        pre_node = _assess_pre_node_strength(lines, line_num)
        vsl_report = getattr(self, "vsl_report", None)
        vsl_gate = vsl_report.gated_node_gate(filepath, to_agent) if vsl_report else None
        if vsl_gate:
            pre_node = _strongest_pre_node(pre_node, {
                "type": "vsl_gate", "strength": _vsl.VSL_GATE_STRENGTH, "evidence_line": vsl_gate,
            })
        pre_node_exists = pre_node is not None and pre_node["strength"] >= GOVERNANCE_STRENGTH_THRESHOLD

        return {
            "from_agent": source_info["agent"],
            "to_agent": to_agent,
            "from_location": f"{filepath}:{source_info['line']}",
            "location": f"{filepath}:{line_num}",
            "data_passed": data_var,
            "input_validation": pre_node_exists,
            "output_validation": False,
            "pre_node_exists": pre_node_exists,
            "pre_node": pre_node,
            "drift_class": None if pre_node_exists else "CLUSTER-HANDOVER + DC-E13",
            "governance_gap": (
                None if pre_node_exists else (
                    f"Agent output ('{data_var}') passed from {source_info['agent']} to "
                    f"{to_agent} without a validation Pre-Node"
                    if data_var else
                    f"Handover from {source_info['agent']} to {to_agent} without a "
                    f"validation Pre-Node"
                )
            ),
            "severity": "low" if pre_node_exists else "high",
        }

    def analyse_js(self, content: str, filepath: str, lines: list) -> list:
        """
        Pattern-based (non-AST) handover detection for JS/TS:

        - Family 5's manual-wrap sub-variant (LangChain.js): a sub-agent is
          wrapped inside a ``tool(...)`` call whose body invokes that
          agent, and the resulting tool is later passed into another
          agent's ``createAgent({ tools: [...] })``.
        - Family 7 (open-agent-sdk-typescript): a dict keyed by name,
          ``const BUILTIN_AGENTS: Record<string, AgentDefinition> = {
          Explore: {...}, Plan: {...} }``.
        - Family 3 (OpenClaw): a call to ``spawnSubagentDirect(...)`` (or a
          reasonable variant name), corroborated by a depth-tracking
          identifier (``spawnDepth``/``childDepth``/...) present somewhere
          in the file — same two-signal requirement as the Python version.
        """
        handovers = []
        tool_to_agent = {}
        for m in _JS_TOOL_WRAP_DECL_RE.finditer(content):
            tool_var = m.group(1)
            window = content[m.end():m.end() + _JS_WRAP_WINDOW]
            inner = _JS_AGENT_CALL_RE.search(window)
            if inner and inner.group(1) != tool_var:
                tool_to_agent[tool_var] = inner.group(1)

        if tool_to_agent:
            for m in _JS_CREATE_AGENT_DECL_RE.finditer(content):
                orchestrator_var = m.group(1)
                window = content[m.end():m.end() + _JS_WRAP_WINDOW]
                tools_match = _JS_TOOLS_LIST_RE.search(window)
                if not tools_match:
                    continue
                line_num = content[:m.start()].count("\n") + 1
                for tool_name in re.findall(r'\w+', tools_match.group(1)):
                    to_agent = tool_to_agent.get(tool_name)
                    if to_agent:
                        handovers.append(self._build_handover(
                            {"agent": orchestrator_var, "line": line_num}, to_agent, "", line_num, lines, filepath,
                        ))

        for m in _JS_AGENT_RECORD_DECL_RE.finditer(content):
            registry_var = m.group(1)
            span = _js_balanced_brace_span(content, m.end())
            line_num = content[:m.start()].count("\n") + 1
            for key_m in _JS_RECORD_KEY_RE.finditer(span):
                handovers.append(self._build_handover(
                    {"agent": registry_var, "line": line_num}, key_m.group(1), "", line_num, lines, filepath,
                ))

        if _JS_DEPTH_PARAM_RE.search(content):
            enclosing_fns = list(_JS_ENCLOSING_FUNCTION_RE.finditer(content))
            for m in _JS_DELEGATION_CALL_RE.finditer(content):
                line_num = content[:m.start()].count("\n") + 1
                from_agent = "Orchestrator"
                for fn_m in enclosing_fns:
                    if fn_m.start() < m.start():
                        from_agent = fn_m.group(1)
                    else:
                        break
                handovers.append(self._build_handover(
                    {"agent": from_agent, "line": line_num}, "<delegated subagent>", "", line_num, lines, filepath,
                ))

        return handovers


# ── Cluster governance analysis (Pass 5, NEW) ─────────────────────────────────

class ClusterGovernanceAnalyser:
    """
    Groups agent handovers (Pass 4 output) by file into sequential agent
    pipelines and identifies cluster-level governance gaps — places where
    a corrupted output at one stage can propagate, unchecked, through the
    rest of the pipeline (DC-E13, Propagating Corruption).
    """

    def analyse(self, handovers: list) -> list:
        by_file = {}
        for h in handovers:
            filepath = h["location"].rsplit(":", 1)[0]
            by_file.setdefault(filepath, []).append(h)

        cluster_gaps = []
        for filepath, file_handovers in by_file.items():
            if len(file_handovers) < 2:
                continue

            ordered = sorted(file_handovers, key=lambda h: int(h["location"].rsplit(":", 1)[1]))

            agents = []
            for h in ordered:
                if h["from_agent"] not in agents:
                    agents.append(h["from_agent"])
                if h["to_agent"] not in agents:
                    agents.append(h["to_agent"])

            gaps = [
                {
                    "from": f"{h['from_agent']} -> {h['to_agent']}",
                    "location": h["location"],
                    "validation_prenode": h["pre_node_exists"],
                    "risk": "DC-E13 (Propagating Corruption)",
                }
                for h in ordered
                if not h["pre_node_exists"]
            ]

            if gaps:
                cluster_gaps.append({
                    "id": f"CLUSTER-GAP-{len(cluster_gaps)+1:03d}",
                    "cluster_type": "sequential_agents",
                    "file": filepath,
                    "agents": agents,
                    "gaps": gaps,
                    "cluster_risk": (
                        "A corrupted output at any ungated stage propagates through the "
                        "remaining pipeline with nothing to stop it — DC-E13, Propagating Corruption."
                    ),
                    "recommended_action": (
                        "Add a validation Pre-Node before every ungated handover listed above."
                    ),
                })

        return cluster_gaps


def _build_pubsub_handover(from_agent: str, from_location: str, to_agent: str, to_location: str) -> dict:
    return {
        "from_agent": from_agent,
        "to_agent": to_agent,
        "from_location": from_location,
        "location": to_location,
        "data_passed": "",
        "input_validation": False,
        "output_validation": False,
        "pre_node_exists": False,
        "pre_node": None,
        "drift_class": "CLUSTER-HANDOVER + DC-E13",
        "governance_gap": (
            f"Publish/subscribe handover from {from_agent} to {to_agent} "
            f"without a validation Pre-Node"
        ),
        "severity": "high",
    }


def _detect_pubsub_messaging(parsed: list) -> list:
    """
    Pass 4 (repo-wide) — family 8: team registry + publish/subscribe
    messaging. Unlike every other handover family, the signature is a
    publish + subscribe PAIR of definitions, and confirmed real examples
    split that pair across multiple files — so this runs once over the
    whole repo's parsed files, not per-file like the rest of
    AgentHandoverAnalyser.
    """
    publish_loc = subscribe_loc = team_loc = send_loc = None

    for file_data in parsed:
        if file_data["extension"] == ".py" and (publish_loc is None or subscribe_loc is None):
            try:
                tree = _ast_parse_quiet(file_data["content"], str(file_data["path"]))
            except (SyntaxError, ValueError, RecursionError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if publish_loc is None and node.name in _PUBLISH_METHOD_NAMES:
                    publish_loc = f"{file_data['path']}:{getattr(node, 'lineno', 0)}"
                elif subscribe_loc is None and node.name in _SUBSCRIBE_METHOD_NAMES:
                    subscribe_loc = f"{file_data['path']}:{getattr(node, 'lineno', 0)}"

        elif file_data["extension"] in (".js", ".ts", ".jsx", ".tsx") and (team_loc is None or send_loc is None):
            content = file_data["content"]
            if team_loc is None:
                m = _JS_TEAM_TOOL_NAME_RE.search(content)
                if m:
                    line_num = content[:m.start()].count("\n") + 1
                    team_loc = f"{file_data['path']}:{line_num}"
            if send_loc is None:
                m = _JS_SEND_MESSAGE_TOOL_NAME_RE.search(content)
                if m:
                    line_num = content[:m.start()].count("\n") + 1
                    send_loc = f"{file_data['path']}:{line_num}"

    handovers = []
    if publish_loc and subscribe_loc:
        handovers.append(_build_pubsub_handover("Environment", publish_loc, "<subscribed roles>", subscribe_loc))
    if team_loc and send_loc:
        handovers.append(_build_pubsub_handover("TeamCreate", team_loc, "<message recipients>", send_loc))
    return handovers


def _detect_terminal_states(decision_points: list) -> list:
    """
    Pass 5 (additional) — flag try/except blocks that catch an exception
    with no recovery action (a bare ``except: pass`` or equivalent). Once
    entered, these blocks leave the system in an unrecoverable Terminal
    State: the error is swallowed and execution proceeds as if nothing
    happened, with no governance record of the failure.
    """
    terminal_states = []
    for dp in decision_points:
        if dp["type"] != "try_except":
            continue
        if not dp.get("has_recovery"):
            terminal_states.append(TerminalState(
                id=f"TERMINAL-{len(terminal_states)+1:03d}",
                type="unhandled_exception_no_recovery",
                location=dp["location"],
                severity="high" if dp.get("bare_except") else "medium",
                plain_english=(
                    f"The except block at {dp['location']} catches all exceptions and "
                    f"takes no recovery action — failures are silently discarded."
                ),
                consequence=(
                    "Execution proceeds as if no error occurred. No governance record "
                    "of the failure is created, and the system may continue operating "
                    "on an invalid state."
                ),
                recommended_action=(
                    "Catch specific exception types and either recover explicitly "
                    "(retry, fallback, compensating action) or re-raise after logging "
                    "to a governance record."
                ),
            ).to_dict())
    return terminal_states


# ── Legion operational semantics — evidence layer & lifecycle ─────────────────
#
# Layer 1 constants — confidence label ↔ float mapping (canonical values).
# All Legion confidence scores must be one of these three values so that
# deduplication and lifecycle updates produce predictable orderings.

_CONFIDENCE_FLOAT: Dict[str, float] = {
    "HIGH": 0.9,
    "MEDIUM": 0.6,
    "SPECULATIVE": 0.3,
}

# Evidence type mapping from heuristic pattern_type
_EVIDENCE_TYPE_MAP: Dict[str, str] = {
    "structural": "call_graph",
    "cfg": "cfg_node",
    "ast": "ast_pattern",
    "keyword": "code_pattern",
}

# Specific matched_pattern values that override heuristic-derived evidence_type
_CALL_GRAPH_PATTERNS = frozenset({
    "agent_handover_no_prenode",
    "chained_ai_calls",
    "cluster_governance_gap",
})
_CFG_PATTERNS = frozenset({
    "confidence_gate_no_correctness_check",
})


def _compute_canonical_hash(
    file_path: str, line_number: int, dc_code: str, legion_code: str, matched_pattern: str
) -> str:
    """Deterministic SHA256-based identifier for a Legion instance.

    Guarantee: given identical (dc_code, legion_code, file_path, line_number,
    matched_pattern), this function always returns the same 16-character hex
    string, across runs, environments, and independent implementations.

    This is the deduplication key — two Legion instances with the same
    canonical_hash represent the same structural finding.
    """
    key = f"{dc_code}:{legion_code}:{file_path}:{line_number}:{matched_pattern or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _compute_evidence_hash(type_: str, source: str, file_path: str, line_number: int) -> str:
    """Deterministic hash for an EvidenceNode — same structural evidence at
    the same location always maps to the same identifier."""
    key = f"{type_}:{source}:{file_path}:{line_number}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _extract_evidence_nodes(primitives: dict) -> List[EvidenceNode]:
    """Layer 2 — Evidence Graph extraction.

    Maps the three categories of scan primitives to their evidence types:
      - decision_points → cfg_node  (CFG branches from DecisionPointAnalyser)
      - agent_handovers → call_edge (call-graph edges from Pass 4)
      - ai_integrations → ast_pattern (AST-detected AI calls)

    Determinism guarantee: given the same primitives dict (same keys in the
    same order), this function always returns the same list of EvidenceNodes
    with the same canonical_hashes. The ordering is input-order-stable.
    """
    evidence: List[EvidenceNode] = []

    for dp in primitives.get("decision_points", []):
        fp, _, ln = dp["location"].rpartition(":")
        n = int(ln) if ln.isdigit() else 0
        evidence.append(EvidenceNode(
            type="cfg_node",
            source=dp["type"],
            payload={"condition": dp.get("condition", ""), "call": dp.get("call", "")},
            confidence=0.7,
            file_path=fp,
            line_number=n,
            canonical_hash=_compute_evidence_hash("cfg_node", dp["type"], fp, n),
        ))

    for h in primitives.get("agent_handovers", []):
        fp, _, ln = h["location"].rpartition(":")
        n = int(ln) if ln.isdigit() else 0
        src = f"{h.get('from_agent', '')} -> {h.get('to_agent', '')}"
        evidence.append(EvidenceNode(
            type="call_edge",
            source=src,
            payload={"governed": h.get("pre_node_exists", False),
                     "governance_gap": h.get("governance_gap", "")},
            confidence=0.9 if not h.get("pre_node_exists") else 0.3,
            file_path=fp,
            line_number=n,
            canonical_hash=_compute_evidence_hash("call_edge", src, fp, n),
        ))

    for ai in primitives.get("ai_integrations", []):
        fp, _, ln = ai["location"].rpartition(":")
        n = int(ln) if ln.isdigit() else 0
        evidence.append(EvidenceNode(
            type="ast_pattern",
            source="ai_call",
            payload={"provider": ai.get("provider"), "governed": ai.get("pre_node_detected", False)},
            confidence=0.8,
            file_path=fp,
            line_number=n,
            canonical_hash=_compute_evidence_hash("ast_pattern", "ai_call", fp, n),
        ))

    return evidence


def _dedup_legions(legions: List[Legion]) -> List[Legion]:
    """Layer 4 lifecycle — deduplicate Legion instances by canonical_hash.

    When the same structural pattern is detected by multiple heuristics
    (e.g. an ungated agent handover matched by both _match_agent_handovers
    and _match_keyword_legions), the instance with the highest
    confidence_float is kept and the lower-confidence duplicate discarded.

    Input order is otherwise preserved.
    """
    seen: Dict[str, Legion] = {}
    for legion in legions:
        h = legion.canonical_hash
        if h not in seen or legion.confidence_float > seen[h].confidence_float:
            seen[h] = legion
    return list(seen.values())


def _update_legion_confidence(legion: Legion, new_evidence: List[EvidenceNode]) -> None:
    """Layer 4 lifecycle — update a Legion's confidence from new evidence.

    Called when a retrace or incremental scan surfaces additional evidence
    for an already-detected Legion. Confidence only ever increases (new
    evidence cannot lower a confirmed HIGH finding to SPECULATIVE).
    Updates last_updated to the current UTC timestamp.
    """
    if not new_evidence:
        return
    max_conf = max(e.confidence for e in new_evidence)
    if max_conf <= legion.confidence_float:
        return
    legion.confidence_float = max_conf
    if max_conf >= 0.8:
        legion.confidence = "HIGH"
    elif max_conf >= 0.5:
        legion.confidence = "MEDIUM"
    else:
        legion.confidence = "SPECULATIVE"
    legion.last_updated = datetime.now(timezone.utc).isoformat()


# ── Pass 6.5 — per-gap drift exposure enrichment ─────────────────────────────

def _flat_dc_entries(dc_classes_complete: dict) -> dict:
    """Return a flat {dc_code: entry} dict from the nested drift_classes structure."""
    flat: dict = {}
    for tier_group in dc_classes_complete.get("drift_classes", {}).values():
        if isinstance(tier_group, dict):
            flat.update(tier_group)
    return flat


_CONTRAINDICATION_REASONS: dict = {}
"""Populated lazily from dc_classes_complete.json by _build_contraindication_reasons()."""


def _build_contraindication_reasons(dc_classes_complete: dict) -> dict:
    """Build a (so_code, dc_code) → {reason, predicted_failure_state} lookup
    from the critical_contraindications section of dc_classes_complete.json."""
    result: dict = {}
    so_operators = dc_classes_complete.get("stabilisation_operators", {})
    critical = dc_classes_complete.get("critical_contraindications", {})

    for so_code, so_info in so_operators.items():
        for dc_code in (so_info.get("contraindicated_on") or []):
            detail = next(
                (
                    c for c in critical.values()
                    if so_code in c.get("prohibition", "") and dc_code in c.get("prohibition", "")
                ),
                None,
            )
            result[(so_code, dc_code)] = {
                "reason": (
                    detail["description"] if detail
                    else f"Do not apply {so_code} to {dc_code}."
                ),
                "predicted_failure_state": detail.get("predicted_failure_state") if detail else None,
            }
    return result


def _so_for_dc(dc_code: str, dc_entries: dict, so_entries: dict) -> dict:
    """Return the primary SO recommendation for a DC, with contraindication check.

    Checks all documented contraindications from dc_classes_complete.json:
      SO-1 + DC-I10 → Deadlock State (boundary enforced but signal invisible)
      SO-4 + DC-I13 → Spurious Attractor Creation (no attractor to disrupt)
      SO-8 + DC-I11 → Decoupled Clone (reinitialises the decoupling, not the state)
    """
    entry = dc_entries.get(dc_code, {})
    so_raw = entry.get("primary_so", "").split(",")[0].strip()
    so = so_entries.get(so_raw, {})
    contraindicated = so.get("contraindicated_on") or []

    warning = None
    if dc_code in contraindicated:
        lookup = _CONTRAINDICATION_REASONS.get((so_raw, dc_code))
        if lookup:
            pfs = lookup.get("predicted_failure_state", "")
            reason = lookup.get("reason", "")
            warning = (
                f"CONTRAINDICATION: Do not apply {so_raw} to {dc_code}. "
                f"Predicted failure state: {pfs}. "
                f"{reason}"
            )
        else:
            warning = f"CONTRAINDICATION: Do not apply {so_raw} to {dc_code}."

    return {
        "code": so_raw,
        "name": so.get("name", ""),
        "proposed_function": so.get("proposed_function", ""),
        "contraindicated_on": contraindicated,
        "contraindication_warning": warning,
    }


def _generate_fix_suggestion(gap: dict, dc_code: str, dc_name: str, so_data: dict) -> str:
    """Generate a contextual, actionable fix suggestion combining gap type + DC + SO."""
    gap_type = gap.get("type", "")
    so_code = so_data.get("code", "")
    so_name = so_data.get("name", "")
    location = gap.get("location", "")

    if gap_type == "missing_pre_node":
        return (
            f"Add a {so_code} ({so_name}) checkpoint immediately before {location}. "
            f"This is a {dc_name} ({dc_code}) pattern — the AI call proceeds without "
            f"a verified structural constraint. The Pre-Node must block execution if "
            f"the check fails (hard enforcement, not a soft warning)."
        )
    if gap_type == "ungoverned_decision_point":
        return (
            f"Gate the decision at {location} with {so_code} ({so_name}). "
            f"{dc_code} ({dc_name}) — this decision is reachable without a structural "
            f"guard. Add a control-flow check whose failure branch raises or returns "
            f"before the consequence executes."
        )
    if gap_type == "ungated_irreversible_action":
        return (
            f"Apply {so_code} ({so_name}) before the irreversible action at {location}. "
            f"{dc_code} ({dc_name}) — once executed this action cannot be undone. "
            f"The Pre-Node must verify all preconditions and abort on failure."
        )
    return (
        f"Implement {so_code} ({so_name}) at {location} to address {dc_code} ({dc_name})."
    )


def _enrich_gaps_with_drift_exposure(
    gaps: list,
    legion_matches: list,
    dc_entries: dict,
    so_entries: dict,
) -> None:
    """Pass 6.5 — attach drift_exposure to each gap dict, only when there is
    real structural evidence for the specific Drift Class involved.

    Matching strategy (per gap):
      1. Same-file HIGH/MEDIUM match — the only signal that actually says
         something about *this* gap, not just "a confirmed Legion exists
         somewhere in the scan."

    Previously this fell back to "any HIGH/MEDIUM match anywhere in the
    scan" or "the best SPECULATIVE match" when no same-file match existed —
    that produced DC labels with no real connection to the gap they were
    attached to (e.g. an unrelated file's confirmed match getting borrowed
    for a gap that has nothing to do with it). Most gaps are generic
    Pre-Node gaps that don't exhibit any specific Drift Class mechanism —
    leaving drift_exposure unset for those is the correct, honest result,
    not a regression. Mutates gap dicts in place. Gracefully skips if data
    is missing.
    """
    if not legion_matches or not dc_entries:
        return

    def _file_of(loc: str) -> str:
        return loc.split(":")[0] if ":" in loc else loc

    high_med = [m for m in legion_matches if m.get("confidence") in ("HIGH", "MEDIUM")]

    for gap in gaps:
        gap_file = _file_of(gap.get("location", ""))

        match = next((m for m in high_med if _file_of(m.get("location", "")) == gap_file), None)
        if not match:
            continue

        dc_code = match.get("dc_code", "")
        dc_entry = dc_entries.get(dc_code, {})
        so_data = _so_for_dc(dc_code, dc_entries, so_entries)
        dc_name = match.get("dc_name", dc_entry.get("name", ""))

        gap["drift_exposure"] = {
            "dc_code": dc_code,
            "dc_name": dc_name,
            "dc_definition": dc_entry.get("operational_definition", ""),
            "tier": dc_entry.get("tier", ""),
            "category": dc_entry.get("category", ""),
            "legion_code": match.get("legion_code", ""),
            "legion_name": match.get("legion_name", ""),
            "confidence": match.get("confidence", "SPECULATIVE"),
            "evidence": match.get("evidence", ""),
            "stabilising_operator": so_data,
            "fix_suggestion": _generate_fix_suggestion(gap, dc_code, dc_name, so_data),
            "vsl_template": f"TEMPLATE ONLY — requires VSL compiler (coming v0.6.0)",
        }


# ── Drift Class / Legion matching (Pass 6, NEW, data-driven) ──────────────────

# Patterns shorter than this are too generic to use for keyword matching —
# they would match almost any line of code and produce noise rather than signal.
_MIN_KEYWORD_PATTERN_LEN = 4


class LegionMatcher:
    """
    Pass 6 — data-driven Drift Class / Legion detection.

    Loads its signatures entirely from LEGION_DETECTION_PATTERNS.json (one
    entry per Drift Class, each with its primary Legions and 1-2 heuristic
    detection patterns) and cross-references dc_classes_complete.json for
    DC metadata (name, tier, primary SO, contraindications).

    Every match is a HYPOTHESIS, not a fact. confidence is one of:
      - HIGH        — directly computed from structural analysis
                      (e.g. an ungated agent handover from Pass 4).
      - MEDIUM      — a reasonably specific code pattern match.
      - SPECULATIVE — a keyword match derived from the Legion's name only;
                      no verified detection signature exists. Flag for
                      human review, not a confirmed finding.

    Zero Drift Classes are hardcoded here — everything comes from the two
    JSON files passed to __init__.
    """

    def __init__(self, legion_patterns: dict, dc_classes_complete: dict):
        self.legion_patterns = legion_patterns or {}
        self.dc_classes_complete = dc_classes_complete or {}

    def match(self, primitives: dict) -> list:
        """Run all heuristics, deduplicate by canonical_hash, return dicts.

        Layer 3 — deterministic extraction algorithm:
          1. Collect Legion instances from all heuristics (stable input order)
          2. Sort by canonical_hash before dedup (stable sort guarantees same
             Legion ordering for identical inputs across environments)
          3. Deduplicate — same canonical_hash → keep highest confidence_float
          4. Convert to dicts (backward-compatible shape via Legion.to_dict())
        """
        legions: List[Legion] = []
        legions.extend(self._match_confidence_gates(primitives))
        legions.extend(self._match_validation_unused(primitives))
        legions.extend(self._match_agent_handovers(primitives))
        legions.extend(self._match_chained_ai_calls(primitives))
        legions.extend(self._match_cluster_gaps(primitives))
        legions.extend(self._match_keyword_legions(primitives, already_matched=legions))
        legions.sort(key=lambda l: l.canonical_hash)
        legions = _dedup_legions(legions)
        return [l.to_dict() for l in legions]

    # ── shared helpers ──────────────────────────────────────────────────

    def _dc_meta(self, dc_code: str) -> dict:
        for tier_group in self.dc_classes_complete.get("drift_classes", {}).values():
            if dc_code in tier_group:
                return tier_group[dc_code]
        return {}

    def _legion_entry(self, dc_code: str, legion_code: str) -> dict:
        return self.legion_patterns.get(dc_code, {}).get("legions", {}).get(legion_code, {})

    def _build_match(
        self, dc_code: str, legion_code: str, location: str,
        evidence, confidence: str, matched_pattern: str = None
    ) -> Legion:
        """Build a typed Legion instance from raw heuristic outputs.

        All fields required by Legion.to_dict() are populated here so that
        downstream consumers receive the full backward-compatible dict shape
        plus the new schema fields.
        """
        dc_meta = self._dc_meta(dc_code)
        legion_meta = self._legion_entry(dc_code, legion_code)
        heuristic = (legion_meta.get("heuristics") or [{}])[0]

        fp, _, ln = location.rpartition(":")
        line_num = int(ln) if ln.isdigit() else 0

        conf_float = _CONFIDENCE_FLOAT.get(confidence, 0.3)
        detection_method = (
            "structural_pattern" if confidence in ("HIGH", "MEDIUM") else "keyword_heuristic"
        )

        # Evidence type: prefer matched_pattern override, else heuristic pattern_type
        mp = matched_pattern or ""
        if mp in _CALL_GRAPH_PATTERNS:
            evidence_type = "call_graph"
        elif mp in _CFG_PATTERNS:
            evidence_type = "cfg_node"
        else:
            evidence_type = _EVIDENCE_TYPE_MAP.get(
                heuristic.get("pattern_type", "keyword"), "code_pattern"
            )

        observability = "STRUCTURAL" if detection_method == "structural_pattern" else "BEHAVIOURAL"
        canon = _compute_canonical_hash(fp, line_num, dc_code, legion_code, mp)
        evidence_str = evidence[:160] if isinstance(evidence, str) else str(evidence)
        ts = datetime.now(timezone.utc).isoformat()

        return Legion(
            id=canon,
            dc_code=dc_code,
            dc_name=dc_meta.get("name", self.legion_patterns.get(dc_code, {}).get("name", "")),
            legion_code=legion_code,
            legion_name=legion_meta.get("name", ""),
            description=legion_meta.get("description", heuristic.get("description", "")),
            detection_method=detection_method,
            confidence_float=conf_float,
            confidence=confidence,
            evidence_type=evidence_type,
            file_path=fp,
            line_number=line_num,
            location=location,
            code_context=evidence_str,
            observability_level=observability,
            canonical_hash=canon,
            version="1.0",
            tier=dc_meta.get("tier", self.legion_patterns.get(dc_code, {}).get("tier", "")),
            primary_so=dc_meta.get("primary_so") or "",
            heuristic_description=heuristic.get("description", ""),
            matched_pattern=mp,
            false_positive_conditions=legion_meta.get("false_positive_conditions", []),
            false_negative_conditions=legion_meta.get("false_negative_conditions", []),
            created_at=ts,
            last_updated=ts,
        )

    def _searchable_snippets(self, primitives: dict) -> list:
        """Flatten decision points / consequences / AI integrations into (location, text) pairs."""
        snippets = []
        for dp in primitives.get("decision_points", []):
            text = " ".join(filter(None, [dp.get("condition"), dp.get("call")]))
            if text:
                snippets.append((dp["location"], text))
        for c in primitives.get("consequences", []):
            snippets.append((c["location"], c.get("action", "")))
        for ai in primitives.get("ai_integrations", []):
            snippets.append((ai["location"], ai.get("line_content", "")))
        return snippets

    # ── individual heuristics ───────────────────────────────────────────

    def _match_confidence_gates(self, primitives: dict) -> list:
        """DC-I11 / L3: Metric Saturation — confidence/score threshold gates a
        consequential action with no independent correctness check (HIGH)."""
        findings = []
        confidence_signals = ["confidence", "threshold", ".score", "probability"]
        window = 10

        # Anything that follows a confidence gate and could plausibly be the
        # "consequential action" it guards — a classified consequence, an AI
        # call, or another decision point further down the same gate's body.
        actionable_locs = []
        for c in primitives.get("consequences", []):
            actionable_locs.append(c["decision_location"])
        for ai in primitives.get("ai_integrations", []):
            actionable_locs.append(ai["location"])
        for dp in primitives.get("decision_points", []):
            actionable_locs.append(dp["location"])

        def _split(loc: str):
            file_, _, line_str = loc.rpartition(":")
            return file_, int(line_str)

        for dp in primitives.get("decision_points", []):
            if dp["type"] not in ("conditional_branch", "ternary"):
                continue
            condition_lower = dp.get("condition", "").lower()
            if not any(sig in condition_lower for sig in confidence_signals):
                continue

            dp_file, dp_line = _split(dp["location"])
            has_action_after = any(
                _split(loc)[0] == dp_file and dp_line < _split(loc)[1] <= dp_line + window
                for loc in actionable_locs
            )
            if has_action_after:
                findings.append(self._build_match(
                    "DC-I11", "L3", dp["location"], dp["condition"], "HIGH",
                    matched_pattern="confidence_gate_no_correctness_check",
                ))
        return findings

    def _match_validation_unused(self, primitives: dict) -> list:
        """DC-I11 / L4: Shadow Compliance — a validation-style call exists but
        nothing in the decision stream branches on its result (SPECULATIVE)."""
        findings = []
        validation_signals = ["validate(", "is_valid", "check_", "verify_"]

        for dp in primitives.get("decision_points", []):
            if dp["type"] != "function_call":
                continue
            call_lower = (dp.get("call") or "").lower()
            if any(sig in call_lower for sig in validation_signals):
                findings.append(self._build_match(
                    "DC-I11", "L4", dp["location"], dp.get("call", ""), "SPECULATIVE",
                    matched_pattern="validation_result_unused",
                ))
        return findings

    def _match_agent_handovers(self, primitives: dict) -> list:
        """DC-E13 / L1 + CLUSTER-HANDOVER / L1 — ungated agent-to-agent
        handovers, directly computed from Pass 4 (HIGH)."""
        findings = []
        for h in primitives.get("agent_handovers", []):
            if h.get("pre_node_exists"):
                continue
            evidence = h.get("governance_gap", "")
            findings.append(self._build_match(
                "DC-E13", "L1", h["location"], evidence, "HIGH",
                matched_pattern="agent_handover_no_prenode",
            ))
            findings.append(self._build_match(
                "CLUSTER-HANDOVER", "L1", h["location"], evidence, "HIGH",
                matched_pattern="agent_handover_no_prenode",
            ))
        return findings

    def _match_chained_ai_calls(self, primitives: dict) -> list:
        """DC-E13 / L3: Sourceless Cascade — >1 AI call in the repo with no
        traceable origin validation between them (MEDIUM)."""
        ai_integrations = primitives.get("ai_integrations", [])
        if len(ai_integrations) <= 1:
            return []
        locations = ", ".join(ai["location"] for ai in ai_integrations[:5])
        return [self._build_match(
            "DC-E13", "L3", ai_integrations[0]["location"],
            f"{len(ai_integrations)} chained AI calls: {locations}", "MEDIUM",
            matched_pattern="chained_ai_calls",
        )]

    def _match_cluster_gaps(self, primitives: dict) -> list:
        """CLUSTER-HANDOVER / L2 — sequential-agent pipeline with >=2 ungated
        handovers, directly computed from Pass 5 (HIGH)."""
        findings = []
        for cluster in primitives.get("cluster_governance_gaps", []):
            if len(cluster.get("gaps", [])) < 2:
                continue
            findings.append(self._build_match(
                "CLUSTER-HANDOVER", "L2", cluster["gaps"][0]["location"],
                f"{len(cluster['gaps'])} ungated handovers across {cluster.get('agents', [])}",
                "HIGH", matched_pattern="cluster_governance_gap",
            ))
        return findings

    def _match_keyword_legions(self, primitives: dict, already_matched: list) -> list:
        """
        Generic fallback — for every Legion whose heuristic is a plain
        keyword list (the SPECULATIVE entries auto-derived from Legion
        names), report the first matching snippet, if any. One finding per
        Legion at most, to keep noise bounded.
        """
        findings = []
        already_dc_legion = {(l.dc_code, l.legion_code) for l in already_matched}
        snippets = self._searchable_snippets(primitives)

        for dc_code, dc_entry in self.legion_patterns.items():
            for legion_code, legion_entry in dc_entry.get("legions", {}).items():
                if (dc_code, legion_code) in already_dc_legion:
                    continue
                for heuristic in legion_entry.get("heuristics", []):
                    if heuristic.get("pattern_type") != "keyword":
                        continue
                    patterns = [
                        p.lower() for p in heuristic.get("patterns", [])
                        if len(p) >= _MIN_KEYWORD_PATTERN_LEN
                    ]
                    if not patterns:
                        continue
                    for location, text in snippets:
                        text_lower = text.lower()
                        match = next((p for p in patterns if p in text_lower), None)
                        if match:
                            findings.append(self._build_match(
                                dc_code, legion_code, location, text,
                                heuristic.get("confidence", "SPECULATIVE"),
                                matched_pattern=match,
                            ))
                            break  # one finding per Legion
        return findings


# ── Guard detection — three-signal pipeline (Pass 3) ─────────────────────────

def _find_scope_start(lines: list, line_num: int) -> int:
    """Return the first 1-based line index of the current function/block scope."""
    if line_num <= 1:
        return 0
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())
    for i in range(line_num - 2, -1, -1):
        stripped = lines[i].strip()
        indent = len(lines[i]) - len(lines[i].lstrip())
        if stripped.startswith(("def ", "async def ", "class ")) and indent < dp_indent:
            return i + 1
    return 0


def _is_conditional(stripped: str) -> bool:
    return bool(_CONDITIONAL_RE.match(stripped))


def _extract_condition(stripped: str) -> str:
    for kw in ["elif ", "else if ", "if ", "unless ", "guard ", "when ", "match ", "switch "]:
        if stripped.lower().startswith(kw):
            return stripped[len(kw):].rstrip(":").rstrip("{").strip()
    return stripped


def _find_block_end_brace(lines: list, start_line: int, max_lines: int = 8) -> int:
    depth = 0
    found_open = False
    for i in range(start_line - 1, min(len(lines), start_line + max_lines)):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                found_open = True
            elif ch == '}':
                depth -= 1
                if found_open and depth == 0:
                    return i + 1
    return min(len(lines), start_line + max_lines)


def _is_hard_block(stripped: str) -> bool:
    s = stripped.lower()
    hard = ["raise ", "throw ", "throw new ", "sys.exit", "os._exit",
            "abort(", "panic!(", "exit(", "return error"]
    return any(s.startswith(p) for p in hard) or s in ("raise", "throw", "panic!")


def _find_preceding_guard(lines: list, line_num: int, window: int = 30) -> Optional[dict]:
    """Backward scan for the nearest structural conditional guard before line_num."""
    if not lines or line_num <= 1:
        return None
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())
    scope_start = _find_scope_start(lines, line_num)
    search_from = max(scope_start, line_num - window)
    for i in range(line_num - 2, search_from - 1, -1):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent > dp_indent:
            continue
        if _is_conditional(stripped):
            condition = _extract_condition(stripped)
            return {"line": i + 1, "indent": indent, "condition": condition,
                    "detection_type": "control_flow"}
    return None


def _score_enforcement(lines: list, guard: dict, consequence_line_num: int,
                        language: str = "pattern") -> float:
    """Score enforcement strength: hard block = 0.4, soft/scope = 0.2, none = 0.0."""
    guard_line_num = guard["line"]
    if language == "python":
        guard_line = lines[guard_line_num - 1] if guard_line_num <= len(lines) else ""
        guard_indent = len(guard_line) - len(guard_line.lstrip())
        search_end = min(len(lines), consequence_line_num - 1)
        for i in range(guard_line_num, min(search_end, guard_line_num + 8)):
            stripped = lines[i].strip()
            line_indent = len(lines[i]) - len(lines[i].lstrip())
            if line_indent <= guard_indent:
                break
            if _is_hard_block(stripped):
                return 0.4
        if consequence_line_num > guard_line_num:
            cons_line = lines[consequence_line_num - 1] if consequence_line_num <= len(lines) else ""
            cons_indent = len(cons_line) - len(cons_line.lstrip())
            if cons_indent > guard_indent:
                return 0.2
        return 0.0
    else:
        block_end = _find_block_end_brace(lines, guard_line_num, max_lines=8)
        for i in range(guard_line_num, min(len(lines), block_end)):
            if _is_hard_block(lines[i].strip()):
                return 0.4
        if guard_line_num < consequence_line_num <= block_end:
            return 0.2
        return 0.0


def _extract_identifiers(line: str) -> set:
    candidates = _IDENTIFIER_RE.findall(line)
    return {c.lower() for c in candidates if c.lower() not in _BUILTIN_NAMES}


def _score_data_causality(guard_line: str, consequence_line: str) -> float:
    """Return 0.2 if guard and consequence share at least one identifier, else 0.0."""
    guard_ids = _extract_identifiers(guard_line)
    cons_ids = _extract_identifiers(consequence_line)
    if guard_ids and cons_ids and (guard_ids & cons_ids):
        return 0.2
    return 0.0


def _find_decorator_guard(lines: list, line_num: int, scan_range: int = 50) -> Optional[dict]:
    """Look for a governance decorator on the containing function definition."""
    if not lines:
        return None
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())
    for i in range(line_num - 2, max(-1, line_num - scan_range), -1):
        stripped = lines[i].strip()
        indent = len(lines[i]) - len(lines[i].lstrip())
        if stripped.startswith(("def ", "async def ")) and indent < dp_indent:
            for j in range(i - 1, max(-1, i - 10), -1):
                dec_stripped = lines[j].strip()
                if not dec_stripped or dec_stripped.startswith("#"):
                    continue
                if dec_stripped.startswith("@"):
                    dec_name = dec_stripped[1:].split("(")[0].split(".")[0].strip()
                    if dec_name.lower() not in _NON_GOVERNANCE_DECORATORS:
                        return {"line": j + 1, "evidence": dec_stripped[:120]}
                else:
                    break
            break
    return None


def _find_containing_function_name(lines: list, line_num: int) -> Optional[str]:
    if not lines:
        return None
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())
    for i in range(line_num - 2, -1, -1):
        stripped = lines[i].strip()
        indent = len(lines[i]) - len(lines[i].lstrip())
        if stripped.startswith(("def ", "async def ")) and indent < dp_indent:
            m = re.match(r"(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)", stripped)
            if m:
                return m.group(1)
    return None


def _find_caller_guard(lines: list, line_num: int, window: int = 15) -> Optional[dict]:
    """One-hop caller guard: check if the containing function is called from a guarded site."""
    if not lines or len(lines) > 1000:
        return None
    fn_name = _find_containing_function_name(lines, line_num)
    if not fn_name:
        return None
    call_pattern = re.compile(rf'\b{re.escape(fn_name)}\s*\(')
    for i, line in enumerate(lines):
        if i + 1 == line_num:
            continue
        if call_pattern.search(line):
            guard = _find_preceding_guard(lines, i + 1, window)
            if guard:
                guard_content = lines[guard["line"] - 1].strip()[:120] if guard["line"] > 0 else ""
                return {"call_site_line": i + 1, "guard_line": guard_content, "guard": guard}
    return None


def _is_self_governing_condition_text(condition: str) -> Optional[dict]:
    """Check if a condition string itself is a governance check (used where source lines
    are unavailable, e.g. _analyse_decision_point_gaps)."""
    cond_lower = condition.lower()
    for _cat, spec in _LEGACY_KEYWORD_CATEGORIES.items():
        if any(kw in cond_lower for kw in spec["keywords"]):
            return PreNode(type="control_flow", strength=0.6, evidence_line=condition[:120]).to_dict()
    return None


def _classify_file_context(rel_path: str, content: str) -> str:
    """R3 — classify a file as 'framework', 'test', or 'application'.

    Framework files implement AI patterns as their purpose (abstract base classes,
    protocol stubs, pure re-exports). High-severity DC findings (DC-E5, DC-L2) on
    framework files are suppressed — governance belongs at the application layer that
    calls them, not inside the framework implementation itself.

    Classification uses content signals with a threshold of 2 to stay conservative
    (prefer 'application' when evidence is ambiguous).
    """
    path_str = str(rel_path).replace("\\", "/").lower()

    # Belt-and-suspenders test detection (SKIP_DIRS handles most; this catches edge cases)
    if any(seg in path_str for seg in ["/test/", "/tests/", "/__tests__/", "/spec/", "/fixture/"]):
        return "test"

    # Path-based framework detection — directories that contain AI block/provider/integration
    # implementations rather than application logic. These implement AI capabilities by design;
    # governance belongs at the application layer that orchestrates them.
    _FRAMEWORK_PATH_SEGMENTS = frozenset({
        "/blocks/", "/providers/", "/integrations/", "/adapters/",
        "/connectors/", "/plugins/", "/drivers/", "/handlers/",
        "/llms/", "/embeddings/", "/vectorstores/", "/retrievers/",
        "/chains/", "/agents/", "/tools/", "/callbacks/",
    })
    if any(seg in path_str for seg in _FRAMEWORK_PATH_SEGMENTS):
        return "framework"

    signals = 0

    # Abstract base class / protocol pattern
    if re.search(r'\b(?:ABC|ABCMeta|Protocol)\b', content):
        signals += 1
    if re.search(r'class\s+(?:Base|Abstract)\w*\s*[:(]', content):
        signals += 1

    # Unimplemented stubs — hallmark of framework base classes
    if content.count("raise NotImplementedError") >= 2:
        signals += 1
    if content.count("@abstractmethod") >= 2:
        signals += 1

    # Pure re-export module (__all__ with >60% import lines)
    non_blank = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    if "__all__" in content and non_blank:
        import_ratio = sum(1 for l in non_blank if l.startswith(("import ", "from "))) / len(non_blank)
        if import_ratio > 0.6:
            signals += 2  # strong signal

    return "framework" if signals >= 2 else "application"


def _find_signature_governance(lines: list, line_num: int, scan_range: int = 60) -> Optional[dict]:
    """R4 — detect framework-level governance in the containing function's parameter signature.

    Recognises FastAPI Depends()/Security()/Body()/Query()/Header()/Form() and Pydantic
    BaseModel-typed parameters. These are evaluated by the framework before the function
    body executes, so they constitute a genuine Pre-Node for every call site inside the
    function regardless of local control flow.

    Returns {"evidence": <short string>} or None.
    """
    if not lines:
        return None
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())

    for i in range(line_num - 2, max(-1, line_num - scan_range - 1), -1):
        raw = lines[i]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if stripped.startswith(("def ", "async def ")) and indent <= dp_indent:
            # Collect the full (possibly multi-line) signature up to the body colon.
            sig_parts = [stripped]
            j = i + 1
            while j < line_num and not sig_parts[-1].rstrip().endswith(":"):
                sig_parts.append(lines[j].strip())
                j += 1
            full_sig = " ".join(sig_parts)
            m = _SIGNATURE_GOVERNANCE_RE.search(full_sig)
            if m:
                token = m.group(0).strip()
                return {"evidence": f"{token} (signature governance in {stripped[:60]})"}
            break  # found the containing def but no governance — stop scanning
    return None


# Agent actions (0.7.0): what an AI agent can do on its own -- call a model,
# call a tool -- is consequential in itself, whatever the tool's body does.
AGENT_ACTION_TYPES = {
    "agent_tool_call": {"blast_radius": "department", "business_impact": "medium"},
    "model_call": {"blast_radius": "customer", "business_impact": "medium"},
}


def _agent_tool_actions(content: str, rel_path: str, lines: list, vsl_report) -> list:
    """One (decision point, consequence) pair per @tool function: a tool
    the model can call is a consequential action. Governed when a VSL gate
    covers it or a generic Pre-Node guards its body."""
    try:
        tree = _ast_parse_quiet(content, rel_path)
    except (SyntaxError, ValueError, RecursionError):
        return []
    pairs = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _vsl._is_tool_function(node):
            continue
        location = f"{rel_path}:{node.lineno}"
        first_body_line = node.body[0].lineno if node.body else node.lineno
        pre_node = _strongest_pre_node(
            _assess_pre_node_strength(lines, first_body_line),
            vsl_report.pre_node_for(rel_path, node.lineno) if vsl_report else None,
        )
        pairs.append(({
            "type": "agent_tool_call",
            "location": location,
            "line": node.lineno,
            "condition": f"tool {node.name}",
            "call": f"tool:{node.name}",
            "branches": 1,
            "severity": "high",
            "pre_node": pre_node,
        }, {
            "decision_location": location,
            "decision_type": "agent_tool_call",
            "consequence_type": "agent_tool_call",
            "location": location,
            "action": f"agent tool {node.name}",
            "reversible": True,
            "severity": "high",
        }))
    return pairs


def _agent_action_summary(gamma_variants) -> dict:
    """Governed/total for each kind of agent action, plus both together."""
    by_type = gamma_variants.by_consequence_type
    parts = {}
    for key, c_type in (("tools", "agent_tool_call"), ("model_calls", "model_call")):
        g = by_type.get(c_type)
        parts[key] = {"governed": g.governed if g else 0, "total": g.total if g else 0}
    parts["total"] = {
        "governed": sum(p["governed"] for p in parts.values()),
        "total": sum(p["total"] for p in parts.values()),
    }
    return parts


def _vsl_summary(vsl_report) -> dict:
    if vsl_report is None or not vsl_report.detected:
        return {"detected": False, "gates_total": 0, "gates_by_kind": {}}
    data = vsl_report.to_dict()
    return {"detected": True, "gates_total": data["gates_total"], "gates_by_kind": data["gates_by_kind"]}


def _agent_action_lines(summary: dict) -> list:
    """Scorecard lines for agent actions and VSL gates (empty if no actions)."""
    actions = summary.get("agent_actions") or {}
    total = actions.get("total", {})
    lines = []
    if total.get("total"):
        tools, models = actions.get("tools", {}), actions.get("model_calls", {})
        lines.append(
            f"Agent Actions Governed:            {total['governed']} / {total['total']}"
            f"  (tools {tools.get('governed', 0)}/{tools.get('total', 0)}, "
            f"model calls {models.get('governed', 0)}/{models.get('total', 0)})"
        )
    vsl = summary.get("vsl") or {}
    if vsl.get("detected"):
        kinds = ", ".join(f"{n} {k}" for k, n in sorted(vsl.get("gates_by_kind", {}).items()))
        lines.append(f"VSL Gates Recognised:              {vsl['gates_total']}  ({kinds})")
        lines.append(
            "  Credited from their wiring. Not verified: declared F1/F2 assurance, "
            "Gamma monitors, or runtime behaviour."
        )
    return lines


def _strongest_pre_node(*candidates: Optional[dict]) -> Optional[dict]:
    """The strongest of several Pre-Node assessments (None ignored)."""
    found = [c for c in candidates if c]
    return max(found, key=lambda c: c.get("strength", 0.0)) if found else None


def _assess_pre_node_strength(
    lines: list,
    line_num: int,
    window: int = 30,
    language: str = "pattern",
) -> Optional[dict]:
    """
    Pass 3 (refactored) — three-signal pipeline for Pre-Node detection.

    Detection paths (early-exit, strongest first):
      1. Preceding structural conditional guard → scored by Enforcement + Causality
      2. Governance decorator on containing function
      2b. Framework dependency injection / Pydantic typed params in function signature (R4)
      3. One-hop caller guard (≤1000-line files only)
      4. Legacy keyword fallback — capped at 0.4 (below governed threshold)

    Signals: Control Flow (+0.4 base) + Enforcement (+0.4 hard / +0.2 soft)
             + Data Causality (+0.2). Max 1.0. Governed threshold: 0.5.
    """
    if not lines or line_num <= 0:
        return None

    # Path 1: preceding structural conditional
    guard = _find_preceding_guard(lines, line_num, window)
    if guard:
        enforcement = _score_enforcement(lines, guard, line_num, language)
        if enforcement > 0.0:
            guard_content = lines[guard["line"] - 1] if 0 < guard["line"] <= len(lines) else ""
            cons_content = lines[line_num - 1] if line_num <= len(lines) else ""
            causality = _score_data_causality(guard_content, cons_content)
            strength = round(min(1.0, 0.4 + enforcement + causality), 2)
            return PreNode(
                type="control_flow",
                strength=strength,
                evidence_line=(guard_content.strip() if isinstance(guard_content, str)
                               else "")[:120],
            ).to_dict()

    # Path 2: governance decorator on containing function
    dec_guard = _find_decorator_guard(lines, line_num)
    if dec_guard:
        return PreNode(type="decorator", strength=0.6,
                       evidence_line=dec_guard["evidence"]).to_dict()

    # Path 2b (R4): framework dependency injection or Pydantic typed params in signature.
    # Depends()/Security()/Body() etc. are evaluated by FastAPI before the function body
    # runs — they are a genuine Pre-Node for every call site inside the function.
    sig_guard = _find_signature_governance(lines, line_num)
    if sig_guard:
        return PreNode(type="dependency_injection", strength=0.7,
                       evidence_line=sig_guard["evidence"]).to_dict()

    # Path 3: one-hop caller guard (small files only)
    if len(lines) <= 1000:
        caller = _find_caller_guard(lines, line_num)
        if caller:
            cons_content = lines[line_num - 1] if line_num <= len(lines) else ""
            causality = _score_data_causality(caller.get("guard_line", ""), cons_content)
            strength = round(min(1.0, 0.4 + 0.2 + causality), 2)
            return PreNode(type="caller_guard", strength=strength,
                           evidence_line=caller.get("guard_line", "")[:120]).to_dict()

    # Path 4: legacy keyword fallback (capped at 0.4 — below governed threshold)
    dp_line = lines[line_num - 1] if line_num <= len(lines) else ""
    dp_indent = len(dp_line) - len(dp_line.lstrip())
    start = max(0, line_num - window)
    for i in range(line_num - 2, start - 1, -1):
        stripped = lines[i].strip()
        indent = len(lines[i]) - len(lines[i].lstrip())
        if stripped.startswith(("def ", "async def ", "class ")) and indent < dp_indent:
            start = i + 1
            break
    for line in lines[start:line_num - 1]:
        line_lower = line.lower().strip()
        if not line_lower or line_lower.startswith("#") or line_lower.startswith("//"):
            continue
        for _cat, spec in _LEGACY_KEYWORD_CATEGORIES.items():
            if any(kw in line_lower for kw in spec["keywords"]):
                return PreNode(type="legacy_keyword", strength=0.4,
                               evidence_line=line.strip()[:120]).to_dict()
    return None


def _has_human_review(lines: list, line_num: int) -> bool:
    """Check for human review mechanism after an AI call."""
    search_lines = lines[line_num:min(len(lines), line_num + 20)]
    human_signals = [
        "review", "approve", "confirm", "human_in_loop",
        "human_review", "manual_check", "oversight",
        "require_approval", "awaiting_approval",
    ]
    return any(
        any(s in line.lower() for s in human_signals)
        for line in search_lines
    )


# subprocess.run/subprocess.call cover both genuinely destructive operations
# (rm -rf, git push, a deploy) and harmless, idempotent ones (git fetch,
# pytest, a build step) — only the former should be treated as irreversible.
# os.system and subprocess.Popen are always flagged regardless of content
# (os.system is shell-injection-prone by construction; Popen is fire-and-forget).
_IRREVERSIBLE_SUBPROCESS_COMMANDS = (
    "rm ", "rmdir", "git push", "git commit", "deploy",
    "kubectl", "docker push", "pip install", "npm publish",
)


def _is_irreversible_subprocess_command(line: str) -> bool:
    # subprocess.run(["rm", "-rf", path]) is the idiomatic (and recommended
    # over shell=True) way to call this — quotes/commas/brackets sit between
    # the command and its arguments, so a literal substring check like
    # "rm " never matches list-style calls, only "rm -rf ..." shell strings.
    # Normalize both styles to plain space-separated words before matching.
    normalized = re.sub(r'["\',\[\]]', ' ', line.lower())
    normalized = re.sub(r'\s+', ' ', normalized)
    return any(cmd in normalized for cmd in _IRREVERSIBLE_SUBPROCESS_COMMANDS)


# Keywords distinguishing a dormant/conditional trigger (a stale feature flag
# or legacy switch that re-activates code after deployment — the Knight
# Capital signature: DC-E14 Substrate Contamination) from an ordinary runtime
# condition. Most ungated irreversible actions have neither kind of guard —
# they're just unconditional calls — which is a generic Pre-Node gap, not
# evidence of this specific drift mechanism.
_DORMANT_TRIGGER_KEYWORDS = (
    "enabled", "flag", "legacy", "deprecated", "feature_flag",
    "toggle", "rollout", "config.", "is_active",
)


def _find_dormant_trigger_guard(lines: list, line_num: int, window: int = 15) -> Optional[str]:
    """Look back from line_num for a conditional whose own condition text
    reads like a stale feature flag / legacy switch, not a normal runtime
    check. Returns the condition text if found, else None."""
    if not lines or line_num <= 1:
        return None
    start = max(0, line_num - window)
    for i in range(line_num - 2, start - 1, -1):
        stripped = lines[i].strip()
        if not _is_conditional(stripped):
            continue
        stripped_lower = stripped.lower()
        if any(kw in stripped_lower for kw in _DORMANT_TRIGGER_KEYWORDS):
            return stripped[:160]
    return None


def _detect_irreversible_actions(lines: list, filepath: str) -> list:
    """
    Detect irreversible actions with no authorisation gate.
    Only called on AI-adjacent files in ai-app and system-utility profiles.
    """
    import re
    findings = []

    for action_type, patterns in IRREVERSIBLE_ACTION_PATTERNS.items():
        for pattern in patterns:
            content_aware = pattern in ("subprocess.run", "subprocess.call")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                if "import " in stripped and "(" not in stripped:
                    continue

                if re.search(pattern, line, re.IGNORECASE):
                    if content_aware and not _is_irreversible_subprocess_command(line):
                        # Reversible command (git fetch, pytest, ...) — keep
                        # scanning the rest of the file for a genuinely
                        # destructive call instead of stopping here.
                        continue
                    has_gate = _has_authorisation_gate(lines, i)
                    if not has_gate:
                        findings.append({
                            "line": i,
                            "action_type": action_type,
                            "pattern": pattern,
                            "line_content": stripped[:120],
                            "filepath": filepath,
                            "dormant_trigger_guard": _find_dormant_trigger_guard(lines, i),
                        })
                    break  # one finding per pattern per file

    return findings


def _has_authorisation_gate(lines: list, line_num: int) -> bool:
    """Check for authorisation gates before irreversible actions."""
    if not lines or line_num == 0:
        return False
    search_lines = lines[max(0, line_num - 20):line_num - 1]
    gate_signals = [
        "approve", "confirm", "authoris", "authoriz",
        "permission", "has_permission", "can_",
        "require_approval", "user_confirmed",
        "human_authorised", "manual_approval",
    ]
    return any(
        any(s in line.lower() for s in gate_signals)
        for line in search_lines
    )


# ── Governance theatre (TS/JS validate() with no usable parameter access) ────
#
# Agent-action frameworks (elizaOS, Infinity, and similar frameworks built
# on the same convention) gate execution behind a validate(runtime, message, state)
# function — if it returns true, the action fires. "Governance theatre" is
# when that function structurally cannot check anything (no parameters, or
# every parameter underscored — TypeScript's "intentionally unused" marker)
# yet still returns true unconditionally. The gate exists; it enforces
# nothing.
#
# Scoped deliberately to only the cases that are a structural FACT, not a
# judgment call: a function with no parameter access cannot possibly check
# identity, authorisation, or message content, regardless of what's in its
# body. Config-only checks, keyword-only checks, and "is the gate sufficient
# for this action's risk level" all require contextual judgment about what a
# specific action needs — that's a human decision, not something a
# deterministic structural scanner should assert.
# A bare-expression arrow (`=> true`, no braces) never references its
# parameters no matter what they're named — this covers the param-less form,
# the underscored form, AND named-but-unused params in one structurally
# certain pattern, since the syntactic shape itself proves the params are
# unused, regardless of naming convention.
_THEATRE_BARE_TRUE = re.compile(
    r"validate\s*:\s*async\s*\([^)]*\)\s*(?::\s*Promise<boolean>\s*)?=>\s*\btrue\b",
)

# A block body (`=> { ... return true; }`) can't be proven empty by syntax
# alone — this relies on the underscore naming convention as the developer's
# own signal that ALL parameters are unused. Known approximation: a function
# with real conditional logic that happens to contain the literal substring
# "return true" within 300 characters could still match. Same limitation the
# source audit's own proposed pattern accepted — flagged for human review,
# not asserted as certain.
_THEATRE_UNDERSCORED_BLOCK = re.compile(
    r"validate\s*:\s*async\s*\("
    r"\s*_\w+(?:\s*:[^,)]+)?\s*"
    r"(?:,\s*_\w+(?:\s*:[^,)]+)?\s*)*"
    r"\)\s*(?::\s*Promise<boolean>\s*)?=>\s*"
    r"\{[^}]{0,300}return\s+true;?\s*\}",
    re.DOTALL,
)

# "validate" alone is far too generic a name to be specific to AI agent
# action gating — a form validator or API request validator would match the
# patterns above just as easily. Require at least one corroborating signal
# that this file actually defines agent-framework actions before flagging
# anything. (File-level, not match-level — matching object boundaries
# precisely would need a real parser, not a regex.) The literal strings here
# are the real package/type names from the one framework convention we have
# audited evidence for (elizaOS's Action interface) — not decorative.
_AGENT_ACTION_FRAMEWORK_SIGNALS = ("handler:", "iagentruntime", "@elizaos/core", "similes:")


def _detect_governance_theatre(content: str, filepath: str) -> list:
    """Detect validate() functions that structurally cannot perform any
    check yet unconditionally return true — present in the structural
    position of a governance gate while enforcing nothing."""
    findings = []
    if TEST_FILE_RE.search(filepath):
        return findings
    content_lower = content.lower()
    if not any(s in content_lower for s in _AGENT_ACTION_FRAMEWORK_SIGNALS):
        return findings

    lines_list = content.splitlines()
    seen_lines = set()
    for pattern, form in (
        (_THEATRE_BARE_TRUE, "UNCONDITIONAL_VALIDATE"),
        (_THEATRE_UNDERSCORED_BLOCK, "UNDERSCORE_PARAM_VALIDATE"),
    ):
        for m in pattern.finditer(content):
            line_num = content[:m.start()].count("\n") + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            line_text = lines_list[line_num - 1].strip() if 0 < line_num <= len(lines_list) else ""
            findings.append({
                "type": "governance_theatre",
                "form": form,
                "location": f"{filepath}:{line_num}",
                "line_content": line_text[:160],
                "severity": "critical",
                "plain_english": (
                    f"validate() at {filepath}:{line_num} has no usable parameter "
                    f"access — it structurally cannot check identity, authorisation, "
                    f"or message content — but unconditionally returns true. The "
                    f"action fires for any matching message."
                ),
                "recommended_action": (
                    "Check that the runtime has the required service available, "
                    "that the message has a traceable sender identity, and — for "
                    "destructive or financial actions — that the sender is "
                    "authorised. A function that ignores all its parameters "
                    "cannot do any of this."
                ),
            })
    return findings


# ── Main scan engine ──────────────────────────────────────────────────────────

class ScanEngine:
    """
    Core scan engine — AI-integration-centric.

    Governance gaps are only meaningful relative to AI calls.
    Irreversible actions flagged only when AI-adjacent (in ai-app profile).

    v0.2.0 — context profiles, fixed Gamma, robust error handling.
    """

    def __init__(
        self, verbose: bool = False, context_profile: str = "ai-app",
        all_frameworks: bool = False,
    ):
        self.verbose = verbose
        self.context_profile = context_profile
        # False (default): only OpenAI/LangChain/LangGraph findings are
        # reported (DEFAULT_FRAMEWORK_SCOPE). True: report every provider/
        # framework the underlying detectors recognise, audited or not.
        self.all_frameworks = all_frameworks
        self.profile = CONTEXT_PROFILES.get(context_profile, CONTEXT_PROFILES["ai-app"])
        self.dc_classes = self._load_taxonomy("dc_classes.json")
        self.so_operators = self._load_taxonomy("so_operators.json")
        self.dc_classes_complete = self._load_data_file("dc_classes_complete.json")
        self.legion_patterns = self._load_data_file("LEGION_DETECTION_PATTERNS.json")
        self.monitoring_frequency_map = self._build_monitoring_frequency_map(self.dc_classes_complete)
        _CONTRAINDICATION_REASONS.update(_build_contraindication_reasons(self.dc_classes_complete))
        self.ast_analyser = ASTAnalyser()
        self.decision_analyser = DecisionPointAnalyser()
        self.js_decision_analyser = JSDecisionPointAnalyser()
        self.go_decision_analyser = GoDecisionPointAnalyser()
        self.rust_decision_analyser = RustDecisionPointAnalyser()
        self.csharp_decision_analyser = CSharpDecisionPointAnalyser()
        self.consequence_classifier = ConsequenceClassifier()
        self.handover_analyser = AgentHandoverAnalyser()
        self.cluster_analyser = ClusterGovernanceAnalyser()
        self.legion_matcher = LegionMatcher(self.legion_patterns, self.dc_classes_complete)

    def _load_taxonomy(self, filename: str) -> dict:
        path = TAXONOMY_PATH / filename
        if path.exists():
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _load_data_file(self, filename: str) -> dict:
        """Load a v0.3.0 data file (dc_classes_complete.json, LEGION_DETECTION_PATTERNS.json)
        from alongside engine.py."""
        path = DATA_PATH / filename
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                if self.verbose:
                    console.print(f"[dim]Could not load {filename}: {e}[/dim]")
                return {}
        if self.verbose:
            console.print(f"[dim]{filename} not found at {path} — related v0.3.0 checks will be skipped.[/dim]")
        return {}

    def _build_monitoring_frequency_map(self, dc_classes_complete: dict) -> dict:
        """
        Pass 8 — build a dc_code -> human-readable monitoring frequency map
        from dc_classes_complete.json's monitoring_frequency_by_dc, which is
        keyed by frequency label -> list of DC codes.
        """
        labels = {
            "per_token": "Per-token monitoring required",
            "per_generation_step": "Per-generation-step monitoring required",
            "per_turn": "Per-turn monitoring required",
            "cross_session": "Cross-session monitoring required",
            "cluster_level": "Cluster-level continuous monitoring required",
            "pre_deployment": "Pre-deployment activation check required",
        }
        freq_map = {}
        for freq_key, dc_codes in dc_classes_complete.get("monitoring_frequency_by_dc", {}).items():
            label = labels.get(freq_key, f"{freq_key.replace('_', ' ').title()} monitoring required")
            for dc_code in dc_codes:
                freq_map[dc_code] = label
        return freq_map

    def scan(self, repo_path: str, identity_key: str = None, focus_paths: list = None) -> dict:
        path = Path(repo_path).resolve()
        identity_key = identity_key or self._generate_identity_key(path)

        results = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "repo": str(path),
            "identity_key": identity_key,
            "verba_version": "0.7.0",
            "context_profile": self.context_profile,
            "all_frameworks": self.all_frameworks,
            "reviewed": False,
            "focus_paths": focus_paths or [],
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:

            t1 = progress.add_task("Pass 1 — Reading code structure...", total=None)
            files = self._collect_files(path, focus_paths=focus_paths)
            parsed = self._parse_files(files)
            results["files_scanned"] = len(files)
            progress.update(t1, completed=True)

            t2 = progress.add_task("Pass 2 — Detecting AI integrations (AST)...", total=None)
            primitives = self._detect_primitives(parsed, path)
            if not self.all_frameworks:
                self._apply_framework_scope(primitives)
            try:
                primitives["agent_handovers"].extend(_detect_pubsub_messaging(parsed))
            except Exception as e:
                if self.verbose:
                    console.print(f"[dim]Pub/sub handover scan error: {e}[/dim]")
            results["primitives"] = primitives
            results["vsl"] = self.vsl_report.to_dict()
            results["language_coverage"] = _compute_language_coverage(parsed)
            progress.update(t2, completed=True)

            # In ai-app profile, a repo with no AI integrations is still a
            # codebase with decision points, error handling, and control flow —
            # structural governance analysis (Passes 3-16) must run regardless.
            # The flag below is informational only; it is not used to skip analysis.
            results["no_ai_context"] = bool(
                self.profile["require_ai_for_scan"] and not primitives["ai_integrations"]
            )

            t3 = progress.add_task("Pass 3 — Mapping Drift Classes...", total=None)
            dc_findings = self._match_dc_patterns(primitives, parsed)
            results["drift_classes"] = dc_findings
            progress.update(t3, completed=True)

            t4 = progress.add_task("Pass 4 — Analysing governance gaps...", total=None)
            gaps = self._analyse_gaps(primitives)
            results["gaps"] = gaps
            progress.update(t4, completed=True)

            t4b = progress.add_task("Pass 3b — Assessing decision-point Pre-Nodes...", total=None)
            decision_point_gaps = self._analyse_decision_point_gaps(primitives)
            results["decision_points"] = primitives.get("decision_points", [])
            results["consequences"] = primitives.get("consequences", [])
            results["decision_point_gaps"] = decision_point_gaps
            progress.update(t4b, completed=True)

            t4c = progress.add_task("Pass 4 — Detecting agent handovers...", total=None)
            results["agent_handovers"] = primitives.get("agent_handovers", [])
            progress.update(t4c, completed=True)

            t4d = progress.add_task("Pass 5 — Analysing cluster governance...", total=None)
            cluster_governance_gaps = self.cluster_analyser.analyse(
                primitives.get("agent_handovers", [])
            )
            primitives["cluster_governance_gaps"] = cluster_governance_gaps
            results["cluster_governance_gaps"] = cluster_governance_gaps
            results["terminal_states"] = primitives.get("terminal_states", [])
            results["governance_theatre"] = primitives.get("governance_theatre", [])
            progress.update(t4d, completed=True)

            t6 = progress.add_task("Pass 6 — Matching Drift Classes & Legions...", total=None)
            legion_matches = self.legion_matcher.match(primitives)
            results["legion_matches"] = legion_matches
            progress.update(t6, completed=True)

            t7 = progress.add_task("Pass 7 — Applying boundary case discriminators...", total=None)
            detected_dc_codes = {f["dc_code"] for f in dc_findings} | {m["dc_code"] for m in legion_matches}
            results["boundary_case_notes"] = self._apply_boundary_cases(detected_dc_codes)
            progress.update(t7, completed=True)

            t8 = progress.add_task("Pass 8 — Assigning monitoring frequency...", total=None)
            for finding in legion_matches:
                finding["monitoring_frequency"] = self._get_monitoring_frequency(finding["dc_code"])
            progress.update(t8, completed=True)

            t65 = progress.add_task("Pass 6.5 — Enriching gaps with drift exposure...", total=None)
            try:
                _dc_entries = _flat_dc_entries(self.dc_classes_complete)
                _so_entries = self.dc_classes_complete.get("stabilisation_operators", {})
                _enrich_gaps_with_drift_exposure(
                    gaps + decision_point_gaps, legion_matches, _dc_entries, _so_entries
                )
            except Exception:
                pass  # graceful degradation — drift exposure is additive
            progress.update(t65, completed=True)

            t9 = progress.add_task("Pass 9 — Computing Gamma score...", total=None)
            gamma = self._compute_gamma(primitives, gaps, decision_point_gaps)
            results["_legacy_gamma_proxy"] = gamma
            progress.update(t9, completed=True)

            # v0.4.0 — Passes 10-16: governance intelligence layers. Additive
            # only; any failure here falls back to empty/default values so a
            # Phase 2/3 bug can never break v0.3.0 results.
            t10 = progress.add_task("Pass 10 — Enriching consequences...", total=None)
            try:
                enhanced_consequences = ConsequenceEnricher().enrich(primitives)
            except Exception:
                enhanced_consequences = []
            progress.update(t10, completed=True)

            t11 = progress.add_task("Pass 11 — Building agent & decision graphs...", total=None)
            try:
                agent_graph = AgentGraphBuilder().build(primitives)
            except Exception:
                agent_graph = AgentGraph()
            try:
                decision_graph = DecisionGraphBuilder().build(primitives, enhanced_consequences)
            except Exception:
                decision_graph = DecisionGraph()
            progress.update(t11, completed=True)

            t12 = progress.add_task("Pass 12 — Building inventories...", total=None)
            inventory_builder = InventoryBuilder()
            try:
                ai_inventory = inventory_builder.build_ai_inventory(primitives)
            except Exception:
                ai_inventory = AIInventory(total=0, by_provider={}, governed=0, ungoverned=0, high_risk_patterns=0)
            try:
                agent_inventory = inventory_builder.build_agent_inventory(agent_graph)
            except Exception:
                agent_inventory = AgentInventory(0, 0, 0, 0, 0, 0, 0, 0, 0)
            try:
                decision_inventory = inventory_builder.build_decision_inventory(decision_graph)
            except Exception:
                decision_inventory = DecisionInventory(total=0, by_consequence_type={}, by_criticality={}, critical_total=0)
            progress.update(t12, completed=True)

            t13 = progress.add_task("Pass 13 — Computing governance coverage...", total=None)
            try:
                coverage = GovernanceMetricsBuilder().compute_coverage(primitives, decision_graph)
            except Exception:
                coverage = GovernanceCoverage(overall_percent=0.0)
            progress.update(t13, completed=True)

            t14 = progress.add_task("Pass 14 — Analysing governance tendency...", total=None)
            try:
                tendency = TendencyAnalyzer().analyze(primitives, decision_graph, agent_graph)
            except Exception:
                tendency = TendencyIndicators(0.0, 0.0, 0.0, 0, 0, 0, 0.0, TendencyState.STABLE, False, "LOW (<10% of critical decisions ungoverned)")
            progress.update(t14, completed=True)

            t15 = progress.add_task("Pass 15 — Computing Gamma variants...", total=None)
            try:
                gamma_variants = GammaVariantsBuilder().compute(primitives, decision_graph, agent_graph)
            except Exception:
                empty = GammaValue(value=0.0, status="BELOW_THRESHOLD", governed=0, total=0)
                gamma_variants = GammaVariants(overall=empty, critical=empty, agent_handover=empty, agent_chain=empty, cluster=empty)
            progress.update(t15, completed=True)

            t16 = progress.add_task("Pass 16 — Running decision graph algorithms...", total=None)
            graph_analyzer = DecisionGraphAnalyzer()
            try:
                pagerank_results = graph_analyzer.pagerank(decision_graph)
            except Exception:
                pagerank_results = {}
            try:
                critical_path = graph_analyzer.critical_path(decision_graph)
            except Exception:
                critical_path = []
            try:
                ungoverned_decisions = [n for n, node in decision_graph.nodes.items() if not node.governed]
                propagation = {
                    node_id: graph_analyzer.propagation_potential(decision_graph, node_id)
                    for node_id in ungoverned_decisions[:5]
                }
            except Exception:
                propagation = {}
            progress.update(t16, completed=True)

        results["enhanced_consequences"] = [ec.to_dict() for ec in enhanced_consequences]
        results["graphs"] = {
            "agent_graph": agent_graph,
            "decision_graph": decision_graph,
        }
        results["inventories"] = {
            "ai": ai_inventory,
            "agent": agent_inventory,
            "decision": decision_inventory,
        }
        results["metrics"] = {
            "coverage": coverage,
            "tendency": tendency,
            "gamma_variants": gamma_variants,
        }
        results["algorithms"] = {
            "pagerank": pagerank_results,
            "critical_path": critical_path,
            "propagation": propagation,
        }

        results["summary"] = self._build_summary(results, files, gaps, dc_findings, gamma)
        results["critical_findings"] = self._extract_critical_findings(gaps, dc_findings)

        return results

    def _generate_identity_key(self, path: Path) -> str:
        return f"{path.name}-{hashlib.md5(str(path).encode()).hexdigest()[:8]}"

    def _collect_files(self, path: Path, focus_paths: list = None) -> list:
        resolved_focus = (
            [
                (p_path if p_path.is_absolute() else path / p_path).resolve()
                for p_path in (Path(p) for p in focus_paths)
            ]
            if focus_paths else None
        )
        files = []
        for root, dirs, filenames in os.walk(path):
            root_path = Path(root)
            if resolved_focus is not None:
                # A directory normally excluded by SKIP_DIRS (e.g. "examples")
                # must still be walked into if it's required to reach an
                # explicit --focus target — i.e. it IS the target, or an
                # ancestor of it. Once inside the focus subtree, normal
                # SKIP_DIRS rules resume (a node_modules/ nested inside a
                # focused directory is still skipped).
                dirs[:] = [
                    d for d in dirs
                    if d not in SKIP_DIRS or any(
                        (cand := (root_path / d).resolve()) == foc
                        or cand in foc.parents
                        for foc in resolved_focus
                    )
                ]
            else:
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in filenames:
                if TEST_FILE_RE.search(fn):
                    continue
                if MINIFIED_BUNDLE_RE.search(fn):
                    continue
                # SKIP_FILENAMES (setup.py, conftest.py, setup.cfg) are
                # packaging/test-tooling files at the repo root — a module
                # that happens to share one of these names deeper in the
                # tree (e.g. tradingagents/graph/setup.py) is production
                # code, not build tooling, and must not be skipped.
                if fn in SKIP_FILENAMES and root_path == path:
                    continue
                fp = Path(root) / fn
                if fp.suffix not in SUPPORTED_EXTENSIONS:
                    continue
                if resolved_focus is not None:
                    fp_resolved = fp.resolve()
                    if not any(
                        fp_resolved == foc or foc in fp_resolved.parents
                        for foc in resolved_focus
                    ):
                        continue
                files.append(fp)
        return files

    def _parse_files(self, files: list) -> list:
        parsed = []
        for fp in files:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                parsed.append({
                    "path": fp,
                    "content": content,
                    "lines": content.splitlines(),
                    "extension": fp.suffix,
                    "has_ai": self._quick_ai_check(content),
                })
            except (OSError, PermissionError) as e:
                if self.verbose:
                    console.print(f"[dim]Skipping {fp}: {e}[/dim]")
        return parsed

    def _quick_ai_check(self, content: str) -> bool:
        """Fast pre-filter: does this file likely contain AI calls?"""
        ai_signals = list(AI_PROVIDER_IMPORTS.keys()) + [
            "openai", "anthropic", "langchain", "llama_index",
            "transformers", "bedrock", "cohere", "generativeai",
            "ChatCompletion", "messages.create", "invoke_model",
            "generateText", "streamText",
            "claude_agent_sdk", "google.adk", "google.genai",
            "strands", "agency_swarm",
        ]
        content_lower = content.lower()
        return any(sig.lower() in content_lower for sig in ai_signals)

    def _is_ai_adjacent_file(self, file_data: dict, ai_file_paths: set) -> bool:
        """
        A file is AI-adjacent if it contains AI calls directly,
        or if it imports a module from an AI-containing file (one level).
        """
        if file_data["has_ai"]:
            return True
        content = file_data["content"]
        for ai_path in ai_file_paths:
            stem = Path(ai_path).stem
            if f"import {stem}" in content or f"from {stem}" in content:
                return True
        return False

    def _apply_framework_scope(self, primitives: dict) -> None:
        """Mutates `primitives` in place, dropping ai_integrations and
        agent_invocation decision points whose provider/framework isn't in
        DEFAULT_FRAMEWORK_SCOPE. Only called when all_frameworks is False.

        Deliberately does NOT touch primitives["agent_handovers"] — that
        subsystem's 9 detection families are structural-pattern-based, not
        framework-tagged per finding (e.g. its graph/builder-edge family
        detects LangGraph, Microsoft Agent Framework, AutoGen, and Haystack
        with one shared detector, recording no per-finding framework label
        at all), so it can't be scoped this way without much larger
        surgery. It stays framework-agnostic/always-on regardless of this
        flag — see the "Handover scope" decision in the project notes.
        """
        primitives["ai_integrations"] = [
            a for a in primitives.get("ai_integrations", [])
            if a.get("provider") in DEFAULT_FRAMEWORK_SCOPE or a.get("provider") == "ai_framework"
        ]
        primitives["decision_points"] = [
            d for d in primitives.get("decision_points", [])
            if d.get("type") not in ("agent_invocation", "model_call")
            or d.get("framework") in DEFAULT_FRAMEWORK_SCOPE
            or (d.get("type") == "model_call" and d.get("framework") == "ai_framework")
        ]
        kept = {d["location"] for d in primitives["decision_points"]}
        primitives["consequences"] = [
            c for c in primitives.get("consequences", [])
            if c.get("consequence_type") != "model_call" or c.get("decision_location") in kept
        ]

    def _detect_primitives(self, parsed: list, base_path: Path) -> dict:
        primitives = {
            "ai_integrations": [],
            "sensitive_fields": [],
            "irreversible_actions": [],
            "constraints": [],
            "nodes": [],
            "clusters": [],
            "decision_points": [],
            "consequences": [],
            "agent_handovers": [],
            "terminal_states": [],
            "governance_theatre": [],
        }

        # VSL gate recognition: one repo-wide pass, consulted below wherever
        # "governed" is decided. See x_verba/vsl.py.
        try:
            self.vsl_report = _vsl.analyse(parsed, base_path)
        except Exception as e:
            self.vsl_report = _vsl.VslReport()
            if self.verbose:
                console.print(f"[dim]VSL gate scan error: {e}[/dim]")
        self.handover_analyser.vsl_report = self.vsl_report

        # First pass: identify AI-containing files
        ai_file_paths = {str(f["path"]) for f in parsed if f["has_ai"]}

        for file_data in parsed:
            content = file_data["content"]
            lines = file_data["lines"]
            fp = file_data["path"]
            ext = file_data["extension"]

            try:
                rel_path = fp.relative_to(base_path)
            except ValueError:
                rel_path = fp

            _ai_integrations_before_this_file = len(primitives["ai_integrations"])

            is_ai_file = file_data["has_ai"]
            is_adjacent = self._is_ai_adjacent_file(file_data, ai_file_paths)
            # Same scoping rule as irreversible-action detection below: a try/except
            # with no recovery is only a governance-relevant Terminal State if it's
            # in AI-adjacent code. The same pattern in an unrelated utility file is
            # not something this tool is positioned to judge.
            should_scan_terminal_states = (
                self.profile["flag_irrev_outside_ai"] or is_adjacent
            )

            # R3: classify this file so DC findings can be scoped correctly
            file_context = _classify_file_context(str(rel_path), content)

            # AST analysis for Python
            if ext == ".py":
                try:
                    ast_result = self.ast_analyser.analyse(content, str(rel_path))
                    for call in ast_result["ai_calls"]:
                        _pn_result = _assess_pre_node_strength(lines, call["line"], language="python")
                        vsl_governed = self.vsl_report.gates_model_call
                        pre_node = _pn_result is not None or vsl_governed
                        human_review = _has_human_review(lines, call["line"])
                        primitives["ai_integrations"].append({
                            "id": f"AI-{len(primitives['ai_integrations'])+1:03d}",
                            "provider": call["provider"],
                            "location": f"{rel_path}:{call['line']}",
                            "line_content": call["line_content"],
                            "temperature": call.get("temperature"),
                            "max_tokens": call.get("max_tokens"),
                            "streaming": call.get("streaming", False),
                            "dynamic_prompt": self._has_dynamic_prompt(content, call["line"]),
                            "user_input_in_prompt": self._has_user_input_in_prompt(content, call["line"]),
                            "pre_node_detected": pre_node,
                            "human_review_detected": human_review,
                            "vsl_governed": vsl_governed,
                            "output_destination": self._detect_output_destination(lines, call["line"]),
                            "source_file": str(rel_path),
                            "file_context": file_context,
                        })
                        _model_location = f"{rel_path}:{call['line']}"
                        primitives["decision_points"].append({
                            "type": "model_call",
                            "location": _model_location,
                            "line": call["line"],
                            "condition": call["line_content"][:120],
                            "call": f"model:{call['provider']}",
                            "framework": call["provider"],
                            "branches": 1,
                            "severity": "high",
                            # Same rule as the AI inventory: governed by a
                            # VSL gate, or by a Pre-Node plus human review.
                            "pre_node": (
                                {
                                    "type": "vsl_gate", "strength": _vsl.VSL_GATE_STRENGTH,
                                    "evidence_line": "VSL PreNode in front of the model call",
                                } if vsl_governed
                                else _pn_result if (_pn_result and human_review)
                                else None
                            ),
                        })
                        primitives["consequences"].append({
                            "decision_location": _model_location,
                            "decision_type": "model_call",
                            "consequence_type": "model_call",
                            "location": _model_location,
                            "action": f"model call ({call['provider']})",
                            "reversible": True,
                            "severity": "high",
                        })
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]AST error in {rel_path}: {e}[/dim]")

                # Pass 1 (enhanced) — all decision points, not just AI calls
                try:
                    decision_points = self.decision_analyser.analyse(content, str(rel_path))
                    for dp in decision_points:
                        dp["pre_node"] = _strongest_pre_node(
                            _assess_pre_node_strength(lines, dp["line"]),
                            self.vsl_report.pre_node_for(str(rel_path), dp["line"]),
                        )
                    primitives["decision_points"].extend(decision_points)

                    # Pass 2 — classify consequences of each decision point
                    primitives["consequences"].extend(
                        self.consequence_classifier.classify(decision_points, lines)
                    )

                    # Agent actions: every @tool the model can call
                    for _action_dp, _action_c in _agent_tool_actions(
                        content, str(rel_path), lines, self.vsl_report,
                    ):
                        primitives["decision_points"].append(_action_dp)
                        primitives["consequences"].append(_action_c)

                    # Pass 5 — terminal states (unhandled exceptions, no recovery)
                    if should_scan_terminal_states:
                        primitives["terminal_states"].extend(
                            _detect_terminal_states(decision_points)
                        )
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]Decision point scan error in {rel_path}: {e}[/dim]")

                # Pass 4 — agent-to-agent handover detection
                try:
                    primitives["agent_handovers"].extend(
                        self.handover_analyser.analyse(content, str(rel_path), lines)
                    )
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]Agent handover scan error in {rel_path}: {e}[/dim]")

            # Pattern-based for JS/TS
            # Pattern-based (non-Python): AI-call detection (Pass 0) plus
            # decision-point/consequence/terminal-state detection (Passes 1,
            # 2, 5) via the shared PatternDecisionPointAnalyser subclasses.
            elif ext in PATTERN_LANGUAGE_CONFIG:
                ai_call_fn, decision_analyser_attr, label = PATTERN_LANGUAGE_CONFIG[ext]

                # Governance theatre — TS/JS only (agent-action-framework
                # validate() functions). Not gated by AI-adjacency: an action
                # registered into an agent's action set is part of the agent's
                # governance surface even if validate() itself makes no direct
                # AI SDK call — the LLM decides whether to invoke it elsewhere.
                if ext in (".js", ".ts", ".jsx", ".tsx"):
                    try:
                        theatre_findings = _detect_governance_theatre(content, str(rel_path))
                        primitives["governance_theatre"].extend(theatre_findings)
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[dim]Governance theatre scan error in {rel_path}: {e}[/dim]")

                    # Pass 4 (JS/TS) — agent-to-agent handover detection,
                    # family 5's manual-wrap sub-variant (LangChain.js).
                    try:
                        primitives["agent_handovers"].extend(
                            self.handover_analyser.analyse_js(content, str(rel_path), lines)
                        )
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[dim]JS agent handover scan error in {rel_path}: {e}[/dim]")

                try:
                    pattern_calls = ai_call_fn(content, lines)
                    for call in pattern_calls:
                        _pn_result = _assess_pre_node_strength(lines, call["line"], language="pattern")
                        pre_node = _pn_result is not None
                        human_review = _has_human_review(lines, call["line"])
                        primitives["ai_integrations"].append({
                            "id": f"AI-{len(primitives['ai_integrations'])+1:03d}",
                            "provider": call["provider"],
                            "location": f"{rel_path}:{call['line']}",
                            "line_content": call["line_content"],
                            "temperature": call.get("temperature"),
                            "max_tokens": call.get("max_tokens"),
                            "streaming": call.get("streaming", False),
                            "dynamic_prompt": "template" in content[
                                max(0, content.find(call["line_content"]) - 200):
                            ].lower(),
                            "user_input_in_prompt": any(
                                s in content[
                                    max(0, content.find(call["line_content"]) - 300):
                                ]
                                for s in [
                                    "req.body", "request.body", "userInput",
                                    "user_input", "query", "r.Body", "Request.Body",
                                ]
                            ),
                            "pre_node_detected": pre_node,
                            "human_review_detected": human_review,
                            "output_destination": self._detect_output_destination(lines, call["line"]),
                            "source_file": str(rel_path),
                            "file_context": file_context,
                        })
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]{label} AI-call scan error in {rel_path}: {e}[/dim]")

                # Pass 1 — decision points (pattern-based)
                try:
                    decision_analyser = getattr(self, decision_analyser_attr)
                    pattern_decision_points = decision_analyser.analyse(content, str(rel_path))
                    for dp in pattern_decision_points:
                        dp["pre_node"] = _assess_pre_node_strength(lines, dp["line"])
                    primitives["decision_points"].extend(pattern_decision_points)

                    # Pass 2 — classify consequences of each decision point
                    primitives["consequences"].extend(
                        self.consequence_classifier.classify(pattern_decision_points, lines)
                    )

                    # Pass 5 — terminal states (unhandled exceptions, no recovery)
                    if should_scan_terminal_states:
                        primitives["terminal_states"].extend(
                            _detect_terminal_states(pattern_decision_points)
                        )
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]{label} decision point scan error in {rel_path}: {e}[/dim]")

            # Raw-HTTP AI-provider calls — no SDK import, no distinctive
            # method name, only a known provider hostname inside a generic
            # fetch/httpx/requests/custom-wrapper HTTP call. Only checked if
            # this file produced zero AI-integration findings via the normal
            # import/pattern-based detectors above, to avoid double-counting
            # files that are already correctly detected.
            if len(primitives["ai_integrations"]) == _ai_integrations_before_this_file:
                try:
                    for finding in _detect_raw_http_ai_calls(content):
                        primitives["ai_integrations"].append({
                            "id": f"AI-{len(primitives['ai_integrations'])+1:03d}",
                            "provider": finding["provider"],
                            "location": f"{rel_path}:{finding['line']}",
                            "line_content": lines[finding["line"] - 1].strip() if 0 < finding["line"] <= len(lines) else "",
                            "temperature": None,
                            "max_tokens": None,
                            "streaming": False,
                            "dynamic_prompt": False,
                            "user_input_in_prompt": False,
                            "pre_node_detected": _assess_pre_node_strength(lines, finding["line"]) is not None,
                            "human_review_detected": _has_human_review(lines, finding["line"]),
                            "output_destination": self._detect_output_destination(lines, finding["line"]),
                            "source_file": str(rel_path),
                            "file_context": file_context,
                            "via": "raw_http_hostname",
                        })
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]Raw-HTTP AI-call scan error in {rel_path}: {e}[/dim]")

            # Irreversible actions — only on AI-adjacent files in ai-app profile
            should_scan_irrev = (
                self.profile["flag_irrev_outside_ai"]
                or is_adjacent
            )
            if should_scan_irrev:
                try:
                    irrev = _detect_irreversible_actions(lines, str(rel_path))
                    primitives["irreversible_actions"].extend(irrev)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]Irreversible action scan error in {rel_path}: {e}[/dim]")

            # Constraints — only on AI files, suppressed in system-utility profile
            if not self.profile["suppress_informal_invariants"] and is_ai_file:
                try:
                    self._detect_constraints(content, lines, rel_path, primitives)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim]Constraint scan error in {rel_path}: {e}[/dim]")

        # Cluster detection
        try:
            self._detect_clusters(base_path, primitives)
        except Exception as e:
            if self.verbose:
                console.print(f"[dim]Cluster detection error: {e}[/dim]")

        # Deduplicate irreversible actions
        seen = set()
        unique_irrev = []
        for a in primitives["irreversible_actions"]:
            key = f"{a['filepath']}:{a['line']}"
            if key not in seen:
                seen.add(key)
                unique_irrev.append(a)
        primitives["irreversible_actions"] = unique_irrev

        return primitives

    def _detect_constraints(self, content, lines, rel_path, primitives):
        constraint_patterns = [
            ("assertion", ["assert ", "assertTrue", "assertFalse"]),
            ("validation", ["validate_", "is_valid(", "check_input", "verify_"]),
            ("auth_check", [
                "@login_required", "@auth", "require_auth",
                "is_authenticated", "permission_required",
            ]),
        ]
        for i, line in enumerate(lines, 1):
            for c_type, patterns in constraint_patterns:
                for pattern in patterns:
                    if pattern in line and not line.strip().startswith("#"):
                        near_ai = self._is_near_ai_call(lines, i)
                        primitives["constraints"].append(Invariant(
                            location=f"{rel_path}:{i}",
                            type=c_type,
                            pattern=pattern,
                            line_content=line.strip()[:120],
                            near_ai_call=near_ai,
                        ).to_dict())
                        break

    def _detect_clusters(self, base_path: Path, primitives: dict) -> None:
        config_files = (
            list(base_path.rglob("docker-compose*.yml")) +
            list(base_path.rglob("kubernetes/*.yaml")) +
            list(base_path.rglob("k8s/*.yaml"))
        )
        if config_files or len(primitives["ai_integrations"]) > 3:
            primitives["clusters"].append({
                "detected": True,
                "evidence": [str(f.name) for f in config_files[:3]],
                "ai_integration_count": len(primitives["ai_integrations"]),
                "cluster_governance_required": True,
            })

    def _match_dc_patterns(self, primitives: dict, parsed: list) -> list:
        findings = []
        dc_classes = self.dc_classes.get("classes", {})
        seen_locations = set()
        dc_i11_locations = []  # R1: collect then aggregate

        for ai in primitives.get("ai_integrations", []):
            loc = ai["location"]
            # R3: skip DC-E5 and DC-L2 on framework files — they implement AI patterns
            # by design; governance is the responsibility of the application layer above.
            is_framework = ai.get("file_context") == "framework"

            # Unsanitised external input reaching an AI prompt is uncontrolled
            # signal injection (DC-E3, "information-level contamination") — not
            # DC-E5 (Dominance Forcing), which is specifically about coercive
            # rhetorical/grammatical structure, a different phenomenon entirely.
            if not is_framework and ai.get("user_input_in_prompt") and not ai.get("pre_node_detected"):
                key = f"DC-E3:{loc}"
                if key not in seen_locations:
                    seen_locations.add(key)
                    findings.append(self._build_finding(
                        "DC-E3", dc_classes.get("DC-E3", {}), loc,
                        "E3-L1", ai["id"],
                        "User input flows into AI prompt with no sanitisation checkpoint",
                        "critical",
                    ))

            # "Dynamic prompt assembly" alone isn't evidence of any specific
            # drift mechanism — it's a structural precondition shared by several
            # different DCs, not a signature of one. DC-L2 (Performative Capture)
            # specifically means outputs that *enact* change (the DAN jailbreak
            # pattern), which this pattern doesn't establish. Left unlabelled
            # rather than guessed — the underlying gap is still tracked separately
            # via _analyse_gaps regardless of whether it carries a DC code.

            temp = ai.get("temperature")
            if temp is not None and isinstance(temp, (int, float)) and temp > 0.7:
                key = f"DC-I6-temp:{loc}"
                if key not in seen_locations:
                    seen_locations.add(key)
                    findings.append(self._build_finding(
                        "DC-I6", dc_classes.get("DC-I6", {}), loc,
                        "I6-L1", ai["id"],
                        f"High temperature ({temp}) — a precondition consistent with cascade "
                        f"rupture risk, not direct evidence it is occurring",
                        "high",
                        confidence="SPECULATIVE",
                    ))

            # R1: collect DC-I11 instances rather than emitting one per call site
            if not ai.get("human_review_detected") and not ai.get("pre_node_detected"):
                if loc not in dc_i11_locations:
                    dc_i11_locations.append(loc)

        # R1 + R5: emit a single scan-level aggregate finding for DC-I11
        if dc_i11_locations:
            findings.append(self._build_dc_i11_aggregate(
                dc_i11_locations, dc_classes.get("DC-I11", {})
            ))

        if len(primitives.get("ai_integrations", [])) > 1:
            dc = dc_classes.get("DC-E13", {})
            key = "DC-E13:chained"
            if key not in seen_locations:
                seen_locations.add(key)
                count = len(primitives["ai_integrations"])
                findings.append(self._build_finding(
                    "DC-E13", dc, f"{count} AI calls detected",
                    "E13-L1", "chain",
                    f"{count} chained AI calls — output of one may seed the next without validation",
                    "high",
                ))

        if primitives.get("clusters"):
            dc = dc_classes.get("DC-S3", {})
            key = "DC-S3:cluster"
            if key not in seen_locations:
                seen_locations.add(key)
                findings.append(self._build_finding(
                    "DC-S3", dc, "cluster-level",
                    "S3-L1", "cluster",
                    "Multi-service architecture with no cluster-level governance — Flash Crash failure mode",
                    "critical",
                ))

        # DC-E14 (Substrate Contamination) is specifically about drift "activating
        # under specific trigger conditions after deployment" — the Knight Capital
        # signature. An ungated irreversible action with no such trigger is just a
        # generic Pre-Node gap (already captured by _analyse_gaps), not evidence of
        # this drift mechanism — only label it DC-E14 when a dormant/legacy-flag
        # guard is actually present.
        for action in primitives.get("irreversible_actions", []):
            if not action.get("dormant_trigger_guard"):
                continue
            loc = f"{action['filepath']}:{action['line']}"
            key = f"DC-E14:{loc}"
            if key not in seen_locations:
                seen_locations.add(key)
                dc = dc_classes.get("DC-E14", {})
                findings.append(self._build_finding(
                    "DC-E14", dc, loc,
                    "E14-L1", "irreversible",
                    f"Irreversible action ({action['action_type']}) gated only by a stale-looking "
                    f"condition ('{action['dormant_trigger_guard']}') with no authorisation check "
                    f"— Knight Capital failure mode",
                    "critical",
                ))

        return findings

    def _dc_meta_complete(self, dc_code: str) -> dict:
        """Look up a Drift Class's metadata in dc_classes_complete.json (Pass 6 data source)."""
        for tier_group in self.dc_classes_complete.get("drift_classes", {}).values():
            if dc_code in tier_group:
                return tier_group[dc_code]
        return {}

    def _build_finding(self, dc_code, dc, location, legion_code, triggered_by, evidence, severity, confidence="HIGH"):
        legions = dc.get("legions", {})
        legion = legions.get(legion_code, {})
        complete = self._dc_meta_complete(dc_code)
        primary_so = dc.get("primary_so") or complete.get("primary_so", "")
        so_data = self.so_operators.get("operators", {}).get(primary_so, {})
        so_complete = self.dc_classes_complete.get("stabilisation_operators", {}).get(primary_so, {})
        contraindications = self._get_contraindications(dc_code)
        monitoring_freq = self._get_monitoring_frequency(dc_code)

        return {
            "dc_code": dc_code,
            "dc_name": dc.get("name") or complete.get("name", ""),
            "tier": dc.get("tier") or complete.get("tier", ""),
            "location": location,
            "severity": severity,
            # How confident this DC label is — distinct from severity (how bad
            # IF true). HIGH = direct structural evidence; MEDIUM = plausible but
            # incomplete evidence; SPECULATIVE = a precondition consistent with
            # this DC, not a signature of it actually occurring.
            "confidence": confidence,
            "triggered_by": triggered_by,
            "evidence": evidence,
            "plain_english": dc.get("plain_english") or complete.get("operational_definition", ""),
            "what_happens_without_governance": dc.get("what_happens_without_governance", ""),
            "consequence": dc.get("consequence", ""),
            "legion_detected": {
                "code": legion_code,
                "name": legion.get("name", ""),
                "description": legion.get("description", ""),
            },
            "stabiliser_recommendation": {
                "primary_so": primary_so,
                "so_name": so_data.get("name") or so_complete.get("name", ""),
                "plain_english": so_data.get("plain_english") or so_complete.get("proposed_function", ""),
                "contraindications": contraindications,
            },
            "monitoring_frequency": monitoring_freq,
            "human_review_required": True,
            "policy": None,
            "invariant": None,
            "terminal_state": None,
            "severity_confirmed": None,
        }

    def _build_dc_i11_aggregate(self, locations: list, dc: dict) -> dict:
        """R1 — single scan-level aggregate for DC-I11 (Evaluative Decoupling).

        DC-I11 is a systemic property of the whole governance architecture,
        not a per-call-site property. One aggregate replaces N near-identical
        findings, reducing noise by ~70% while retaining the full location list
        for developer follow-up.
        """
        complete = self._dc_meta_complete("DC-I11")
        primary_so = dc.get("primary_so") or complete.get("primary_so", "")
        so_data = self.so_operators.get("operators", {}).get(primary_so, {})
        so_complete = self.dc_classes_complete.get("stabilisation_operators", {}).get(primary_so, {})
        count = len(locations)
        rep_locs = locations[:5]

        return {
            "dc_code": "DC-I11",
            "dc_name": dc.get("name") or complete.get("name", "Evaluative Decoupling"),
            "tier": dc.get("tier") or complete.get("tier", ""),
            "location": f"scan-level aggregate ({count} instances)",
            "severity": "informational",
            # Missing human review is a generic Pre-Node gap; it's only genuine
            # Evaluative Decoupling if there's also a metrics/objective-mismatch
            # signal, which isn't checked here — MEDIUM, not HIGH, confidence.
            "confidence": "MEDIUM",
            "aggregate": True,
            "aggregate_count": count,
            "aggregate_locations": locations,
            "triggered_by": "aggregate",
            "evidence": (
                f"{count} AI call site{'s' if count != 1 else ''} without a governance "
                f"checkpoint. Implement a governance checkpoint layer at your API entry "
                f"points rather than per-call-site."
            ),
            "plain_english": (
                dc.get("plain_english") or complete.get("operational_definition", "")
            ),
            "what_happens_without_governance": dc.get("what_happens_without_governance", ""),
            "consequence": dc.get("consequence", ""),
            "representative_locations": rep_locs,
            "recommendation": (
                "Implement a governance checkpoint layer at your API entry points. "
                f"Representative locations: {', '.join(rep_locs[:3])}"
                + (f" (+{count - 3} more)" if count > 3 else "")
            ),
            "legion_detected": {"code": "I11-L1", "name": "Aggregate", "description": ""},
            "stabiliser_recommendation": {
                "primary_so": primary_so,
                "so_name": so_data.get("name") or so_complete.get("name", ""),
                "plain_english": so_data.get("plain_english") or so_complete.get("proposed_function", ""),
                "contraindications": self._get_contraindications("DC-I11"),
            },
            "monitoring_frequency": self._get_monitoring_frequency("DC-I11"),
            "human_review_required": True,
            "policy": None,
            "invariant": None,
            "terminal_state": None,
            "severity_confirmed": None,
        }

    def _analyse_gaps(self, primitives: dict) -> list:
        gaps = []

        for ai in primitives.get("ai_integrations", []):
            # R3: framework files implement AI patterns by design — governance gaps
            # belong at the application layer that calls them, not inside the implementation.
            if ai.get("file_context") == "framework":
                continue

            if not ai.get("pre_node_detected"):
                gaps.append(GovernanceGap(
                    id=f"PN-GAP-{len(gaps)+1:03d}",
                    type="missing_pre_node",
                    location=ai["location"],
                    severity="critical",
                    plain_english=(
                        f"No checkpoint exists before the AI call at {ai['location']}. "
                        f"The AI receives input and produces output with nothing checking "
                        f"whether it should — or what it can return."
                    ),
                    what_is_missing="A mandatory checkpoint immediately before this AI call.",
                    consequence=(
                        "Any input reaches this AI call unfiltered. Any output proceeds "
                        "to its destination unchecked. No governance record exists."
                    ),
                    verba_term="Pre-Node gap",
                    recommended_action=(
                        "Define what must be checked before this AI call. "
                        "What conditions must be met? What must the AI never return?"
                    ),
                    policy=None,
                    extra={
                        "verba_explanation": (
                            "A Pre-Node is the mandatory checkpoint that fires at the saddle "
                            "point — the moment before commitment, where governance has maximum "
                            "leverage and minimum intervention cost."
                        ),
                        "ai_integration_ref": ai["id"],
                    },
                ).to_dict())

            if not ai.get("human_review_detected"):
                dest = ai.get("output_destination", "downstream")
                gaps.append(GovernanceGap(
                    id=f"HG-GAP-{len(gaps)+1:03d}",
                    type="missing_human_gate",
                    location=ai["location"],
                    severity="high",
                    plain_english=(
                        f"AI output flows to '{dest}' with no human review detected."
                    ),
                    what_is_missing="Human authorisation gate for critical severity outputs.",
                    consequence="Every AI output reaches its destination automatically.",
                    verba_term="Human-Authorised Transition missing",
                    recommended_action=(
                        "Define the severity and required authorisation level for this output."
                    ),
                    policy=None,
                    extra={
                        "verba_explanation": (
                            "In VERBA, a Human-Authorised Transition cannot be initiated by "
                            "automation — it requires explicit, auditable human approval."
                        ),
                        "ai_integration_ref": ai["id"],
                    },
                ).to_dict())

        for action in primitives.get("irreversible_actions", []):
            loc = f"{action['filepath']}:{action['line']}"
            gaps.append(GovernanceGap(
                id=f"IA-GAP-{len(gaps)+1:03d}",
                type="ungated_irreversible_action",
                location=loc,
                severity="critical",
                plain_english=(
                    f"An irreversible action ({action['action_type']}) at line {action['line']} "
                    f"in an AI-adjacent file has no authorisation gate. "
                    f"Once executed, it cannot be undone."
                ),
                what_is_missing="An eligibility condition confirming authorisation before execution.",
                consequence=(
                    "This action executes automatically. No human approval. "
                    "No record. No way to stop it once triggered. "
                    "Knight Capital lost $440M from exactly this pattern."
                ),
                verba_term="Eligibility Condition missing",
                recommended_action=(
                    "Define what must be confirmed before this action executes. "
                    "Define what happens if conditions are not met."
                ),
                policy=None,
                extra={
                    "verba_explanation": (
                        "An Eligibility Condition is a mandatory prerequisite that, if not met, "
                        "terminates automation and escalates to a human."
                    ),
                },
            ).to_dict())

        if not self.profile["suppress_informal_invariants"]:
            for constraint in primitives.get("constraints", []):
                gaps.append(GovernanceGap(
                    id=f"INV-GAP-{len(gaps)+1:03d}",
                    type="informal_invariant",
                    location=constraint["location"],
                    severity="medium",
                    plain_english=(
                        f"A governance check exists at {constraint['location']} "
                        f"but it is informal — not version-controlled, not machine-executable, "
                        f"not connected to any audit trail."
                    ),
                    what_is_missing="Formalisation as a VERBA Invariant.",
                    consequence=(
                        "A future refactor removes this check silently. "
                        "No test catches it. No audit records it."
                    ),
                    verba_term="Informal Invariant — needs formalisation",
                    recommended_action=(
                        "Formalise this check as an Invariant with CANNOT_BE_BYPASSED: TRUE."
                    ),
                    policy=None,
                    extra={
                        "verba_explanation": (
                            "An Invariant must always hold, cannot be bypassed, "
                            "and must be explicitly declared in the governance schema."
                        ),
                    },
                ).to_dict())

        return gaps

    def _analyse_decision_point_gaps(self, primitives: dict) -> list:
        """
        Pass 3 (enhanced) — for every decision point that leads to a
        consequential action, check whether a Pre-Node guards it and how
        strong that Pre-Node is. Decision points below the strength
        threshold (or with no Pre-Node at all) are flagged.

        This is additive to _analyse_gaps: it covers ALL decision points
        (conditionals, loops, try/except, agent invocations, consequential
        function calls), not just AI integrations and irreversible actions.
        """
        gaps = []
        strength_threshold = GOVERNANCE_STRENGTH_THRESHOLD
        consequence_by_loc = {
            c["decision_location"]: c for c in primitives.get("consequences", [])
        }

        for dp in primitives.get("decision_points", []):
            consequence = consequence_by_loc.get(dp["location"])
            if not consequence:
                continue

            pre_node = dp.get("pre_node")
            strength = pre_node["strength"] if pre_node else 0.0

            # A conditional/ternary whose own condition matches a Pre-Node
            # pattern (e.g. "if not is_authorized(user_id):") IS the gate
            # for the consequence that follows it — it doesn't need a gate
            # of its own.
            if dp["type"] in ("conditional_branch", "ternary"):
                sg = _is_self_governing_condition_text(dp.get("condition", ""))
                if sg and sg["strength"] > strength:
                    pre_node = sg
                    strength = sg["strength"]

            if strength >= strength_threshold:
                continue

            gaps.append(GovernanceGap(
                id=f"DP-GAP-{len(gaps)+1:03d}",
                type="ungoverned_decision_point",
                location=dp["location"],
                severity=consequence["severity"],
                plain_english=(
                    f"Decision point ({dp['type']}) at {dp['location']} leads to a "
                    f"{consequence['consequence_type']} action "
                    f"({'reversible' if consequence['reversible'] else 'irreversible'}) "
                    f"with {'no' if strength == 0 else 'a weak'} Pre-Node guarding it "
                    f"(strength {strength})."
                ),
                what_is_missing=(
                    "A Pre-Node check (validation, authorization, schema, or approval) "
                    "immediately before this decision point."
                ),
                consequence=consequence["action"],
                verba_term="Pre-Node gap",
                recommended_action=(
                    "Add or strengthen a Pre-Node (validation/authorization/approval) "
                    "immediately before this decision point."
                ),
                policy=None,
                extra={
                    "decision_type": dp["type"],
                    "consequence_type": consequence["consequence_type"],
                    "pre_node_pattern": pre_node["type"] if pre_node else None,
                    "pre_node_strength": strength,
                },
            ).to_dict())

        return gaps

    def _compute_gamma(self, primitives: dict, gaps: list, decision_point_gaps: list) -> dict:
        """
        Pass 9 — Structural Gamma = Governed Decision Points / Total Decision Points.

        v0.3.0: computed over ALL decision points that lead to a consequential
        action (Pass 1-3) plus all agent-to-agent handovers (Pass 4) — not just
        AI integrations and irreversible actions (the v0.2.0 proxy).

        Governed decision point = Pre-Node strength >= 0.5 (absent from
        decision_point_gaps). Governed agent handover = pre_node_exists.
        """
        consequence_locs = {
            c["decision_location"] for c in primitives.get("consequences", [])
        }
        governable_dps = [
            dp for dp in primitives.get("decision_points", [])
            if dp["location"] in consequence_locs
        ]
        handovers = primitives.get("agent_handovers", [])

        total_decision_points = len(governable_dps) + len(handovers)

        if total_decision_points == 0:
            return {
                "proxy_value": None,
                "threshold": 0.9,
                "status": "NO_GOVERNABLE_DECISION_POINTS",
                "interpretation": "No decision points leading to consequential actions were detected. Governance score not applicable.",
                "total_decision_points": 0,
                "governed_decision_points": 0,
                "important_note": "Structural proxy only. Runtime Gamma requires the VERBA Priming Engine.",
                "what_this_means": "Gamma = Governed Decision Points / Total Decision Points",
            }

        ungoverned_dp_locs = {g["location"] for g in decision_point_gaps}
        governed_dps = sum(
            1 for dp in governable_dps if dp["location"] not in ungoverned_dp_locs
        )
        governed_handovers = sum(1 for h in handovers if h.get("pre_node_exists"))

        governed = governed_dps + governed_handovers
        gamma = round(governed / total_decision_points, 2)

        if gamma >= 0.9:
            status = "ABOVE_THRESHOLD"
            interpretation = "Structural governance coverage meets the 90% sufficiency threshold."
        elif gamma >= 0.5:
            status = "PARTIAL_COVERAGE"
            interpretation = (
                f"Only {int(gamma*100)}% of decision points are governed. "
                f"Significant gaps remain."
            )
        else:
            status = "BELOW_THRESHOLD"
            interpretation = (
                f"Only {int(gamma*100)}% of decision points are governed. "
                f"The system is structurally ungoverned. "
                f"The Drift Node is the global energy minimum."
            )

        return {
            "proxy_value": gamma,
            "threshold": 0.9,
            "status": status,
            "interpretation": interpretation,
            "total_decision_points": total_decision_points,
            "governed_decision_points": governed,
            "important_note": (
                "Structural proxy only — not runtime Gamma. "
                "Measures whether governance mechanisms are structurally present."
            ),
            "what_this_means": "Gamma = Governed Decision Points / Total Decision Points",
        }

    def _build_summary(self, results, files, gaps, dc_findings, gamma):
        critical = sum(1 for g in gaps if g.get("severity") == "critical")
        high = sum(1 for g in gaps if g.get("severity") == "high")
        medium = sum(1 for g in gaps if g.get("severity") == "medium")
        # R5: informational = aggregate/structural findings (e.g. DC-I11 aggregate)
        dc_i11 = next((f for f in dc_findings if f.get("dc_code") == "DC-I11" and f.get("aggregate")), None)
        informational_dc_i11_count = dc_i11["aggregate_count"] if dc_i11 else 0
        ai_integrations = results.get("primitives", {}).get("ai_integrations", [])
        ai_count = len(ai_integrations)
        # R3: count how many AI call sites were in framework vs application files
        framework_ai_count = sum(1 for a in ai_integrations if a.get("file_context") == "framework")
        application_ai_count = ai_count - framework_ai_count
        total = gamma.get("total_decision_points", 0)
        governed = gamma.get("governed_decision_points", 0)
        coverage = int((governed / total) * 100) if total > 0 else 100

        decision_point_gaps = results.get("decision_point_gaps", [])
        dp_critical = sum(1 for g in decision_point_gaps if g.get("severity") == "critical")
        dp_medium = sum(1 for g in decision_point_gaps if g.get("severity") == "medium")

        agent_handovers = results.get("agent_handovers", [])
        ungoverned_handovers = sum(1 for h in agent_handovers if not h.get("pre_node_exists"))
        cluster_gaps = results.get("cluster_governance_gaps", [])
        terminal_states = results.get("terminal_states", [])

        legion_matches = results.get("legion_matches", [])
        legion_high = sum(1 for m in legion_matches if m.get("confidence") == "HIGH")
        legion_medium = sum(1 for m in legion_matches if m.get("confidence") == "MEDIUM")
        legion_speculative = sum(1 for m in legion_matches if m.get("confidence") == "SPECULATIVE")
        all_dc_codes = {f["dc_code"] for f in dc_findings} | {m["dc_code"] for m in legion_matches}

        return {
            "files_scanned": len(files),
            "ai_integrations_detected": ai_count,
            "ai_integrations_framework": framework_ai_count,
            "ai_integrations_application": application_ai_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "informational_dc_i11_count": informational_dc_i11_count,
            "dc_i11_aggregate": dc_i11,
            "total_gaps": len(gaps),
            "dc_classes_detected": len(dc_findings),
            "governance_coverage": f"{coverage}%",
            "structural_gamma": gamma.get("proxy_value"),
            "governance_status": gamma.get("status"),
            "context_profile": self.context_profile,
            "all_frameworks": self.all_frameworks,
            "decision_points_detected": len(results.get("decision_points", [])),
            "decision_point_gaps": len(decision_point_gaps),
            "decision_point_gaps_critical": dp_critical,
            "decision_point_gaps_medium": dp_medium,
            "agent_handovers_detected": len(agent_handovers),
            "agent_handovers_ungoverned": ungoverned_handovers,
            "cluster_governance_gaps": len(cluster_gaps),
            "terminal_states_detected": len(terminal_states),
            "legion_matches_detected": len(legion_matches),
            "legion_matches_high_confidence": legion_high,
            "legion_matches_medium_confidence": legion_medium,
            "legion_matches_speculative": legion_speculative,
            "distinct_dc_codes_detected": len(all_dc_codes),
            "boundary_case_notes": len(results.get("boundary_case_notes", [])),
            "language_coverage": results.get("language_coverage", {}),
            **self._build_v0_4_0_summary(results),
        }

    def _build_v0_4_0_summary(self, results: dict) -> dict:
        """
        v0.4.0 — fold Phase 1/2 inventories, coverage, tendency, Gamma
        variants, and algorithm results into the summary. Degrades
        gracefully (returns {}) if Pass 10-16 didn't run or produced
        nothing — keeping v0.3.0 summaries unaffected.
        """
        inventories = results.get("inventories") or {}
        metrics = results.get("metrics") or {}
        algorithms = results.get("algorithms") or {}

        ai_inventory = inventories.get("ai")
        agent_inventory = inventories.get("agent")
        decision_inventory = inventories.get("decision")
        coverage = metrics.get("coverage")
        tendency = metrics.get("tendency")
        gamma_variants = metrics.get("gamma_variants")

        if not all((ai_inventory, agent_inventory, decision_inventory, coverage, tendency, gamma_variants)):
            return {}

        return {
            "ai_inventory": {
                "total": ai_inventory.total,
                "by_provider": ai_inventory.by_provider,
                "governed": ai_inventory.governed,
                "ungoverned": ai_inventory.ungoverned,
                "high_risk_patterns": ai_inventory.high_risk_patterns,
            },
            "agent_inventory": {
                "total_agents": agent_inventory.total_agents,
                "handovers": agent_inventory.total_handovers,
                "governed_handovers": agent_inventory.governed_handovers,
                "ungoverned_handovers": agent_inventory.ungoverned_handovers,
                "chains": agent_inventory.total_chains,
                "fully_governed_chains": agent_inventory.fully_governed_chains,
                "partially_governed_chains": agent_inventory.partially_governed_chains,
                "ungoverned_chains": agent_inventory.ungoverned_chains,
                "clusters": agent_inventory.total_clusters,
            },
            "decision_inventory": {
                "total": decision_inventory.total,
                "by_consequence_type": decision_inventory.by_consequence_type,
                "by_criticality": decision_inventory.by_criticality,
                "critical": decision_inventory.critical_total,
            },
            "coverage": {
                "overall": coverage.overall_percent,
                "by_decision_type": coverage.by_decision_type,
                "by_consequence_type": coverage.by_consequence_type,
                "critical": coverage.critical_coverage,
                "by_checkpoint_type": coverage.by_checkpoint_type,
            },
            "tendency": {
                "state": tendency.state.value,
                "score": tendency.score,
                "t_amplification_active": tendency.t_amplification_active,
                "pre_node_proximity": tendency.pre_node_proximity,
                "ungoverned_decision_density": tendency.ungoverned_decision_density,
                "critical_ungoverned_ratio": tendency.critical_ungoverned_ratio,
            },
            "gamma_variants": {
                "overall": gamma_variants.overall.to_dict(),
                "by_decision_type": {k: v.to_dict() for k, v in gamma_variants.by_decision_type.items()},
                "by_consequence_type": {k: v.to_dict() for k, v in gamma_variants.by_consequence_type.items()},
                "critical": gamma_variants.critical.to_dict(),
                "agent_handover": gamma_variants.agent_handover.to_dict(),
                "agent_chain": gamma_variants.agent_chain.to_dict(),
                "cluster": gamma_variants.cluster.to_dict(),
            },
            "top_decisions": {
                "most_influential": list(algorithms.get("pagerank", {}).items())[:5],
                "critical_path": algorithms.get("critical_path", []),
            },
            # Supersede the v0.3.0 proxy (AI-integrations + irreversible-actions
            # only) with the v0.4.0 Gamma variant computed over ALL governable
            # decision points + agent handovers — this is the value the terminal
            # scorecard's "Structural Gamma" line and the report's GOVERNANCE
            # SCORECARD section both display.
            "agent_actions": _agent_action_summary(gamma_variants),
            "vsl": _vsl_summary(getattr(self, "vsl_report", None)),
            "structural_gamma": gamma_variants.overall.value,
            "governance_coverage": f"{round(gamma_variants.overall.value * 100)}%",
            "governance_status": gamma_variants.overall.status,
        }

    def _extract_critical_findings(self, gaps, dc_findings):
        critical = [g for g in gaps if g.get("severity") == "critical"]
        findings = []
        for gap in critical[:5]:
            dc_match = next(
                (d for d in dc_findings if d.get("location") == gap.get("location")),
                None,
            )
            findings.append({
                "location": gap.get("location", ""),
                "plain_english": gap.get("plain_english", "")[:120],
                "dc_candidate": (
                    f"{dc_match['dc_code']} {dc_match['dc_name']}"
                    if dc_match else gap.get("verba_term", "")
                ),
                "severity": "critical",
            })
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    # Template signal must co-occur with a prompt-related keyword on the SAME
    # line — checking a wide multi-line block for either signal independently
    # (the old behaviour) flagged unrelated code, e.g. a list comprehension
    # using the variable name "query" 15 lines away from an unrelated f-string.
    _DYNAMIC_PROMPT_KEYWORDS = ("prompt", "messages", "content", "system", "user")
    _DYNAMIC_PROMPT_TEMPLATE_SIGNALS = ('f"', "f'", ".format(", "{query}", "{input}", "{task}", "{context}")

    def _has_dynamic_prompt(self, content: str, line_num: int) -> bool:
        lines = content.splitlines()
        # Narrower window than the surrounding context checks (30 lines) — a
        # prompt is assembled close to where it's used, not anywhere in the
        # enclosing function.
        context_lines = lines[max(0, line_num - 10):line_num + 3]
        for line in context_lines:
            line_lower = line.lower()
            has_keyword = any(kw in line_lower for kw in self._DYNAMIC_PROMPT_KEYWORDS)
            has_template = any(s in line for s in self._DYNAMIC_PROMPT_TEMPLATE_SIGNALS)
            if has_keyword and has_template:
                return True
        return False

    def _has_user_input_in_prompt(self, content: str, line_num: int) -> bool:
        lines = content.splitlines()
        context = "\n".join(lines[max(0, line_num - 30):line_num + 5])
        user_signals = [
            "request.", "req.", "user_input", "user_message",
            "query", "input_text", "body", "form_data",
        ]
        prompt_signals = ["prompt", "messages", "content", "system"]
        return (
            any(s in context for s in user_signals)
            and any(s in context for s in prompt_signals)
        )

    def _detect_output_destination(self, lines: list, line_num: int) -> str:
        search = lines[line_num:min(len(lines), line_num + 15)]
        text = "\n".join(search)
        if any(s in text for s in ["return response", "render", "jsonify", "send_response"]):
            return "user-facing response"
        if any(s in text for s in ["db.", ".save(", ".commit(", "insert"]):
            return "database write"
        if any(s in text for s in ["requests.", "http.", "fetch(", "axios."]):
            return "external API call"
        if any(s in text for s in ["openai.", "anthropic.", "claude.", "generate"]):
            return "next AI call"
        return "downstream processing"

    def _is_near_ai_call(self, lines: list, line_num: int, window: int = 10) -> bool:
        search = lines[max(0, line_num - window):min(len(lines), line_num + window)]
        ai_signals = list(AI_PROVIDER_IMPORTS.keys()) + ["completion", "generate", "chat"]
        return any(any(s in line.lower() for s in ai_signals) for line in search)

    def _get_contraindications(self, dc_code: str) -> list:
        """
        Data-driven from dc_classes_complete.json: every Stabilisation
        Operator that lists ``dc_code`` in its ``contraindicated_on`` must
        not be applied to a Drift Class of this code. Cross-referenced with
        ``critical_contraindications`` for the reason text and predicted
        failure state. Returns objects shaped as {do_not_apply, so_name,
        reason, predicted_failure_state} for writer compatibility.
        """
        contraindications = []
        so_operators = self.dc_classes_complete.get("stabilisation_operators", {})
        critical = self.dc_classes_complete.get("critical_contraindications", {})

        for so_code, so_info in so_operators.items():
            if dc_code not in (so_info.get("contraindicated_on") or []):
                continue
            detail = next(
                (
                    c for c in critical.values()
                    if so_code in c.get("prohibition", "") and dc_code in c.get("prohibition", "")
                ),
                None,
            )
            contraindications.append({
                "do_not_apply": so_code,
                "so_name": so_info.get("name", ""),
                "to_dc": dc_code,
                "reason": (
                    detail["description"] if detail
                    else f"Do not apply {so_code} to {dc_code}."
                ),
                "predicted_failure_state": detail.get("predicted_failure_state") if detail else None,
                "prohibition": detail.get("prohibition", "") if detail else "",
            })

        return contraindications

    def _apply_boundary_cases(self, detected_dc_codes: set) -> list:
        """
        Pass 7 — boundary case discriminators.

        For every ambiguous DC pair in dc_classes_complete.json's
        boundary_cases, if both Drift Classes in the pair were detected in
        this scan, surface the distinguishing test and misdiagnosis risk so
        a human reviewer applies the correct discriminator before choosing
        a Stabilisation Operator.
        """
        notes = []
        for key, case in self.dc_classes_complete.get("boundary_cases", {}).items():
            classes = case.get("classes", [])
            if len(classes) == 2 and all(c in detected_dc_codes for c in classes):
                notes.append({
                    "boundary_case": key,
                    "classes": classes,
                    "distinguishing_test": case.get("distinguishing_test", ""),
                    "misdiagnosis_risk": case.get("misdiagnosis_risk", ""),
                    "why_it_matters": case.get("why_it_matters", ""),
                })
        return notes

    def _get_monitoring_frequency(self, dc_code: str) -> str:
        """
        Pass 8 — monitoring frequency, data-driven from
        dc_classes_complete.json (monitoring_frequency_by_dc). Falls back to
        the v0.2.0 default for DCs the data file doesn't assign a frequency to.
        """
        return self.monitoring_frequency_map.get(dc_code, "Per-turn monitoring recommended")


# ═══════════════════════════════════════════════════════════════════════════
# v0.4.0 — Governance Intelligence Foundation (Phase 1)
#
# Additive only: nothing below this line is called by the v0.3.0 passes
# (1-9) above. These data models, builders, and enrichers consume the
# `primitives` dict produced by `ScanEngine.scan()` and turn it into
# graphs, inventories, and enriched consequences for Phase 2 (governance
# coverage, tendency analysis, Gamma variants) and Phase 3 (graph
# algorithms, multi-section reporting).
# ═══════════════════════════════════════════════════════════════════════════

# ── TASK-001: Enhanced data models ────────────────────────────────────────────
#
# TendencyState, EnhancedConsequence, AgentNode/Edge/Graph,
# DecisionNode/Edge/Graph, AIInventory, AgentInventory, and
# DecisionInventory moved to models.py and imported above.


# ── TASK-002: Consequence taxonomy & enrichment ───────────────────────────────

# Full consequence taxonomy (Regeneration Handover, Part 4), grouping detailed
# consequence types under business categories and giving each a default
# blast radius / business impact. classify_consequence_type() matches a
# consequence's action text against these patterns; ConsequenceEnricher falls
# back to BASE_CONSEQUENCE_DEFAULTS (keyed by the v0.3.0 7-type
# CONSEQUENCE_TYPE_PATTERNS classification) when no detailed pattern matches.
CONSEQUENCE_TYPE_TAXONOMY = {
    # FINANCIAL
    "payment_processing": {
        "category": "financial",
        "patterns": ["stripe.charge", "stripe.paymentintent", "payment.create", "charge.create"],
        "blast_radius": "customer", "business_impact": "critical",
    },
    "refund_processing": {
        "category": "financial",
        "patterns": ["refund.create", "stripe.refund", ".refund("],
        "blast_radius": "customer", "business_impact": "critical",
    },
    "account_debit": {
        "category": "financial",
        "patterns": ["debit(", "balance -=", "account.debit"],
        "blast_radius": "customer", "business_impact": "critical",
    },

    # DATA_MUTATION
    "database_write": {
        "category": "data_mutation",
        "patterns": [
            "db.insert", "db.update", "session.add", "session.commit",
            "collection.insert", "collection.update", "insert into", "update ",
        ],
        "blast_radius": "department", "business_impact": "high",
    },
    "database_delete": {
        "category": "data_mutation",
        "patterns": [
            "db.delete", "collection.delete", "collection.drop",
            "session.delete", "delete from", ".drop(",
        ],
        "blast_radius": "customer", "business_impact": "critical",
    },
    "file_write": {
        "category": "data_mutation",
        "patterns": ["open(", ".write(", ".save("],
        "blast_radius": "organization", "business_impact": "medium",
    },
    "file_delete": {
        "category": "data_mutation",
        "patterns": ["os.remove", "os.unlink", "shutil.rmtree"],
        "blast_radius": "organization", "business_impact": "high",
    },
    "state_mutation": {
        "category": "data_mutation",
        "patterns": [".append(", ".pop(", ".extend(", ".update("],
        "blast_radius": "single_user", "business_impact": "low",
    },

    # DEPLOYMENT
    "production_release": {
        "category": "deployment",
        "patterns": ["deploy(", "release(", "kubectl apply", "docker push"],
        "blast_radius": "public", "business_impact": "critical",
    },
    "configuration_change": {
        "category": "deployment",
        "patterns": ["update_config", "config.set", "set_config"],
        "blast_radius": "organization", "business_impact": "high",
    },
    "infrastructure_modification": {
        "category": "deployment",
        "patterns": ["terraform apply", "cloudformation", "kubectl delete"],
        "blast_radius": "organization", "business_impact": "critical",
    },

    # COMMUNICATION
    "email_send": {
        "category": "communication",
        "patterns": ["send_mail", "smtp.sendmail", "sendgrid", "mailgun", "ses.send_email"],
        "blast_radius": "team", "business_impact": "medium",
    },
    "sms_send": {
        "category": "communication",
        "patterns": ["twilio", "send_sms", "sns.publish"],
        "blast_radius": "single_user", "business_impact": "medium",
    },
    "notification_push": {
        "category": "communication",
        "patterns": ["send_notification", "push_notification", "notify("],
        "blast_radius": "single_user", "business_impact": "low",
    },
    "external_api_call": {
        "category": "communication",
        "patterns": [
            "requests.post", "requests.put", "requests.delete", "requests.get",
            "httpx.post", "httpx.put", "httpx.delete", "httpx.get", "fetch(", "axios.",
        ],
        "blast_radius": "organization", "business_impact": "medium",
    },
    "webhook_trigger": {
        "category": "communication",
        "patterns": ["webhook", "trigger_event"],
        "blast_radius": "organization", "business_impact": "medium",
    },

    # EXECUTION
    "agent_invocation": {
        "category": "execution",
        "patterns": [
            "agent.run", "agent.invoke", "crew.kickoff", "execute_task",
            "initiate_chat", "graph.invoke",
        ],
        "blast_radius": "department", "business_impact": "medium",
    },
    "system_command": {
        "category": "execution",
        "patterns": ["os.system", "subprocess."],
        "blast_radius": "organization", "business_impact": "high",
    },
    "remote_job_submission": {
        "category": "execution",
        "patterns": ["submit_job", "celery", ".apply_async("],
        "blast_radius": "department", "business_impact": "medium",
    },

    # DATA_ACCESS
    "sensitive_data_read": {
        "category": "data_access",
        "patterns": ["get_pii", "fetch_ssn", "decrypt("],
        "blast_radius": "customer", "business_impact": "high",
    },
    "pii_access": {
        "category": "data_access",
        "patterns": ["pii", "social_security", "credit_card"],
        "blast_radius": "customer", "business_impact": "high",
    },
    "customer_data_export": {
        "category": "data_access",
        "patterns": ["export_data", "data_export", ".to_csv("],
        "blast_radius": "customer", "business_impact": "high",
    },
    "audit_log_query": {
        "category": "data_access",
        "patterns": ["audit_log", "get_audit"],
        "blast_radius": "team", "business_impact": "low",
    },

    # DECISION
    "authorization_decision": {
        "category": "decision",
        "patterns": ["is_authorized", "is_authorised", "has_permission", "check_permission"],
        "blast_radius": "department", "business_impact": "high",
    },
    "approval_decision": {
        "category": "decision",
        "patterns": ["approve(", "require_approval"],
        "blast_radius": "department", "business_impact": "high",
    },
    "feature_flag_toggle": {
        "category": "decision",
        "patterns": ["feature_flag", "toggle_feature", "set_flag"],
        "blast_radius": "organization", "business_impact": "medium",
    },
    "rate_limit_enforcement": {
        "category": "decision",
        "patterns": ["rate_limit", "throttle("],
        "blast_radius": "organization", "business_impact": "low",
    },
}

# Fallback mapping from v0.3.0's 7-type CONSEQUENCE_TYPE_PATTERNS classification
# to a detailed taxonomy key, used when no detailed pattern in
# CONSEQUENCE_TYPE_TAXONOMY matches the action text.
BASE_CONSEQUENCE_DEFAULTS = {
    "external_api": "external_api_call",
    "database": "database_write",
    "deployment": "production_release",
    "file_system": "file_write",
    "payment_action": "payment_processing",
    "agent_invocation": "agent_invocation",
    "state_mutation": "state_mutation",
}


def classify_consequence_type(action_text: str, base_type: Optional[str] = None) -> str:
    """
    Map a consequence's action text to a detailed consequence type from
    CONSEQUENCE_TYPE_TAXONOMY. Falls back to the v0.3.0 base classification
    (via BASE_CONSEQUENCE_DEFAULTS) when no detailed pattern matches, and to
    "unclassified" when neither is available.
    """
    text_lower = (action_text or "").lower()
    for detailed_type, spec in CONSEQUENCE_TYPE_TAXONOMY.items():
        if any(pattern in text_lower for pattern in spec["patterns"]):
            return detailed_type
    return BASE_CONSEQUENCE_DEFAULTS.get(base_type, "unclassified")


def estimate_blast_radius(consequence_type: str) -> str:
    """Default blast radius for a detailed consequence type (organization if unknown)."""
    if consequence_type in AGENT_ACTION_TYPES:
        return AGENT_ACTION_TYPES[consequence_type]["blast_radius"]
    return CONSEQUENCE_TYPE_TAXONOMY.get(consequence_type, {}).get("blast_radius", "organization")


def estimate_business_impact(consequence_type: str) -> str:
    """Default business impact for a detailed consequence type (medium if unknown)."""
    if consequence_type in AGENT_ACTION_TYPES:
        return AGENT_ACTION_TYPES[consequence_type]["business_impact"]
    return CONSEQUENCE_TYPE_TAXONOMY.get(consequence_type, {}).get("business_impact", "medium")


class ConsequenceEnricher:
    """
    Pass 10 — enriches each Pass 2 consequence with a detailed consequence
    type, blast radius, business impact, governance status (from the
    decision point's Pre-Node), and a computed criticality score.
    """

    def enrich(self, primitives: dict) -> List[EnhancedConsequence]:
        dp_by_location = {dp["location"]: dp for dp in primitives.get("decision_points", [])}
        enriched = []
        for c in primitives.get("consequences", []):
            if c.get("consequence_type") in AGENT_ACTION_TYPES:
                detailed_type = c["consequence_type"]
            else:
                detailed_type = classify_consequence_type(c.get("action", ""), c.get("consequence_type"))
            dp = dp_by_location.get(c["decision_location"], {})
            pre_node = dp.get("pre_node") or {}
            strength = pre_node.get("strength", 0.0)
            enriched.append(EnhancedConsequence(
                location=c["location"],
                decision_location=c["decision_location"],
                consequence_type=detailed_type,
                reversible="true" if c.get("reversible") else "false",
                blast_radius=estimate_blast_radius(detailed_type),
                business_impact=estimate_business_impact(detailed_type),
                governed=strength >= GOVERNANCE_STRENGTH_THRESHOLD,
                governance_type=pre_node.get("type"),
                governance_strength=strength,
                drift_class=None,
            ))
        return enriched


# ── TASK-003: Agent graph constructor ─────────────────────────────────────────

class AgentGraphBuilder:
    """
    Pass 11a — builds an AgentGraph from Pass 4 agent_handovers: one node per
    unique agent, one edge per handover, plus chain (linear sequence) and
    cluster (connected component) topology.
    """

    def build(self, primitives: dict) -> AgentGraph:
        handovers = primitives.get("agent_handovers", [])

        nodes_by_name: Dict[str, AgentNode] = {}
        edges: List[AgentEdge] = []

        for h in handovers:
            for agent_name, location in (
                (h["from_agent"], h["from_location"]),
                (h["to_agent"], h["location"]),
            ):
                if agent_name not in nodes_by_name:
                    nodes_by_name[agent_name] = AgentNode(
                        name=agent_name,
                        framework="unknown",
                        location=location,
                    )

            pre_node = h.get("pre_node") or {}
            strength = pre_node.get("strength", 0.0)
            edge = AgentEdge(
                from_agent=h["from_agent"],
                to_agent=h["to_agent"],
                data_variable=h.get("data_passed", ""),
                location=h["location"],
                pre_node_exists=bool(h.get("pre_node_exists")),
                pre_node_strength=strength,
                drift_class=h.get("drift_class"),
            )
            edges.append(edge)

            # The receiving agent's governance reflects the strongest
            # Pre-Node guarding any handover into it.
            to_node = nodes_by_name[h["to_agent"]]
            if strength > to_node.governance_strength:
                to_node.governance_strength = strength
                to_node.governed = edge.pre_node_exists
                to_node.governance_type = pre_node.get("type")

        chains = self._detect_chains(edges)
        clusters = self._detect_clusters(list(nodes_by_name.keys()), edges)

        return AgentGraph(
            nodes=list(nodes_by_name.values()),
            edges=edges,
            chains=chains,
            clusters=clusters,
        )

    def _detect_chains(self, edges: List[AgentEdge]) -> List[List[str]]:
        """
        Detect maximal linear sequences of handovers (A -> B -> C -> ...).

        A chain starts at an agent with no incoming handover and follows
        single (non-branching, non-merging) outgoing edges as far as
        possible.
        """
        adjacency: Dict[str, List[str]] = {}
        incoming: Dict[str, int] = {}
        all_agents = set()

        for e in edges:
            adjacency.setdefault(e.from_agent, []).append(e.to_agent)
            incoming[e.to_agent] = incoming.get(e.to_agent, 0) + 1
            all_agents.add(e.from_agent)
            all_agents.add(e.to_agent)

        starts = [a for a in all_agents if incoming.get(a, 0) == 0]
        if not starts:
            # Fully cyclic graph — treat every agent as a potential start.
            starts = sorted(all_agents)

        chains = []
        visited_starts = set()
        for start in sorted(starts):
            if start in visited_starts:
                continue

            chain = [start]
            seen = {start}
            current = start
            while True:
                nexts = adjacency.get(current, [])
                if len(nexts) != 1 or incoming.get(nexts[0], 0) > 1:
                    break
                nxt = nexts[0]
                if nxt in seen:
                    break
                chain.append(nxt)
                seen.add(nxt)
                current = nxt

            if len(chain) > 1:
                chains.append(chain)
                visited_starts.update(chain)

        return chains

    def _detect_clusters(self, agents: List[str], edges: List[AgentEdge]) -> List[List[str]]:
        """Connected components of the (undirected) agent handover graph."""
        adjacency: Dict[str, set] = {a: set() for a in agents}
        for e in edges:
            adjacency.setdefault(e.from_agent, set()).add(e.to_agent)
            adjacency.setdefault(e.to_agent, set()).add(e.from_agent)

        visited = set()
        clusters = []
        for agent in agents:
            if agent in visited:
                continue
            component = []
            stack = [agent]
            while stack:
                node = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                component.append(node)
                stack.extend(adjacency.get(node, set()) - visited)
            if len(component) > 1:
                clusters.append(sorted(component))

        return clusters


# ── TASK-004: Decision graph constructor ──────────────────────────────────────

class DecisionGraphBuilder:
    """
    Pass 11b — builds a DecisionGraph from Pass 1 decision_points and the
    Pass 10 EnhancedConsequence list: one node per decision point, one edge
    per decision-to-consequence mapping. A decision's criticality is the
    highest criticality among its downstream consequences.
    """

    def build(self, primitives: dict, enhanced_consequences: List[EnhancedConsequence]) -> DecisionGraph:
        nodes: Dict[str, DecisionNode] = {}
        for dp in primitives.get("decision_points", []):
            pre_node = dp.get("pre_node") or {}
            strength = pre_node.get("strength", 0.0)
            nodes[dp["location"]] = DecisionNode(
                id=dp["location"],
                decision_type=dp["type"],
                condition=dp.get("condition") or dp.get("call", ""),
                pre_node_strength=strength,
                governed=strength >= GOVERNANCE_STRENGTH_THRESHOLD,
            )

        edges: List[DecisionEdge] = []
        for ec in enhanced_consequences:
            edges.append(DecisionEdge(
                from_node=ec.decision_location,
                to_consequence=ec.location,
                consequence_type=ec.consequence_type,
                criticality=ec.criticality,
            ))

            node = nodes.get(ec.decision_location)
            if node is not None:
                node.criticality = max(node.criticality, ec.criticality)

        return DecisionGraph(nodes=nodes, edges=edges)


# ── TASK-005: Inventory builders ──────────────────────────────────────────────

class InventoryBuilder:
    """
    Pass 12 — aggregates primitives and Phase 1 graphs into high-level
    inventories: what AI exists, what agents/handovers/chains/clusters
    exist, and how decision points break down by consequence type and
    criticality.
    """

    def build_ai_inventory(self, primitives: dict) -> AIInventory:
        ai_integrations = primitives.get("ai_integrations", [])
        by_provider: Dict[str, int] = {}
        governed = 0
        high_risk = 0

        for ai in ai_integrations:
            provider = ai.get("provider", "unknown")
            by_provider[provider] = by_provider.get(provider, 0) + 1

            if (ai.get("pre_node_detected") and ai.get("human_review_detected")) or ai.get("vsl_governed"):
                governed += 1

            temperature = ai.get("temperature") or 0
            if (
                temperature > 0.7
                and ai.get("user_input_in_prompt")
                and ai.get("dynamic_prompt")
            ):
                high_risk += 1

        total = len(ai_integrations)
        return AIInventory(
            total=total,
            by_provider=by_provider,
            governed=governed,
            ungoverned=total - governed,
            high_risk_patterns=high_risk,
        )

    def build_agent_inventory(self, agent_graph: AgentGraph) -> AgentInventory:
        total_handovers = len(agent_graph.edges)
        governed_handovers = sum(1 for e in agent_graph.edges if e.pre_node_exists)

        fully_governed = partially_governed = ungoverned_chains = 0
        for chain in agent_graph.chains:
            chain_edges = [
                e for e in agent_graph.edges
                if e.from_agent in chain and e.to_agent in chain
            ]
            if not chain_edges:
                continue
            governed_count = sum(1 for e in chain_edges if e.pre_node_exists)
            if governed_count == len(chain_edges):
                fully_governed += 1
            elif governed_count == 0:
                ungoverned_chains += 1
            else:
                partially_governed += 1

        return AgentInventory(
            total_agents=len(agent_graph.nodes),
            total_handovers=total_handovers,
            governed_handovers=governed_handovers,
            ungoverned_handovers=total_handovers - governed_handovers,
            total_chains=len(agent_graph.chains),
            fully_governed_chains=fully_governed,
            partially_governed_chains=partially_governed,
            ungoverned_chains=ungoverned_chains,
            total_clusters=len(agent_graph.clusters),
        )

    def build_decision_inventory(self, decision_graph: DecisionGraph) -> DecisionInventory:
        by_consequence_type: Dict[str, int] = {}
        for edge in decision_graph.edges:
            by_consequence_type[edge.consequence_type] = by_consequence_type.get(edge.consequence_type, 0) + 1

        by_criticality = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for node in decision_graph.nodes.values():
            by_criticality[self._criticality_band(node.criticality)] += 1

        return DecisionInventory(
            total=len(decision_graph.nodes),
            by_consequence_type=by_consequence_type,
            by_criticality=by_criticality,
            critical_total=by_criticality["critical"],
        )

    @staticmethod
    def _criticality_band(value: float) -> str:
        if value >= 0.8:
            return "critical"
        if value >= 0.5:
            return "high"
        if value >= 0.2:
            return "medium"
        return "low"


# ═══════════════════════════════════════════════════════════════════════════
# v0.4.0 — Governance Intelligence Layers (Phase 2)
#
# Additive only: consumes the Phase 1 EnhancedConsequence list, AgentGraph,
# and DecisionGraph (plus raw primitives) to compute governance coverage,
# tendency state, Gamma variants, and decision-graph algorithms (PageRank,
# critical path, reachability, propagation potential).
# ═══════════════════════════════════════════════════════════════════════════

# Decision is "governed" if its strongest Pre-Node has strength >= this value.
# 0.5 let a guard with no hard block (no raise/return — pure scope overlap
# plus matching variable names) count as governed: 0.4 base + 0.2 soft
# enforcement (+0.2 causality) reached 0.6-0.8 with nothing that actually
# stops execution on failure. 0.7 requires real enforcement (a hard block,
# or the 0.7 dependency-injection signal) to count.
GOVERNANCE_STRENGTH_THRESHOLD = 0.7

# A decision/consequence is "critical" if its criticality score is >= this value.
CRITICALITY_THRESHOLD = 0.8

# Gamma status bands (Regeneration Handover, Part 11).
GAMMA_ABOVE_THRESHOLD = 0.9
GAMMA_PARTIAL_THRESHOLD = 0.5


def _gamma_status(value: float) -> str:
    """Classify a Gamma ratio (0.0-1.0) into a coverage status band."""
    if value >= GAMMA_ABOVE_THRESHOLD:
        return "ABOVE_THRESHOLD"
    if value >= GAMMA_PARTIAL_THRESHOLD:
        return "PARTIAL_COVERAGE"
    return "BELOW_THRESHOLD"


def _safe_ratio(numerator: float, denominator: float) -> float:
    """Division that returns 0.0 instead of raising on a zero denominator."""
    return numerator / denominator if denominator else 0.0


# ── TASK-006: Governance coverage models & builder ────────────────────────────
#
# GovernanceCoverage moved to models.py and imported above.


class GovernanceMetricsBuilder:
    """Pass 13 — compute governance coverage metrics from primitives and the DecisionGraph."""

    def compute_coverage(self, primitives: dict, decision_graph: DecisionGraph) -> GovernanceCoverage:
        """
        Compute overall, per-decision-type, per-consequence-type, and
        critical-decision governance coverage, plus a count of decisions by
        Pre-Node checkpoint type.

        Reference: Regeneration Handover, Part 5.
        """
        # Same consequential-only filter as GammaVariantsBuilder.compute() — a
        # decision point only belongs in the coverage surface if it leads to a
        # consequence. Otherwise null checks and simple loops dilute the figure.
        consequence_locs = {c["decision_location"] for c in primitives.get("consequences", [])}
        decision_points = [
            dp for dp in primitives.get("decision_points", [])
            if dp["location"] in consequence_locs
        ]
        overall_percent = self._percent_governed(decision_points)

        by_decision_type: Dict[str, float] = {}
        types = {dp["type"] for dp in decision_points}
        for dp_type in types:
            subset = [dp for dp in decision_points if dp["type"] == dp_type]
            by_decision_type[dp_type] = self._percent_governed(subset)

        by_consequence_type = self._consequence_type_coverage(primitives, decision_graph)

        consequential_node_ids = {edge.from_node for edge in decision_graph.edges}
        critical_nodes = [
            n for n_id, n in decision_graph.nodes.items()
            if n_id in consequential_node_ids and n.criticality >= CRITICALITY_THRESHOLD
        ]
        critical_governed = sum(1 for n in critical_nodes if n.governed)
        critical_coverage = _safe_ratio(critical_governed, len(critical_nodes)) * 100

        by_checkpoint_type = self._checkpoint_type_counts(decision_points)

        return GovernanceCoverage(
            overall_percent=overall_percent,
            by_decision_type=by_decision_type,
            by_consequence_type=by_consequence_type,
            critical_coverage=critical_coverage,
            by_checkpoint_type=by_checkpoint_type,
        )

    @staticmethod
    def _is_governed(dp: dict) -> bool:
        pre_node = dp.get("pre_node") or {}
        return pre_node.get("strength", 0.0) >= GOVERNANCE_STRENGTH_THRESHOLD

    def _percent_governed(self, decision_points: List[dict]) -> float:
        if not decision_points:
            return 0.0
        governed = sum(1 for dp in decision_points if self._is_governed(dp))
        return _safe_ratio(governed, len(decision_points)) * 100

    def _consequence_type_coverage(self, primitives: dict, decision_graph: DecisionGraph) -> Dict[str, float]:
        consequences = primitives.get("consequences", [])
        by_type: Dict[str, List[bool]] = {}
        for c in consequences:
            node = decision_graph.nodes.get(c["decision_location"])
            governed = node.governed if node is not None else False
            by_type.setdefault(c.get("consequence_type", "unclassified"), []).append(governed)

        return {
            c_type: _safe_ratio(sum(governed_flags), len(governed_flags)) * 100
            for c_type, governed_flags in by_type.items()
        }

    @staticmethod
    def _checkpoint_type_counts(decision_points: List[dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for dp in decision_points:
            pre_node = dp.get("pre_node") or {}
            if pre_node.get("strength", 0.0) >= GOVERNANCE_STRENGTH_THRESHOLD:
                checkpoint_type = pre_node.get("type", "unknown")
                counts[checkpoint_type] = counts.get(checkpoint_type, 0) + 1
        return counts


# ── TASK-007: Tendency analysis ───────────────────────────────────────────────
#
# TendencyIndicators moved to models.py and imported above.


class TendencyAnalyzer:
    """Pass 14 — classify the governance tendency of a scanned codebase."""

    def analyze(self, primitives: dict, decision_graph: DecisionGraph, agent_graph: AgentGraph) -> TendencyIndicators:
        decision_points = primitives.get("decision_points", [])
        total_decisions = len(decision_points)
        ungoverned_decisions = sum(1 for dp in decision_points if not GovernanceMetricsBuilder._is_governed(dp))
        ungoverned_decision_density = _safe_ratio(ungoverned_decisions, total_decisions)

        critical_nodes = [n for n in decision_graph.nodes.values() if n.criticality >= CRITICALITY_THRESHOLD]
        ungoverned_critical = sum(1 for n in critical_nodes if not n.governed)
        critical_ungoverned_ratio = _safe_ratio(ungoverned_critical, len(critical_nodes))

        total_handovers = len(agent_graph.edges)
        ungoverned_handovers = sum(1 for e in agent_graph.edges if not e.pre_node_exists)
        ungoverned_handover_ratio = _safe_ratio(ungoverned_handovers, total_handovers)

        # PageRank not computed yet at this point in the pipeline — approximate
        # high-centrality decisions as the top 10 by criticality (per
        # CLAUDE_CODE_PROMPT_PHASE2.md TASK-007 note).
        top_10 = sorted(decision_graph.nodes.values(), key=lambda n: n.criticality, reverse=True)[:10]
        high_centrality_ungoverned = sum(1 for n in top_10 if not n.governed)

        # Betweenness centrality is deferred to a later version.
        dependency_bridges_ungoverned = 0

        silent_failure_density = len(primitives.get("terminal_states", []))

        score = (
            ungoverned_decision_density * 0.3
            + critical_ungoverned_ratio * 0.3
            + ungoverned_handover_ratio * 0.2
            + (high_centrality_ungoverned / 10) * 0.1
            + (silent_failure_density / 5) * 0.1
        )
        state = self._classify_state(score)

        t_amplification_active = high_centrality_ungoverned > 0 and ungoverned_handover_ratio > 0.3
        pre_node_proximity = self._pre_node_proximity(critical_ungoverned_ratio)

        return TendencyIndicators(
            ungoverned_decision_density=ungoverned_decision_density,
            critical_ungoverned_ratio=critical_ungoverned_ratio,
            ungoverned_handover_ratio=ungoverned_handover_ratio,
            high_centrality_ungoverned=high_centrality_ungoverned,
            dependency_bridges_ungoverned=dependency_bridges_ungoverned,
            silent_failure_density=silent_failure_density,
            score=score,
            state=state,
            t_amplification_active=t_amplification_active,
            pre_node_proximity=pre_node_proximity,
        )

    @staticmethod
    def _classify_state(score: float) -> TendencyState:
        if score >= 0.7:
            return TendencyState.FAILURE
        if score >= 0.5:
            return TendencyState.CRITICAL
        if score >= 0.3:
            return TendencyState.AMPLIFYING
        if score >= 0.1:
            return TendencyState.EMERGING
        return TendencyState.STABLE

    @staticmethod
    def _pre_node_proximity(critical_ungoverned_ratio: float) -> str:
        if critical_ungoverned_ratio > 0.5:
            return "CRITICAL (>50% of critical decisions ungoverned)"
        if critical_ungoverned_ratio > 0.3:
            return "HIGH (30-50% of critical decisions ungoverned)"
        if critical_ungoverned_ratio > 0.1:
            return "MEDIUM (10-30% of critical decisions ungoverned)"
        return "LOW (<10% of critical decisions ungoverned)"


# ── TASK-008: Gamma variants ──────────────────────────────────────────────────
#
# GammaValue and GammaVariants moved to models.py and imported above.


class GammaVariantsBuilder:
    """Pass 15 — compute Structural Gamma across decision-type, consequence-type, criticality, and agent dimensions."""

    def compute(self, primitives: dict, decision_graph: DecisionGraph, agent_graph: AgentGraph) -> GammaVariants:
        # Only count decision points that lead to a consequential action —
        # decision_graph.nodes contains every decision point detected (including
        # null checks, simple loops, ternaries with no downstream consequence),
        # but a decision point only belongs in the governance surface if there's
        # something to govern. This matches the filter _compute_gamma() already
        # applies for the legacy proxy value.
        consequential_node_ids = {edge.from_node for edge in decision_graph.edges}
        nodes = [
            n for n_id, n in decision_graph.nodes.items()
            if n_id in consequential_node_ids
        ]

        overall = self._gamma(sum(1 for n in nodes if n.governed), len(nodes))

        by_decision_type: Dict[str, GammaValue] = {}
        for dp_type in {n.decision_type for n in nodes}:
            subset = [n for n in nodes if n.decision_type == dp_type]
            by_decision_type[dp_type] = self._gamma(sum(1 for n in subset if n.governed), len(subset))

        by_consequence_type: Dict[str, GammaValue] = {}
        for c in primitives.get("consequences", []):
            c_type = c.get("consequence_type", "unclassified")
            by_consequence_type.setdefault(c_type, []).append(c)
        by_consequence_type = {
            c_type: self._gamma(
                sum(1 for c in items if (decision_graph.nodes.get(c["decision_location"]) or DecisionNode("", "", "", 0.0, False)).governed),
                len(items),
            )
            for c_type, items in by_consequence_type.items()
        }

        critical_nodes = [n for n in nodes if n.criticality >= CRITICALITY_THRESHOLD]
        critical = self._gamma(sum(1 for n in critical_nodes if n.governed), len(critical_nodes))

        agent_handover = self._gamma(
            sum(1 for e in agent_graph.edges if e.pre_node_exists), len(agent_graph.edges)
        )

        fully_governed_chains = sum(
            1 for chain in agent_graph.chains
            if all(
                e.pre_node_exists
                for e in agent_graph.edges
                if e.from_agent in chain and e.to_agent in chain
            )
        )
        agent_chain = self._gamma(fully_governed_chains, len(agent_graph.chains))

        cluster = self._cluster_gamma(agent_graph)

        return GammaVariants(
            overall=overall,
            by_decision_type=by_decision_type,
            by_consequence_type=by_consequence_type,
            critical=critical,
            agent_handover=agent_handover,
            agent_chain=agent_chain,
            cluster=cluster,
        )

    @staticmethod
    def _gamma(governed: int, total: int) -> GammaValue:
        value = _safe_ratio(governed, total)
        # Status is computed from the precise ratio (so a value right at a
        # threshold boundary isn't misclassified by display rounding), but the
        # stored/displayed value itself is rounded to 2dp — every consumer
        # (terminal, JSON, YAML) reads this same field, so rounding once here
        # is sufficient everywhere.
        return GammaValue(value=round(value, 2), status=_gamma_status(value), governed=governed, total=total)

    def _cluster_gamma(self, agent_graph: AgentGraph) -> GammaValue:
        """
        Gamma for multi-agent clusters: fraction of within-cluster handovers
        that are governed. A cluster is a connected component of >= 2 agents
        (Phase 1 AgentGraphBuilder._detect_clusters).
        """
        cluster_agents = {agent for cluster in agent_graph.clusters for agent in cluster}
        cluster_edges = [
            e for e in agent_graph.edges
            if e.from_agent in cluster_agents and e.to_agent in cluster_agents
        ]
        governed = sum(1 for e in cluster_edges if e.pre_node_exists)
        return self._gamma(governed, len(cluster_edges))


# ── TASK-009 to TASK-012: Decision graph algorithms ───────────────────────────
#
# PageRank, critical path, reachability, and propagation-risk algorithms
# moved to graph/ (pagerank.py, critical_path.py, propagation.py) and
# imported above. DecisionGraphAnalyzer remains as a thin delegator so
# existing call sites (e.g. `DecisionGraphAnalyzer().pagerank(...)`) are
# unchanged.


class DecisionGraphAnalyzer:
    """
    Pass 16 — graph algorithms over a DecisionGraph: PageRank-based decision
    importance, critical path, reachability, and propagation-risk ranking.
    """

    def pagerank(
        self, decision_graph: DecisionGraph,
        damping: float = PAGERANK_DAMPING, iterations: int = PAGERANK_ITERATIONS,
    ) -> Dict[str, float]:
        return _pagerank(decision_graph, damping, iterations)

    def critical_path(self, decision_graph: DecisionGraph) -> List[str]:
        return _critical_path(decision_graph)

    def reachability_from(
        self, decision_graph: DecisionGraph, start_node: str, max_depth: int = 5,
    ) -> Dict[str, List[str]]:
        return _reachability_from(decision_graph, start_node, max_depth)

    def propagation_potential(
        self, decision_graph: DecisionGraph, ungoverned_decision: str, max_depth: int = 5,
    ) -> Dict[str, List[str]]:
        return _propagation_potential(decision_graph, ungoverned_decision, max_depth)


# ═══════════════════════════════════════════════════════════════════════════
# v0.4.0 — Report Generation & Output (Phase 3)
#
# Additive only: consumes the Phase 1/2 graphs, inventories, metrics, and
# algorithm results (plus v0.3.0 findings) to render a multi-section
# governance intelligence report. Does not change scan() orchestration logic
# beyond appending Pass 10-16 results to the existing `results` dict.
# ═══════════════════════════════════════════════════════════════════════════

REPORT_RULE = "═" * 80


def _pct(numerator: float, denominator: float) -> str:
    """Format a ratio as a whole-number percentage string, e.g. '68%'."""
    return f"{round(_safe_ratio(numerator, denominator) * 100)}%"


def _section_header(title: str) -> List[str]:
    return [REPORT_RULE, title, REPORT_RULE, ""]


def _scorecard_tendency_note(tendency: "TendencyIndicators") -> str:
    """One-sentence driver explanation for a non-stable tendency state."""
    if tendency.state.value == "stable":
        return ""
    reasons = []
    if tendency.critical_ungoverned_ratio > 0.3:
        reasons.append("ungoverned critical decisions")
    if tendency.t_amplification_active:
        reasons.append("T-Amplification active on high-centrality decisions")
    if tendency.ungoverned_decision_density > 0.5:
        reasons.append("high ungoverned decision density")
    if not reasons:
        reasons.append("weak Pre-Node coverage")
    return f"Tendency driven primarily by: {', '.join(reasons)}."


class ReportBuilder:
    """
    Pass 17 — renders each section of the governance scorecard as a
    formatted string. Reference: Executive Summary, Part 12.
    """

    # ── Section 1 ──────────────────────────────────────────────────────────

    def governance_scorecard(self, summary: dict, gamma_variants: GammaVariants, tendency: TendencyIndicators) -> str:
        """Top-line Structural Gamma and governance tendency."""
        lines = _section_header("GOVERNANCE SCORECARD")

        overall = gamma_variants.overall
        ungoverned = overall.total - overall.governed
        lines.append(
            f"Structural Gamma:                  {overall.value:.2f} / 1.0  [{overall.status}]"
        )
        gamma_pct = int(round(overall.value * 100))
        lines.append(
            f"  ({gamma_pct}% of governance-relevant decision points have an observable governance checkpoint.)"
        )
        lines.append(f"  ├─ Total Decision Points:        {overall.total}")
        lines.append(
            f"  ├─ Governed Decision Points:     {overall.governed} ({_pct(overall.governed, overall.total)})"
        )
        lines.append(
            f"  └─ Ungoverned Decision Points:   {ungoverned} ({_pct(ungoverned, overall.total)})"
        )
        lines.append("")

        action_lines = _agent_action_lines(summary)
        if action_lines:
            lines.extend(action_lines)
            lines.append("")

        lines.append(f"Tendency State:                     {tendency.state.value.upper()}")
        amp = "Yes" if tendency.t_amplification_active else "No"
        lines.append(
            f"  ├─ T-Amplification Active:       {amp} "
            f"({tendency.high_centrality_ungoverned} high-centrality ungoverned decisions)"
        )
        lines.append(f"  └─ Pre-Node Proximity:           {tendency.pre_node_proximity}")
        tendency_note = _scorecard_tendency_note(tendency)
        if tendency_note:
            lines.append(f"  Note: {tendency_note}")
        lines.append("")

        coverage_warning = self._language_coverage_warning(summary.get("language_coverage", {}))
        if coverage_warning:
            lines.append(coverage_warning)
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _language_coverage_warning(language_coverage: dict) -> Optional[str]:
        """
        Build a warning when decision/governance/Gamma/tendency metrics are
        derived from only a small fraction of the scanned files. Files in
        languages without a decision-point detector (e.g. .java, .go, .rb,
        .cs, .php) contribute nothing to decision points, consequences,
        agent handovers, or governance coverage.
        """
        total = language_coverage.get("total_files", 0)
        if not total:
            return None

        analysed = language_coverage.get("decision_analysed_files", 0)
        unanalysed = language_coverage.get("unanalysed_files", 0)
        fraction = language_coverage.get("decision_analysed_fraction", 0.0)

        if fraction >= LANGUAGE_COVERAGE_WARNING_THRESHOLD or unanalysed == 0:
            return None

        return (
            "WARNING — Limited Language Coverage:\n"
            f"  Decision/governance analysis covers {analysed}/{total} files "
            f"({_pct(analysed, total)}).\n"
            f"  The remaining {unanalysed} file(s) are in languages without a "
            "decision-point detector —\n"
            "  decision points, consequences, agent handovers, and governance "
            "coverage do not reflect them."
        )

    # ── Section 2 ──────────────────────────────────────────────────────────

    def ai_visibility(self, ai_inventory: AIInventory, dc_findings: list) -> str:
        """AI integration counts, providers, and AI-related drift class findings."""
        lines = _section_header("AI VISIBILITY")

        lines.append(f"AI Integrations Detected:          {ai_inventory.total}")
        lines.append(
            f"  ├─ Governed:                     {ai_inventory.governed} "
            f"({_pct(ai_inventory.governed, ai_inventory.total)})"
        )
        lines.append(
            f"  ├─ Ungoverned:                   {ai_inventory.ungoverned} "
            f"({_pct(ai_inventory.ungoverned, ai_inventory.total)})"
        )
        lines.append(
            f"  └─ High-Risk Patterns:           {ai_inventory.high_risk_patterns} "
            f"(high temperature + user input + dynamic prompt)"
        )
        lines.append("")
        lines.append(
            f"Candidate Governance Nodes:        {ai_inventory.total}  "
            f"(X-Verba inferences — confirm or correct in governance contract)"
        )
        lines.append("")

        if ai_inventory.by_provider:
            lines.append("Providers:")
            items = sorted(ai_inventory.by_provider.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (provider, count) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {provider.title():<26} {count}")
            lines.append("")

        ai_related = [f for f in dc_findings if f.get("dc_code", "").startswith(("DC-I", "DC-E5"))]
        if ai_related:
            lines.append(f"AI-Related Drift Class Findings:    {len(ai_related)}")
            by_code: Dict[str, int] = {}
            for f in ai_related:
                by_code[f["dc_code"]] = by_code.get(f["dc_code"], 0) + 1
            items = sorted(by_code.items())
            for idx, (code, count) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {code:<26} {count}")
            lines.append("")

        return "\n".join(lines)

    # ── Section 3 ──────────────────────────────────────────────────────────

    def agent_visibility(self, agent_inventory: AgentInventory, agent_graph: AgentGraph, cluster_gaps: list) -> str:
        """Agent handover, chain, and cluster governance counts."""
        lines = _section_header("AGENT VISIBILITY")

        lines.append(f"Agents Detected:                    {agent_inventory.total_agents}")
        lines.append(f"Agent Handovers Detected:           {agent_inventory.total_handovers}")
        lines.append(
            f"  ├─ Governed:                     {agent_inventory.governed_handovers} "
            f"({_pct(agent_inventory.governed_handovers, agent_inventory.total_handovers)})"
        )
        lines.append(
            f"  └─ Ungoverned:                   {agent_inventory.ungoverned_handovers} "
            f"({_pct(agent_inventory.ungoverned_handovers, agent_inventory.total_handovers)})"
        )
        lines.append("")

        lines.append(f"Agent Chains:                        {agent_inventory.total_chains}")
        lines.append(f"  ├─ Fully Governed:               {agent_inventory.fully_governed_chains}")
        lines.append(f"  ├─ Partially Governed:           {agent_inventory.partially_governed_chains}")
        lines.append(f"  └─ Ungoverned:                   {agent_inventory.ungoverned_chains}")
        lines.append("")

        chain_risk = agent_graph.chain_risk
        avg_risk = _safe_ratio(sum(chain_risk.values()), len(chain_risk)) if chain_risk else 0.0
        critical_risk_clusters = sum(1 for c in cluster_gaps if len(c.get("gaps", [])) >= 2)

        lines.append(f"Agent Clusters:                      {agent_inventory.total_clusters}")
        lines.append(f"  ├─ Cluster Risk (Avg Chain Risk): {avg_risk:.2f}")
        lines.append(f"  └─ Cluster Governance Gaps:      {len(cluster_gaps)} "
                      f"({critical_risk_clusters} with 2+ ungated handovers)")
        lines.append("")
        return "\n".join(lines)

    # ── Section 4 ──────────────────────────────────────────────────────────

    def decision_visibility(self, decision_inventory: DecisionInventory, decision_graph: DecisionGraph, pagerank_results: dict) -> str:
        """Decision counts by criticality, governance by consequence type, and influence ranking."""
        lines = _section_header("DECISION VISIBILITY")

        lines.append(f"Decision Points Detected:            {decision_inventory.total}")
        by_crit = decision_inventory.by_criticality
        for label, key in (("Low Consequence", "low"), ("Medium Consequence", "medium"),
                            ("High Consequence", "high"), ("Critical Consequence", "critical")):
            count = by_crit.get(key, 0)
            connector = "└─" if key == "critical" else "├─"
            lines.append(f"  {connector} {label:<24} {count} ({_pct(count, decision_inventory.total)})")
        lines.append("")

        if decision_inventory.by_consequence_type:
            lines.append("Governance by Consequence Type:")
            items = sorted(decision_inventory.by_consequence_type.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (c_type, total) in enumerate(items):
                edges = [e for e in decision_graph.edges if e.consequence_type == c_type]
                governed = sum(
                    1 for e in edges
                    if (decision_graph.nodes.get(e.from_node) or DecisionNode("", "", "", 0.0, False)).governed
                )
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {c_type} ({total}):  {governed} governed, {total - governed} ungoverned")
            lines.append("")

        if pagerank_results:
            ranked = list(pagerank_results.items())
            top_id, top_score = ranked[0]
            top_node = decision_graph.nodes.get(top_id)
            lines.append("Decision Influence Ranking (PageRank):")
            top_criticality = top_node.criticality if top_node else 0.0
            lines.append(
                f"  ├─ Most Influential Decision:   {top_id} "
                f"(score={top_score:.6f}, criticality={top_criticality:.2f})"
            )
            choke_point = next(
                ((node_id, score) for node_id, score in ranked
                 if not (decision_graph.nodes.get(node_id) or DecisionNode("", "", "", 0.0, True)).governed),
                None,
            )
            if choke_point:
                lines.append(f"  └─ Governance Choke Point:      {choke_point[0]} (score={choke_point[1]:.6f}, ungoverned)")
            else:
                lines.append("  └─ Governance Choke Point:      none (all high-influence decisions governed)")
            lines.append("")

        return "\n".join(lines)

    # ── Section 5 ──────────────────────────────────────────────────────────

    def governance_coverage(self, coverage: GovernanceCoverage, gamma_variants: GammaVariants) -> str:
        """Coverage percentages by decision type, checkpoint type, and criticality."""
        lines = _section_header("GOVERNANCE COVERAGE")

        lines.append(f"Overall Coverage:                    {coverage.overall_percent:.0f}%")
        lines.append("")

        if coverage.by_decision_type:
            lines.append("Coverage by Decision Type:")
            items = sorted(coverage.by_decision_type.items())
            for idx, (dp_type, pct) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {dp_type:<24} {pct:.0f}%")
            lines.append("")

        if coverage.by_checkpoint_type:
            lines.append("Coverage by Checkpoint Type:")
            items = sorted(coverage.by_checkpoint_type.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (checkpoint_type, count) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                display = CHECKPOINT_TYPE_DISPLAY.get(
                    checkpoint_type, checkpoint_type.replace("_", " ").title()
                )
                lines.append(f"  {connector} {display:<24} {count} decisions")
            lines.append("")

        critical = gamma_variants.critical
        lines.append("Critical Decision Coverage:")
        lines.append(f"  ├─ Critical Decisions:           {critical.total}")
        lines.append(f"  ├─ Governed:                     {critical.governed} ({_pct(critical.governed, critical.total)})")
        lines.append(
            f"  └─ Ungoverned:                   {critical.total - critical.governed} "
            f"({_pct(critical.total - critical.governed, critical.total)})"
        )
        lines.append("")
        return "\n".join(lines)

    # ── Section 6 ──────────────────────────────────────────────────────────

    def critical_findings(self, dc_findings: list, decision_point_gaps: list, decision_graph: DecisionGraph) -> str:
        """Top critical-severity findings with location, risk, and recommended action."""
        lines = _section_header("CRITICAL FINDINGS")

        critical_gaps = [g for g in decision_point_gaps if g.get("severity") == "critical"]
        critical_gaps.sort(
            key=lambda g: (decision_graph.nodes.get(g["location"]) or DecisionNode("", "", "", 0.0, False)).criticality,
            reverse=True,
        )

        if not critical_gaps:
            lines.append("No critical-severity decision point gaps detected.")
            lines.append("")
            return "\n".join(lines)

        for idx, gap in enumerate(critical_gaps[:5], start=1):
            node = decision_graph.nodes.get(gap["location"])
            dc_match = next((f for f in dc_findings if f.get("location") == gap["location"]), None)

            lines.append(f"{idx}. {gap['location']}")
            if dc_match:
                lines.append(f"     Drift Class:        {dc_match['dc_code']} ({dc_match.get('dc_name', '')})")
            lines.append(f"     Risk:                {gap.get('plain_english', '')}")
            lines.append(f"     Recommended Action:  {gap.get('recommended_action', '')}")
            if node is not None:
                lines.append(f"     Business Impact:     criticality={node.criticality:.2f}, governed={node.governed}")
            lines.append("")

        return "\n".join(lines)

    # ── Section 7 ──────────────────────────────────────────────────────────

    def governance_gaps_summary(self, gaps: list, decision_point_gaps: list, agent_handovers: list, cluster_gaps: list, terminal_states: list) -> str:
        """Counts of governance gaps by severity and category."""
        lines = _section_header("GOVERNANCE GAPS SUMMARY")

        all_gaps = gaps + decision_point_gaps
        critical = [g for g in all_gaps if g.get("severity") == "critical"]
        high = [g for g in all_gaps if g.get("severity") == "high"]
        medium = [g for g in all_gaps if g.get("severity") == "medium"]

        lines.append(f"Critical Governance Gaps:            {len(critical)}")
        if critical:
            by_type: Dict[str, int] = {}
            for g in critical:
                by_type[g.get("type", "unknown")] = by_type.get(g.get("type", "unknown"), 0) + 1
            items = sorted(by_type.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (gap_type, count) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {gap_type.replace('_', ' ').title():<28} {count}")
        lines.append("")

        lines.append(f"High Governance Gaps:                {len(high)}")
        lines.append(f"Medium Governance Gaps:              {len(medium)}")
        lines.append("")

        ungoverned_handovers = sum(1 for h in agent_handovers if not h.get("pre_node_exists"))
        lines.append(f"Agent Handover Gaps:                 {ungoverned_handovers} / {len(agent_handovers)} ungoverned")
        lines.append(f"Cluster Governance Gaps:             {len(cluster_gaps)}")
        lines.append(f"Terminal States (Silent Failures):   {len(terminal_states)}")
        lines.append("")
        return "\n".join(lines)

    def governance_theatre(self, theatre_findings: list) -> str:
        """TS/JS validate() functions with no usable parameter access that
        unconditionally return true — a governance gate that enforces
        nothing. Additive finding category; does not affect Gamma."""
        lines = _section_header("GOVERNANCE THEATRE")

        if not theatre_findings:
            lines.append("No governance theatre detected.")
            lines.append("")
            return "\n".join(lines)

        lines.append(
            f"Validators with no usable parameter access, returning "
            f"unconditional true: {len(theatre_findings)}"
        )
        lines.append("")
        for idx, f in enumerate(theatre_findings[:10], start=1):
            lines.append(f"{idx}. {f['location']}  [{f['form']}]")
            lines.append(f"     {f.get('plain_english', '')}")
            lines.append("")
        if len(theatre_findings) > 10:
            lines.append(f"  ... and {len(theatre_findings) - 10} more.")
            lines.append("")
        return "\n".join(lines)

    # ── Section 8 ──────────────────────────────────────────────────────────

    # Behavioural domain groupings for Drift Class codes
    _DC_DOMAIN: Dict[str, str] = {
        "DC-E3":  "AI",
        "DC-E5":  "AI",
        "DC-L2":  "AI",
        "DC-S3":  "Multi-Agent / Cluster",
        "DC-E14": "Infrastructure",
        "DC-I11": "AI",
        "DC-I6":  "AI",
        "DC-E13": "AI",
        "DC-S7":  "Multi-Agent / Cluster",
    }

    # Fallback human-readable names when dc_name field is empty. Names below
    # are the canonical ones from dc_classes_complete.json — verified against
    # the real operational definitions; do not "improve" these without
    # checking the data file first, since prior versions of this dict drifted
    # from the canonical names without anyone noticing for some time.
    _DC_NAME_FALLBACK: Dict[str, str] = {
        "DC-E3":  "Signal Corruption",
        "DC-E5":  "Dominance Forcing",
        "DC-E13": "Propagating Corruption",
        "DC-E14": "Substrate Contamination",
        "DC-I6":  "Cascade Rupture",
        "DC-I11": "Evaluative Decoupling",
        "DC-L2":  "Performative Capture",
        "DC-S3":  "Emergent Misalignment",
        "DC-S7":  "Symbiotic Corruption",
    }

    def drift_class_detections(self, dc_findings: list, legion_matches: list) -> str:
        """All drift class findings and Legion matches, grouped by DC code and confidence."""
        lines = _section_header("DRIFT CLASS DETECTIONS")

        by_code: Dict[str, Dict[str, int]] = {}
        dc_names: Dict[str, str] = {}
        for f in dc_findings:
            code = f["dc_code"]
            confidence = f.get("confidence", "HIGH")
            by_code.setdefault(code, {})[confidence] = by_code.setdefault(code, {}).get(confidence, 0) + 1
            if not dc_names.get(code):
                dc_names[code] = f.get("dc_name") or self._DC_NAME_FALLBACK.get(code, "")
        for m in legion_matches:
            code = m["dc_code"]
            confidence = m.get("confidence", "SPECULATIVE")
            by_code.setdefault(code, {})[confidence] = by_code.setdefault(code, {}).get(confidence, 0) + 1
            if not dc_names.get(code):
                dc_names[code] = m.get("dc_name") or self._DC_NAME_FALLBACK.get(code, "")

        speculative_total = sum(1 for m in legion_matches if m.get("confidence") == "SPECULATIVE")

        if not by_code:
            lines.append("No drift class detections.")
            lines.append("")
            return "\n".join(lines)

        for code in sorted(by_code.keys()):
            confidences = by_code[code]
            total = sum(confidences.values())
            confidence_str = ", ".join(f"{c} {n}" for c, n in sorted(confidences.items()))
            name = dc_names.get(code, "")
            name_part = f" — {name}" if name else ""
            lines.append(f"{code}{name_part:<40} {total} detection(s)  ({confidence_str})")
        lines.append("")

        if speculative_total:
            lines.append(f"Speculative Matches (Low Confidence): {speculative_total}")
            lines.append("  └─ Recommendation: Review for false positives")
            lines.append("")

        domain_counts: Dict[str, int] = {}
        for code, confidences in by_code.items():
            domain = self._DC_DOMAIN.get(code)
            if not domain:
                prefix = code.split("-")[1][0] if "-" in code and len(code.split("-")) > 1 else ""
                domain = {"I": "AI", "E": "External / State", "L": "Lifecycle", "S": "Config / State"}.get(prefix, "Other")
            domain_counts[domain] = domain_counts.get(domain, 0) + sum(confidences.values())

        if domain_counts:
            lines.append("Behavioural Domains Affected:")
            items = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (domain, count) in enumerate(items):
                connector = "└─" if idx == len(items) - 1 else "├─"
                lines.append(f"  {connector} {domain:<24} {count} detection(s)")
            lines.append("")

        return "\n".join(lines)

    # ── Section 9 ──────────────────────────────────────────────────────────

    def governance_recommendations(self, gaps: list, dc_findings: list, decision_graph: DecisionGraph, pagerank_results: dict) -> str:
        """Prioritised recommendations: immediate (critical), short-term (high), medium-term (medium)."""
        lines = _section_header("GOVERNANCE RECOMMENDATIONS")

        def _priority(gap: dict) -> float:
            node = decision_graph.nodes.get(gap.get("location", ""))
            criticality = node.criticality if node else 0.0
            rank = pagerank_results.get(gap.get("location", ""), 0.0)
            return criticality + rank

        critical = sorted((g for g in gaps if g.get("severity") == "critical"), key=_priority, reverse=True)
        high = sorted((g for g in gaps if g.get("severity") == "high"), key=_priority, reverse=True)
        medium = sorted((g for g in gaps if g.get("severity") == "medium"), key=_priority, reverse=True)

        for title, bucket in (
            (f"Immediate Actions (Critical): {len(critical)} items", critical),
            (f"Short-term (High): {len(high)} items", high),
            (f"Medium-term (Medium): {len(medium)} items", medium),
        ):
            lines.append(title)
            if not bucket:
                lines.append("  (none)")
            for idx, gap in enumerate(bucket[:5], start=1):
                dc_match = next((f for f in dc_findings if f.get("location") == gap.get("location")), None)
                tag = f" [{dc_match['dc_code']}]" if dc_match else ""
                lines.append(f"  {idx}. {gap.get('recommended_action', '')} — {gap.get('location', '')}{tag}")
            lines.append("")

        lines.append("Implementation order is based on:")
        lines.append("  - Decision criticality (business_impact x blast_radius x irreversibility)")
        lines.append("  - PageRank (most influential decisions first)")
        lines.append("  - Severity (critical > high > medium)")
        lines.append("")
        return "\n".join(lines)


class OutputFormatter:
    """Pass 18 — render full scan results as a text report or JSON document."""

    def __init__(self):
        self.report_builder = ReportBuilder()

    def format_report(self, results: dict, fmt: str = "text") -> str:
        """
        Render `results` (the dict returned by ScanEngine.scan()) as a
        report.

        fmt: "text" for the console governance scorecard, "json" for a
        fully serialisable JSON document.
        """
        if fmt == "json":
            return json.dumps(OutputFormatter._json_safe(results), indent=2, default=str)
        return self._format_text(results)

    def _format_text(self, results: dict) -> str:
        output = [REPORT_RULE, "X-VERBA SCAN RESULTS", REPORT_RULE, ""]
        output.append(f"Repository:  {results.get('repo', '')}")
        output.append(f"Scan Date:   {results.get('scan_date', '')}")
        output.append("")

        graphs = results.get("graphs") or {}
        inventories = results.get("inventories") or {}
        metrics = results.get("metrics") or {}
        algorithms = results.get("algorithms") or {}

        agent_graph = graphs.get("agent_graph")
        decision_graph = graphs.get("decision_graph")
        gamma_variants = metrics.get("gamma_variants")
        tendency = metrics.get("tendency")
        coverage = metrics.get("coverage")

        sections: List[str] = []

        if gamma_variants is not None and tendency is not None:
            sections.append(self.report_builder.governance_scorecard(
                results.get("summary", {}), gamma_variants, tendency,
            ))
        else:
            sections.append("\n".join(_section_header("GOVERNANCE SCORECARD") + ["Analysis not available.", ""]))

        if "ai" in inventories:
            sections.append(self.report_builder.ai_visibility(inventories["ai"], results.get("drift_classes", [])))
        if "agent" in inventories and agent_graph is not None:
            sections.append(self.report_builder.agent_visibility(
                inventories["agent"], agent_graph, results.get("cluster_governance_gaps", []),
            ))
        if "decision" in inventories and decision_graph is not None:
            sections.append(self.report_builder.decision_visibility(
                inventories["decision"], decision_graph, algorithms.get("pagerank", {}),
            ))
        if coverage is not None and gamma_variants is not None:
            sections.append(self.report_builder.governance_coverage(coverage, gamma_variants))
        if decision_graph is not None:
            sections.append(self.report_builder.critical_findings(
                results.get("drift_classes", []), results.get("decision_point_gaps", []), decision_graph,
            ))

        sections.append(self.report_builder.governance_gaps_summary(
            results.get("gaps", []), results.get("decision_point_gaps", []),
            results.get("agent_handovers", []), results.get("cluster_governance_gaps", []),
            results.get("terminal_states", []),
        ))
        sections.append(self.report_builder.governance_theatre(
            results.get("governance_theatre", []),
        ))
        sections.append(self.report_builder.drift_class_detections(
            results.get("drift_classes", []), results.get("legion_matches", []),
        ))
        if decision_graph is not None:
            sections.append(self.report_builder.governance_recommendations(
                results.get("gaps", []), results.get("drift_classes", []),
                decision_graph, algorithms.get("pagerank", {}),
            ))

        for section in sections:
            output.append(section)

        output.append(REPORT_RULE)
        output.append("End of Report")
        output.append(REPORT_RULE)
        return "\n".join(output)

    @staticmethod
    def _json_safe(value):
        """Recursively convert dataclasses/enums into JSON-safe primitives."""
        if hasattr(value, "to_dict"):
            return OutputFormatter._json_safe(value.to_dict())
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {k: OutputFormatter._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [OutputFormatter._json_safe(v) for v in value]
        return value


