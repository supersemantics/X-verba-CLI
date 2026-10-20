"""
X-Verba Output Writer v0.4.0

Generates the VERBA governance contract — the developer-facing template
that defines what the system must and must never do.

Structure (unchanged from v0.2.0):
  1. System Identity
  2. Governance Nodes (candidate stabilised behavioural patterns)
  3. Pre-Nodes (what must be checked before each node)
  4. Invariants (rules that must always hold)
  5. Thresholds (quantitative limits)
  6. Human Authorisation Gates
  7. Terminal States (where automation must stop)
  8. Drift Class Candidates (diagnostic context)
  9. Governance Score

New in v0.4.0 — read-only reference sections sourced from engine.py's
governance-intelligence layers (Passes 10-16):
  10. Governance Intelligence (coverage, tendency, Gamma variants)
  11. Agent Governance (agent/handover/chain/cluster inventory)
  12. Critical Decisions (PageRank-ranked, criticality-ranked decisions)

These three sections are additive only. If a results dict was produced by
an older engine (no "summary"/"top_decisions"/etc. v0.4.0 keys), they are
skipped and the contract still contains sections 1-9.

Design principle: a developer who has never heard of VERBA should be able
to open this file, read the comments, and know exactly what to fill in.
VERBA terms appear as field names, not as required prior knowledge.

Plain English first. VERBA term second. Always.
"""
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone

from .engine import OutputFormatter
from .qa_engine import _dc_qa_recommendations

# Mirrors engine.py's GAMMA_ABOVE_THRESHOLD / GAMMA_PARTIAL_THRESHOLD —
# the canonical Gamma status bands (Regeneration Handover, Part 11).
GAMMA_ABOVE_THRESHOLD = 0.9
GAMMA_PARTIAL_THRESHOLD = 0.5

GAMMA_PROXY_NOTE = (
    "Structural proxy only — not runtime Gamma. "
    "Measures whether governance mechanisms are structurally present."
)


def _gamma_interpretation(status: str, value) -> str:
    """Human-readable interpretation of a canonical GammaValue, by status."""
    if status == "NO_AI_INTEGRATIONS":
        return (
            "No AI integration points detected. Structural governance analysis "
            "still applies to decision points, error handling, and control flow "
            "regardless of AI presence — see the Gamma value above."
        )
    if status == "ABOVE_THRESHOLD":
        return f"Structural governance coverage meets the {int(GAMMA_ABOVE_THRESHOLD*100)}% sufficiency threshold."
    if status == "PARTIAL_COVERAGE":
        pct = round(value * 100) if value is not None else 0
        return f"Only {pct}% of decision points are governed. Significant gaps remain."
    if status == "BELOW_THRESHOLD":
        pct = round(value * 100) if value is not None else 0
        return (
            f"Only {pct}% of decision points are governed. "
            "The system is structurally ungoverned. "
            "The Drift Node is the global energy minimum."
        )
    return ""


# ── Node inference ────────────────────────────────────────────────────────────
# Keyword sets used by _infer_candidate_node to derive a behavioural-state name
# from an AI integration's line content and output destination.
_EMBED_KW      = frozenset({"embed", "embedding", "embeddings", "vector", "vectorize", "encode"})
_CLASSIFY_KW   = frozenset({"classify", "classification", "categorize", "categorise"})
_SUMMARIZE_KW  = frozenset({"summarize", "summarise", "summary", "tldr"})
_SEARCH_KW     = frozenset({"semantic_search", "similarity_search", "retrieve", "retrieval"})
_RERANK_KW     = frozenset({"rerank", "re_rank", "reranker"})
_EXTRACT_KW    = frozenset({"extract", "extraction", "structured_output", "parse_output"})
_STREAM_DEST   = frozenset({"queue", "stream", "publish", "emit"})
_PERSIST_DEST  = frozenset({"db", "database", "store", "save", "persist", "write", "insert"})
_USER_DEST     = frozenset({"user", "response", "reply", "message", "output"})


def _infer_candidate_node(ai: dict) -> tuple[str, str]:
    """Propose a behavioural-state Node name from an AI integration entry.

    Returns (candidate_node, confidence) where confidence is HIGH, MEDIUM, or LOW.
    HIGH  — unambiguous keyword found in the method name / call line.
    MEDIUM — destination or provider context narrows the operation.
    LOW   — no signal; generic fallback.
    """
    line   = (ai.get("line_content")      or "").lower()
    dest   = (ai.get("output_destination") or "").lower()
    provider = (ai.get("provider")         or "").lower()

    known_llm_providers = {"openai", "anthropic", "google", "mistral", "cohere",
                            "azure", "bedrock", "huggingface", "ollama", "groq"}

    if any(k in line for k in _EMBED_KW):
        return "EMBEDDINGS_GENERATED", "HIGH"
    if any(k in line for k in _CLASSIFY_KW):
        return "CONTENT_CLASSIFIED", "HIGH"
    if any(k in line for k in _SUMMARIZE_KW):
        return "CONTENT_SUMMARIZED", "HIGH"
    if any(k in line for k in _SEARCH_KW):
        return "SEMANTIC_SEARCH_EXECUTED", "HIGH"
    if any(k in line for k in _RERANK_KW):
        return "RESULTS_RERANKED", "HIGH"
    if any(k in line for k in _EXTRACT_KW):
        return "STRUCTURED_DATA_EXTRACTED", "HIGH"

    if dest:
        if any(k in dest for k in _USER_DEST):
            return "AI_RESPONSE_GENERATED", "MEDIUM"
        if any(k in dest for k in _PERSIST_DEST):
            return "AI_OUTPUT_PERSISTED", "MEDIUM"
        if any(k in dest for k in _STREAM_DEST):
            return "AI_OUTPUT_STREAMED", "MEDIUM"

    if provider in known_llm_providers:
        return "AI_RESPONSE_GENERATED", "MEDIUM"

    return "AI_OPERATION_EXECUTED", "LOW"


class OutputWriter:
    """Writes scan results as a VERBA governance contract."""

    def __init__(self, results: dict, output_format: str = "yaml"):
        self.results = results
        self.format = output_format.lower()

    def write(self, output_path: str = None) -> str:
        if not output_path:
            output_path = self._default_output_path()

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.format == "yaml":
            content = self._render_yaml()
        elif self.format == "json":
            content = self._render_json()
        elif self.format == "md":
            content = self._render_markdown()
        else:
            content = self._render_yaml()

        path.write_text(content, encoding="utf-8")
        return str(path)

    def _default_output_path(self) -> str:
        ext_map = {"yaml": "yaml", "json": "json", "md": "md"}
        ext = ext_map.get(self.format, "yaml")
        return f".verba/governance.{ext}"

    # ── Verification report ─────────────────────────────────────────────────

    def write_verification(self, verification: dict, output_path: str = None) -> str:
        """Write a `VerificationResult.to_dict()` as a verification report."""
        if not output_path:
            ext_map = {"yaml": "yaml", "json": "json", "md": "md"}
            ext = ext_map.get(self.format, "yaml")
            output_path = f".verba/governance-verification.{ext}"

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.format == "json":
            content = json.dumps(OutputFormatter._json_safe(verification), indent=2, default=str)
        elif self.format == "md":
            content = self._render_verification_markdown(verification)
        else:
            content = self._render_verification_yaml(verification)

        path.write_text(content, encoding="utf-8")
        return str(path)

    def _render_verification_yaml(self, verification: dict) -> str:
        lines = [
            "# ═══════════════════════════════════════════════════════════════",
            "# X-VERBA GOVERNANCE VERIFICATION",
            "# Current scan compared against the saved governance baseline.",
            "# ═══════════════════════════════════════════════════════════════",
            "",
        ]
        data = {
            "overall_status": verification.get("overall_status"),
            "passed": verification.get("passed"),
            "has_critical_regressions": verification.get("has_critical_regressions"),
            "deltas": [
                {
                    "metric": d.get("metric"),
                    "baseline_value": d.get("baseline_value"),
                    "current_value": d.get("current_value"),
                    "direction": d.get("direction"),
                    "severity": d.get("severity"),
                    "description": d.get("description"),
                }
                for d in verification.get("deltas", [])
            ],
        }
        lines.append(yaml.dump(data, default_flow_style=False, allow_unicode=True))
        return "\n".join(lines)

    def _render_verification_markdown(self, verification: dict) -> str:
        lines = [
            "# X-Verba Governance Verification",
            "",
            f"**Overall status:** {verification.get('overall_status', 'UNKNOWN')}  ",
            f"**Passed:** {verification.get('passed')}  ",
            f"**Critical regressions:** {verification.get('has_critical_regressions')}",
            "",
            "| Metric | Baseline | Current | Direction | Severity | Description |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for d in verification.get("deltas", []):
            lines.append(
                f"| {d.get('metric')} | {d.get('baseline_value')} | {d.get('current_value')} | "
                f"{d.get('direction')} | {d.get('severity')} | {d.get('description')} |"
            )
        lines.append("")
        return "\n".join(lines)

    # ── YAML renderer ─────────────────────────────────────────────────────────

    def _render_yaml(self) -> str:
        lines = []

        lines += [
            "# ═══════════════════════════════════════════════════════════════",
            "# X-VERBA GOVERNANCE CONTRACT",
            "# Generated by Super Semantics — supersemantics.org",
            "#",
            "# HOW TO USE THIS FILE",
            "#",
            "# This is your system's governance contract.",
            "# X-Verba scanned your code and found the decision points.",
            "# Your job is to fill in every field marked: null",
            "#",
            "# Each section has plain-English instructions.",
            "# Fill in plain English first — Verba Studio will help you",
            "# translate it into formal policy.",
            "#",
            "# Sections 10-12 are read-only reference material generated by",
            "# X-Verba's governance-intelligence analysis (v0.4.0). They are",
            "# not part of the contract you approve — use them to decide",
            "# what to prioritise in sections 4-8.",
            "#",
            "# Fields left null will be flagged by x-verba qa.",
            "# ═══════════════════════════════════════════════════════════════",
            "",
        ]

        # System Identity
        lines += self._section(
            "SECTION 1 — SYSTEM IDENTITY",
            "Scope all governance events to this system.",
            "Fill in these fields once. They propagate through the full lifecycle.",
        )
        meta = {
            "system_identity": {
                "identity_key": self.results.get("identity_key", ""),
                "system_name": None,
                "version": None,
                "domain": None,
                "governance_authority": None,
                "scan_date": self.results.get("scan_date", ""),
                "verba_version": self.results.get("verba_version", "0.7.0"),
                "context_profile": self.results.get("context_profile", "ai-app"),
                "framework_scope": "all" if self.results.get("all_frameworks") else "openai, langchain, langgraph (default)",
                "reviewed": False,
                "approved": False,
                "approved_by": None,
                "approved_date": None,
            }
        }
        lines.append(yaml.dump(meta, default_flow_style=False, allow_unicode=True))

        # Executive summary (read-only)
        summary = self.results.get("summary", {})
        lines += self._section(
            "SECTION 2 — SCAN SUMMARY",
            "What X-Verba found. Read-only — do not edit.",
        )
        lines.append(self._render_summary_yaml(summary))

        # Nodes
        primitives = self.results.get("primitives", {})
        lines += self._section(
            "SECTION 3 — GOVERNANCE NODES",
            "A Governance Node is a stabilised pattern of behaviour — a repeatable,",
            "consequential behavioural state that persists across the system's lifecycle.",
            "Nodes are inferred from observable implementation transitions such as",
            "AI calls, API calls, agent handovers, database commits, workflow",
            "transitions, and other consequential operations.",
            "",
            "X-Verba proposes candidate Governance Nodes by analysing observable",
            "implementation transitions and inferring the most likely resulting",
            "behavioural state. The 'candidate_node' field is that inference.",
            "Confirm or correct it.",
            "",
            "Agent handovers are also valid candidate Nodes — see Section 11.",
            "",
            "For each candidate Node, confirm or fill in:",
            "  - confirmed_node_name: the agreed governance name for this Node",
            "  - description: what consequential state it produces",
            "  - input_source: where the Node's input originates",
            "  - output_destination: where the Node's output goes",
            "  - criticality: low / medium / high / critical",
        )
        lines.append(self._render_nodes_yaml(primitives))

        # Pre-Nodes
        lines += self._section(
            "SECTION 4 — PRE-NODES",
            "A Pre-Node is the mandatory checkpoint that fires immediately before",
            "a Node executes. It is the last point where governance can stop",
            "the system before it commits.",
            "",
            "X-Verba detected these as MISSING where no checkpoint was found.",
            "For each one, define:",
            "  - What conditions must be TRUE for execution to proceed",
            "  - What conditions will BLOCK execution (and what happens next)",
            "  - What the fallback is if conditions are not met",
        )
        lines.append(self._render_pre_nodes_yaml(primitives, self.results.get("gaps", [])))

        # Invariants
        lines += self._section(
            "SECTION 5 — INVARIANTS",
            "An Invariant is a rule that must ALWAYS be true — across every state,",
            "every input, every transition. No exceptions. Cannot be bypassed.",
            "",
            "If violated, the system must stop and escalate to a human. Always.",
            "",
            "X-Verba detected these informal checks in your code as candidates.",
            "Formalise them here. Add any additional invariants you require.",
        )
        lines.append(self._render_invariants_yaml(primitives))

        # Thresholds
        lines += self._section(
            "SECTION 6 — THRESHOLDS",
            "A Threshold is a fixed quantitative limit your system cannot exceed.",
            "Exceeding a Threshold triggers a governance response.",
            "",
            "X-Verba detected these parameters from your AI calls.",
            "Set the permitted ranges. Define what happens when they are exceeded.",
        )
        lines.append(self._render_thresholds_yaml(primitives))

        # Human Authorisation Gates
        gaps = self.results.get("gaps", [])
        lines += self._section(
            "SECTION 7 — HUMAN AUTHORISATION GATES",
            "A Human Authorisation Gate is a point where automation must pause",
            "and a human must explicitly approve before the system continues.",
            "",
            "In VERBA: a Human-Authorised Transition cannot be initiated by automation.",
            "It requires explicit, auditable human approval.",
            "",
            "X-Verba detected these as MISSING — no human gate was found.",
        )
        lines.append(self._render_human_gates_yaml(gaps))

        # Terminal States
        lines += self._section(
            "SECTION 8 — TERMINAL STATES",
            "A Terminal State is a state from which no automated transition is permitted.",
            "Automation stops. A human must explicitly authorise the next step.",
            "Automation cannot exit a Terminal State. Ever.",
            "",
            "Define entry conditions for every critical gap below.",
        )
        lines.append(self._render_terminal_states_yaml(gaps))

        # DC Findings (diagnostic context, not the primary task)
        dc_findings = self.results.get("drift_classes", [])
        lines += self._section(
            "SECTION 9 — FAILURE MODE CANDIDATES",
            "Drift Classes are formally defined categories of failure mode.",
            "Think of them as diagnostic codes — like ICD codes for medical diagnosis.",
            "",
            "These are CANDIDATES — structural indicators detected in your code.",
            "Review and confirm each one. They inform the Invariants and Terminal States above.",
        )
        lines.append(self._render_dc_findings_yaml(dc_findings))

        # Legion matches (Pass 6 Tier 1/Tier 2 detection)
        legion_matches = self.results.get("legion_matches", [])
        if legion_matches is not None:
            lines += self._section(
                "SECTION 9b — DRIFT CLASS DETECTION (LEGION ANALYSIS)",
                "Legion matches from Pass 6 — structural Tier 1 (HIGH/MEDIUM) and",
                "keyword-based Tier 2 (SPECULATIVE) detection.",
                "",
                "Tier 1 HIGH/MEDIUM: directly confirmed from code structure.",
                "Tier 2 SPECULATIVE: keyword match only — manual review required.",
                "",
                "Each HIGH/MEDIUM finding includes a Stabilising Operator recommendation",
                "and a TEMPLATE ONLY governance contract stub (VSL compiler coming v0.6.0).",
            )
            lines.append(self._render_legion_matches_yaml(legion_matches or []))

        # QA recommendations from Legion matches (Section 9c)
        if legion_matches:
            lines += self._section(
                "SECTION 9c — QA TEST RECOMMENDATIONS",
                "Test stubs generated from Drift Class detection (Section 9b).",
                "",
                "HIGH/MEDIUM confidence → named test cases with approach notes.",
                "SPECULATIVE → manual review required before writing tests.",
                "",
                "Fill in the 'status' field as you implement each test:",
                "  status: pass | fail | skip",
            )
            lines.append(self._render_qa_recommendations_yaml(legion_matches))

        # ── v0.4.0 — additive reference sections (10-12) ────────────────────
        # Wrapped individually: a missing/older summary degrades to skipping
        # the section, never to a write failure.

        try:
            section_10 = self._render_governance_intelligence_yaml(summary)
        except Exception:
            section_10 = None
        if section_10:
            lines += self._section(
                "SECTION 10 — GOVERNANCE INTELLIGENCE (READ-ONLY REFERENCE)",
                "Aggregate governance-coverage, tendency, and Structural Gamma",
                "metrics computed by X-Verba across the whole scan.",
                "",
                "Read-only. Use this to prioritise sections 4-8 above.",
            )
            lines.append(section_10)

        try:
            section_11 = self._render_agent_governance_yaml(summary)
        except Exception:
            section_11 = None
        if section_11:
            lines += self._section(
                "SECTION 11 — AGENT GOVERNANCE (READ-ONLY REFERENCE)",
                "Inventory of agent-to-agent handovers, chains, and clusters",
                "detected in this codebase, and how many are governed.",
                "",
                "Read-only. Ungoverned handovers are strong candidates for",
                "new Pre-Nodes (section 4) and Human Authorisation Gates (section 7).",
            )
            lines.append(section_11)

        try:
            section_12 = self._render_critical_decisions_yaml(summary)
        except Exception:
            section_12 = None
        if section_12:
            lines += self._section(
                "SECTION 12 — CRITICAL DECISIONS (READ-ONLY REFERENCE)",
                "The decision points X-Verba considers most consequential —",
                "ranked by PageRank (influence on downstream decisions) and",
                "by criticality (blast radius x business impact x irreversibility).",
                "",
                "Read-only. Start with these when filling in sections 4-8.",
            )
            lines.append(section_12)

        # Gamma
        gamma = summary.get("gamma_variants", {}).get("overall", {})
        lines += self._section(
            "SECTION 13 — GOVERNANCE SCORE",
            "Structural Gamma = Governed Decision Points / Total Decision Points",
            "Target: >= 0.9. Below 0.5 = structurally ungoverned.",
            "Note: this is a structural proxy, not runtime Gamma.",
        )
        lines.append(self._render_gamma_yaml(gamma))

        # Next steps
        lines += self._section("SECTION 14 — NEXT STEPS")
        lines.append(self._render_next_steps_yaml(summary, gaps))

        return "\n".join(lines)

    def _section(self, title, *lines):
        """Emit a section header block."""
        out = [
            "# ───────────────────────────────────────────────────────────────",
            f"# {title}",
        ]
        for line in lines:
            out.append(f"# {line}" if line else "#")
        out.append("# ───────────────────────────────────────────────────────────────")
        out.append("")
        return out

    def _render_summary_yaml(self, summary: dict) -> str:
        ai_count = summary.get("ai_integrations_detected", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        files = summary.get("files_scanned", 0)
        gamma = summary.get("structural_gamma")
        status = summary.get("governance_status", "UNKNOWN")

        data = {
            "scan_summary": {
                "files_scanned": files,
                "ai_integrations_detected": ai_count,
                "findings": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "total": critical + high + medium,
                },
                "structural_gamma_proxy": gamma,
                "governance_status": status,
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_nodes_yaml(self, primitives: dict) -> str:
        ai_integrations = primitives.get("ai_integrations", [])
        nodes = []

        for ai in ai_integrations:
            node_id = ai["id"].replace("AI-", "NODE-")
            candidate_name, inference_confidence = _infer_candidate_node(ai)
            nodes.append({
                node_id: {
                    # Scanner inference — confirm or correct these
                    "candidate_node": candidate_name,
                    "inference_confidence": inference_confidence,
                    "implementation": ai["location"],
                    "trigger": ai.get("line_content", ""),
                    "provider": ai.get("provider", "unknown"),
                    "streaming": ai.get("streaming", False),
                    # Fields for developer to fill in
                    "confirmed_node_name": None,
                    "description": None,
                    "input_source": None,
                    "output_destination": ai.get("output_destination", None),
                    "criticality": None,
                    "notes": None,
                }
            })

        data = {"nodes": nodes if nodes else [{"note": "No candidate Nodes detected."}]}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_pre_nodes_yaml(self, primitives: dict, gaps: list) -> str:
        ai_integrations = primitives.get("ai_integrations", [])
        pre_nodes = []

        missing_locs = {
            g["ai_integration_ref"]
            for g in gaps
            if g.get("type") == "missing_pre_node" and g.get("ai_integration_ref")
        }

        # Build lookup: ai_id → gap with drift_exposure (for MISSING pre-nodes)
        gap_by_ai_ref = {
            g["ai_integration_ref"]: g
            for g in gaps
            if g.get("type") == "missing_pre_node" and g.get("ai_integration_ref")
        }

        for ai in ai_integrations:
            node_id = ai["id"].replace("AI-", "NODE-")
            status = "MISSING" if ai["id"] in missing_locs else "detected"
            gap = gap_by_ai_ref.get(ai["id"], {})
            drift = gap.get("drift_exposure")
            node_entry: dict = {
                "node_ref": node_id,
                "location": ai["location"],
                "status": status,
                "pre_node_detected_in_code": ai.get("pre_node_detected", False),
                "user_input_in_prompt": ai.get("user_input_in_prompt", False),
                "dynamic_prompt": ai.get("dynamic_prompt", False),
                # Fields for developer to fill in
                "conditions_that_must_be_true": None,
                "conditions_that_block_execution": None,
                "what_happens_on_block": None,
                "input_sanitisation_required": None,
                "prompt_boundary_defined": None,
                "governance_log_on_entry": True,
            }
            if drift and status == "MISSING":
                so = drift.get("stabilising_operator", {})
                warning = so.get("contraindication_warning")
                node_entry["drift_exposure"] = {
                    "dc_code": drift["dc_code"],
                    "dc_name": drift["dc_name"],
                    "dc_definition": drift["dc_definition"],
                    "tier": drift["tier"],
                    "legion": f"{drift['legion_code']}: {drift['legion_name']}",
                    "confidence": drift["confidence"],
                    "stabilising_operator": f"{so.get('code', '')} — {so.get('name', '')}",
                    "so_proposed_function": so.get("proposed_function", ""),
                    **({"contraindication_warning": warning} if warning else {}),
                    "fix_suggestion": drift["fix_suggestion"],
                    "vsl_template": drift["vsl_template"],
                }
            pre_nodes.append({f"PN-{node_id}": node_entry})

        data = {"pre_nodes": pre_nodes if pre_nodes else [{"note": "No nodes detected."}]}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_invariants_yaml(self, primitives: dict) -> str:
        constraints = primitives.get("constraints", [])
        invariants = []

        for i, c in enumerate(constraints, 1):
            invariants.append({
                f"INV-{i:03d}": {
                    "detected_from": c["location"],
                    "current_code": c["line_content"],
                    "constraint_type": c["type"],
                    "near_ai_call": c.get("near_ai_call", False),
                    "currently_enforced_in_code": True,
                    "currently_formalised": False,
                    # Fields for developer to fill in
                    "rule": None,
                    "scope": None,
                    "cannot_be_bypassed": True,
                    "violation_action": None,
                    "severity": None,
                    "audit_on_check": True,
                }
            })

        # Add blank template entries for additional invariants
        invariants.append({
            "INV-TEMPLATE": {
                "_comment": "Add your own invariants here. Copy this block.",
                "rule": None,
                "scope": None,
                "cannot_be_bypassed": True,
                "violation_action": None,
                "severity": None,
                "audit_on_check": True,
            }
        })

        data = {"invariants": invariants}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_thresholds_yaml(self, primitives: dict) -> str:
        ai_integrations = primitives.get("ai_integrations", [])
        thresholds = []

        for i, ai in enumerate(ai_integrations, 1):
            temp = ai.get("temperature")
            max_tokens = ai.get("max_tokens")

            if temp is not None or max_tokens is not None:
                thresholds.append({
                    f"TH-{i:03d}": {
                        "node_ref": ai["id"],
                        "location": ai["location"],
                        "detected_parameters": {
                            "temperature": {
                                "current_value": temp,
                                "risk": (
                                    f"HIGH — temperature {temp} increases output variability. "
                                    "Governance cost scales with temperature."
                                ) if temp and temp > 0.7 else (
                                    f"Within acceptable range ({temp})"
                                ) if temp is not None else "Not detected",
                            },
                            "max_tokens": {
                                "current_value": max_tokens,
                                "risk": (
                                    "Unbounded output length — no explicit limit detected."
                                ) if not max_tokens else f"Limited to {max_tokens} tokens",
                            },
                        },
                        # Fields for developer to fill in
                        "maximum_temperature_permitted": None,
                        "maximum_output_tokens": None,
                        "minimum_confidence_score": None,
                        "forbidden_content_patterns": None,
                        "on_threshold_breach": None,
                    }
                })

        thresholds.append({
            "TH-TEMPLATE": {
                "_comment": "Add quantitative thresholds here. Copy this block.",
                "parameter": None,
                "maximum_permitted": None,
                "minimum_permitted": None,
                "on_breach": None,
            }
        })

        data = {"thresholds": thresholds}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_human_gates_yaml(self, gaps: list) -> str:
        hg_gaps = [g for g in gaps if g.get("type") == "missing_human_gate"]
        gates = []

        for gap in hg_gaps:
            gates.append({
                gap["id"]: {
                    "location": gap["location"],
                    "ai_integration_ref": gap.get("ai_integration_ref", ""),
                    "status": "MISSING",
                    "output_flows_to": gap.get("plain_english", ""),
                    # Fields for developer to fill in
                    "trigger_condition": None,
                    "authorisation_level": None,
                    "what_human_must_review": None,
                    "what_human_must_approve": None,
                    "timeout_seconds": None,
                    "on_timeout": None,
                    "audit_trail_required": True,
                }
            })

        gates.append({
            "HG-TEMPLATE": {
                "_comment": "Add human authorisation gates here. Copy this block.",
                "trigger_condition": None,
                "authorisation_level": None,
                "what_human_must_approve": None,
                "timeout_seconds": None,
                "on_timeout": None,
                "audit_trail_required": True,
            }
        })

        data = {"human_authorisation_gates": gates}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_terminal_states_yaml(self, gaps: list) -> str:
        critical_gaps = [g for g in gaps if g.get("severity") == "critical"]
        ts_entries = []

        for i, gap in enumerate(critical_gaps, 1):
            ts_entry: dict = {
                "triggered_by_gap": gap["id"],
                "location": gap["location"],
                "reason": gap["plain_english"],
                "automated_transitions": "NONE — by definition",
                "human_authorised_exit_required": True,
                "re_enablement_creates_new_instance": True,
                # Fields for developer to fill in
                "entry_conditions": None,
                "governance_authority": None,
                "escalation_path": None,
                "response_time_sla": None,
                "notification_targets": None,
            }
            drift = gap.get("drift_exposure")
            if drift:
                so = drift.get("stabilising_operator", {})
                warning = so.get("contraindication_warning")
                ts_entry["drift_exposure"] = {
                    "dc_code": drift["dc_code"],
                    "dc_name": drift["dc_name"],
                    "confidence": drift["confidence"],
                    "legion": f"{drift['legion_code']}: {drift['legion_name']}",
                    "stabilising_operator": f"{so.get('code', '')} — {so.get('name', '')}",
                    **({"contraindication_warning": warning} if warning else {}),
                    "fix_suggestion": drift["fix_suggestion"],
                }
            ts_entries.append({f"TS-{i:03d}": ts_entry})

        ts_entries.append({
            "TS-TEMPLATE": {
                "_comment": "Add terminal states here. Copy this block.",
                "entry_conditions": None,
                "automated_transitions": "NONE",
                "governance_authority": None,
                "escalation_path": None,
                "response_time_sla": None,
            }
        })

        data = {"terminal_states": ts_entries}
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_dc_findings_yaml(self, dc_findings: list) -> str:
        finding_data = []
        aggregate_i11 = None

        for i, finding in enumerate(dc_findings, 1):
            # R1 + R5: DC-I11 aggregate rendered as a structural/informational block
            if finding.get("aggregate") and finding.get("dc_code") == "DC-I11":
                aggregate_i11 = finding
                continue

            contraindications = finding.get(
                "stabiliser_recommendation", {}
            ).get("contraindications", [])

            finding_data.append({
                f"DC-FINDING-{i:03d}": {
                    "code": finding["dc_code"],
                    "name": finding["dc_name"],
                    "tier": finding["tier"],
                    "location": finding["location"],
                    "severity": finding["severity"],
                    "plain_english": finding["plain_english"],
                    "what_happens_without_governance": finding.get(
                        "what_happens_without_governance", ""
                    ),
                    "evidence_detected": finding["evidence"],
                    "legion_detected": {
                        "code": finding["legion_detected"]["code"],
                        "name": finding["legion_detected"]["name"],
                    },
                    "stabiliser_recommendation": {
                        "operator": finding["stabiliser_recommendation"]["primary_so"],
                        "name": finding["stabiliser_recommendation"]["so_name"],
                        "contraindications": [
                            {
                                k: v for k, v in {
                                    "do_not_apply": c.get("do_not_apply", ""),
                                    "reason": c.get("reason", ""),
                                    "predicted_failure_state": c.get("predicted_failure_state"),
                                }.items() if v
                            }
                            for c in contraindications
                        ] if contraindications else "None",
                    },
                    "monitoring_frequency": finding["monitoring_frequency"],
                    # Fields for developer to fill in
                    "confirmed": None,
                    "invariant_ref": None,
                    "terminal_state_ref": None,
                }
            })

        if aggregate_i11:
            count = aggregate_i11.get("aggregate_count", 0)
            locs = aggregate_i11.get("aggregate_locations", [])
            finding_data.append({
                "DC-I11-AGGREGATE": {
                    "severity": "informational",
                    "note": (
                        "DC-I11 is a systemic property — one aggregate replaces "
                        f"{count} per-call-site findings."
                    ),
                    "code": "DC-I11",
                    "name": aggregate_i11.get("dc_name", "Evaluative Decoupling"),
                    "total_instances": count,
                    "representative_locations": locs[:10],
                    "recommendation": (
                        "Implement a governance checkpoint layer at your API entry "
                        "points rather than per-call-site."
                    ),
                    # Fields for developer to fill in
                    "confirmed": None,
                    "governance_layer_location": None,
                }
            })

        data = {
            "drift_class_candidates": finding_data if finding_data
            else [{"note": "No Drift Class candidates detected."}]
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    # ── v0.4.0 reference renderers ───────────────────────────────────────────

    def _render_governance_intelligence_yaml(self, summary: dict) -> str | None:
        """
        Section 10. Reads the pre-aggregated v0.4.0 metrics that
        ScanEngine._build_v0_4_0_summary() already folds into
        results["summary"]: "coverage", "tendency", "gamma_variants".

        Returns None if these keys are absent (results from an engine
        older than v0.4.0) so the caller can skip the section entirely.
        """
        coverage = summary.get("coverage")
        tendency = summary.get("tendency")
        gamma_variants = summary.get("gamma_variants")

        if not (coverage and tendency and gamma_variants):
            return None

        overall_gamma = gamma_variants.get("overall", {})
        critical_gamma = gamma_variants.get("critical", {})
        handover_gamma = gamma_variants.get("agent_handover", {})

        data = {
            "governance_intelligence": {
                "overall_governance_coverage_percent": coverage.get("overall"),
                "coverage_by_decision_type": coverage.get("by_decision_type", {}),
                "coverage_by_consequence_type": coverage.get("by_consequence_type", {}),
                "critical_decision_coverage_percent": coverage.get("critical"),
                "tendency_state": tendency.get("state"),
                "tendency_score": tendency.get("score"),
                "t_amplification_active": tendency.get("t_amplification_active"),
                "pre_node_proximity": tendency.get("pre_node_proximity"),
                "structural_gamma_overall": overall_gamma.get("value"),
                "gamma_critical": critical_gamma.get("value"),
                "gamma_agent_handover": handover_gamma.get("value"),
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_agent_governance_yaml(self, summary: dict) -> str | None:
        """
        Section 11. Reads results["summary"]["agent_inventory"], populated
        from inventories.agent (Pass 12) by ScanEngine._build_v0_4_0_summary().

        Returns None if "agent_inventory" is absent.
        """
        agent_inventory = summary.get("agent_inventory")
        if not agent_inventory:
            return None

        data = {
            "agent_governance": {
                "total_agents": agent_inventory.get("total_agents", 0),
                "total_handovers": agent_inventory.get("handovers", 0),
                "governed_handovers": agent_inventory.get("governed_handovers", 0),
                "ungoverned_handovers": agent_inventory.get("ungoverned_handovers", 0),
                "total_chains": agent_inventory.get("chains", 0),
                "fully_governed_chains": agent_inventory.get("fully_governed_chains", 0),
                "partially_governed_chains": agent_inventory.get("partially_governed_chains", 0),
                "ungoverned_chains": agent_inventory.get("ungoverned_chains", 0),
                "total_clusters": agent_inventory.get("clusters", 0),
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_critical_decisions_yaml(self, summary: dict) -> str | None:
        """
        Section 12. Reads results["summary"]["decision_inventory"] and
        results["summary"]["top_decisions"] (PageRank ranking, Pass 16),
        cross-referenced against results["graphs"]["decision_graph"] (Pass 11)
        for per-decision criticality/governed status when available.

        Returns None if "decision_inventory" is absent.
        """
        decision_inventory = summary.get("decision_inventory")
        gamma_variants = summary.get("gamma_variants")
        if not decision_inventory:
            return None

        total_critical = decision_inventory.get("critical", 0)

        critical_ungoverned = 0
        if gamma_variants:
            critical_gamma = gamma_variants.get("critical", {})
            critical_ungoverned = max(
                0, critical_gamma.get("total", 0) - critical_gamma.get("governed", 0)
            )

        decision_graph = self.results.get("graphs", {}).get("decision_graph")
        graph_nodes = getattr(decision_graph, "nodes", {}) if decision_graph else {}

        top_decisions = summary.get("top_decisions", {})
        most_influential = []
        for location, score in top_decisions.get("most_influential", []):
            entry = {"location": location, "pagerank": score}
            node = graph_nodes.get(location)
            if node is not None:
                entry["criticality"] = node.criticality
                entry["governed"] = node.governed
            most_influential.append(entry)

        data = {
            "critical_decisions": {
                "total_critical": total_critical,
                "critical_ungoverned": critical_ungoverned,
                "most_influential": most_influential if most_influential
                else "None ranked (PageRank produced no results).",
                "critical_path": top_decisions.get("critical_path", []),
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_gamma_yaml(self, gamma: dict) -> str:
        value = gamma.get("value")
        status = gamma.get("status", "UNKNOWN")
        data = {
            "structural_gamma": {
                "value": value,
                "threshold": GAMMA_ABOVE_THRESHOLD,
                "status": status,
                "interpretation": _gamma_interpretation(status, value),
                "governed_decision_points": gamma.get("governed", 0),
                "total_decision_points": gamma.get("total", 0),
                "note": GAMMA_PROXY_NOTE,
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def _render_next_steps_yaml(self, summary: dict, gaps: list) -> str:
        critical = summary.get("critical", 0)
        steps = {
            "next_steps": [
                {
                    "step_1": {
                        "action": "Fill in every null field in this file",
                        "start_with": "Section 4 (Pre-Nodes) and Section 8 (Terminal States)",
                        "critical_count": critical,
                    }
                },
                {
                    "step_2": {
                        "action": "Complete the test stubs in test_case_matrix.yaml",
                        "why": "Every governance rule needs a test. No test = unverifiable governance.",
                    }
                },
                {
                    "step_3": {
                        "action": "Open in Verba Studio for AI-assisted authoring",
                        "url": "https://studio.supersemantics.org",
                    }
                },
                {
                    "step_4": {
                        "action": "Add x-verba qa to your CI/CD pipeline",
                        "command": "x-verba qa . --schema .verba/governance.yaml",
                        "note": "Coming in v0.2. Returns exit code 1 if critical regressions found.",
                    }
                },
                {
                    "step_5": {
                        "action": "Compile and deploy with VERBA Runtime",
                        "command": "x-verba compile .verba/governance.yaml",
                        "note": "Coming in v0.2.",
                    }
                },
            ]
        }
        return yaml.dump(steps, default_flow_style=False, allow_unicode=True)

    # ── Legion matches renderer (Section 9b) ─────────────────────────────────

    def _render_governance_contract_snippet(
        self, dc_code: str, so_code: str, so_data: dict
    ) -> str:
        """Return a VSL governance contract template for a DC/SO pair.

        Labeled TEMPLATE ONLY — the VSL compiler is not yet implemented.
        """
        so_name = so_data.get("name", so_code)
        description = so_data.get("description", "")
        snippet = {
            "vsl_template": {
                "note": "TEMPLATE ONLY — requires VSL compiler (coming v0.6.0)",
                "drift_class": dc_code,
                "stabilising_operator": so_code,
                "operator_name": so_name,
                "operator_description": description,
                "governance_contract": {
                    "pre_node": f"# TODO: implement {so_code} checkpoint before AI call",
                    "invariant": f"# TODO: define invariant that {so_name} must satisfy",
                    "terminal_state": f"# TODO: define terminal state if {so_code} check fails",
                    "human_gate": "# TODO: specify human authorisation gate if required",
                },
            }
        }
        return yaml.dump(snippet, default_flow_style=False, allow_unicode=True)

    def _render_legion_matches_yaml(self, legion_matches: list) -> str:
        """Render Legion match findings as YAML (Section 9b).

        Tier 1 (HIGH/MEDIUM) findings first, Tier 2 (SPECULATIVE) second.
        Each Tier 1 match includes an SO recommendation and a VSL template stub.
        """
        if not legion_matches:
            return yaml.dump(
                {"legion_matches": [{"note": "No Legion matches detected."}]},
                default_flow_style=False, allow_unicode=True,
            )

        tier1 = [m for m in legion_matches if m.get("confidence") in ("HIGH", "MEDIUM")]
        tier2 = [m for m in legion_matches if m.get("confidence") == "SPECULATIVE"]

        findings: list = []

        for i, m in enumerate(tier1, 1):
            dc_code = m.get("dc_code", "")
            so_recs = m.get("so_recommendations", [])
            primary_so = so_recs[0] if so_recs else {}
            so_code = primary_so.get("so_code", "")
            entry: dict = {
                f"LEGION-T1-{i:03d}": {
                    "confidence": m.get("confidence"),
                    "dc_code": dc_code,
                    "dc_name": m.get("dc_name", ""),
                    "legion_code": m.get("legion_code", ""),
                    "legion_name": m.get("legion_name", ""),
                    "location": m.get("location", ""),
                    "evidence": m.get("evidence", ""),
                    "plain_english": m.get("plain_english", ""),
                    "stabilising_operator": {
                        "code": so_code,
                        "name": primary_so.get("so_name", ""),
                        "rationale": primary_so.get("rationale", ""),
                    } if primary_so else "None",
                    "contraindications": m.get("contraindications", []) or "None",
                    "vsl_template": (
                        f"See governance_contract_template.{dc_code.lower().replace('-', '_')}"
                        if so_code else "None"
                    ),
                }
            }
            findings.append(entry)

        for i, m in enumerate(tier2, 1):
            entry = {
                f"LEGION-T2-{i:03d}": {
                    "confidence": "SPECULATIVE",
                    "note": "manual review recommended — keyword match only",
                    "dc_code": m.get("dc_code", ""),
                    "dc_name": m.get("dc_name", ""),
                    "legion_code": m.get("legion_code", ""),
                    "legion_name": m.get("legion_name", ""),
                    "location": m.get("location", ""),
                    "matched_pattern": m.get("matched_pattern", ""),
                    "evidence": m.get("evidence", ""),
                }
            }
            findings.append(entry)

        data = {
            "legion_matches": {
                "tier1_count": len(tier1),
                "tier2_count": len(tier2),
                "findings": findings,
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    # ── QA recommendations renderer (Section 9c) ─────────────────────────────

    @staticmethod
    def _load_dc_reference_data() -> tuple[dict, dict, dict]:
        """Load DC definitions, SO definitions, and Legion descriptions from JSON files.

        Returns (dc_entries, so_entries, legion_descriptions) — all dicts, all empty
        on any load failure so the caller degrades gracefully.

        dc_entries:  { "DC-E13": { "operational_definition": ..., "primary_so": "SO-4", ... } }
        so_entries:  { "SO-4": { "name": ..., "proposed_function": ... } }
        legion_descriptions: { "DC-E13": { "L1": "...", "L3": "..." } }
        """
        base = Path(__file__).parent
        dc_entries: dict = {}
        so_entries: dict = {}
        legion_descriptions: dict = {}

        try:
            raw = json.loads((base / "dc_classes_complete.json").read_text(encoding="utf-8"))
            for section_val in raw.get("drift_classes", {}).values():
                if isinstance(section_val, dict):
                    for code, entry in section_val.items():
                        if isinstance(entry, dict):
                            dc_entries[code] = entry
            for so_code, so_entry in raw.get("stabilisation_operators", {}).items():
                if isinstance(so_entry, dict):
                    so_entries[so_code] = so_entry
        except Exception:
            pass

        try:
            raw_legions = json.loads(
                (base / "LEGION_DETECTION_PATTERNS.json").read_text(encoding="utf-8")
            )
            for dc_code, dc_block in raw_legions.items():
                if not isinstance(dc_block, dict):
                    continue
                legion_descriptions[dc_code] = {}
                for legion_code, legion_block in dc_block.get("legions", {}).items():
                    heuristics = legion_block.get("heuristics", [])
                    desc = heuristics[0].get("description", "") if heuristics else ""
                    legion_descriptions[dc_code][legion_code] = desc
        except Exception:
            pass

        return dc_entries, so_entries, legion_descriptions

    def _render_qa_recommendations_yaml(self, legion_matches: list) -> str:
        """Render QA test recommendations derived from Legion matches (Section 9c).

        Each entry includes inline definitions for the DC, its primary SO, and the
        matched Legion so developers learn the taxonomy while reading the test stubs.

        HIGH/MEDIUM confidence → named test stubs with approach notes.
        SPECULATIVE → manual-review note, no test stubs.
        """
        recs = _dc_qa_recommendations(legion_matches)

        if not recs:
            return yaml.dump(
                {"qa_test_recommendations": [{"note": "No QA recommendations generated."}]},
                default_flow_style=False, allow_unicode=True,
            )

        dc_entries, so_entries, legion_descriptions = self._load_dc_reference_data()

        def _dc_block(dc_code: str) -> dict:
            entry = dc_entries.get(dc_code, {})
            so_raw = entry.get("primary_so", "")
            # primary_so may be "SO-5, SO-7" — take the first code only
            primary_so_code = so_raw.split(",")[0].strip() if so_raw else ""
            so_entry = so_entries.get(primary_so_code, {})
            return {
                "definition": entry.get(
                    "operational_definition", "See dc_classes_complete.json"
                ),
                "tier": entry.get("tier", ""),
                "category": entry.get("category", ""),
                "stabilising_operator": {
                    "code": primary_so_code,
                    "name": so_entry.get("name", ""),
                    "proposed_function": so_entry.get("proposed_function", ""),
                    "contraindicated_on": so_entry.get("contraindicated_on") or [],
                } if primary_so_code else "None",
            }

        def _legion_description(dc_code: str, legion_code: str) -> str:
            return legion_descriptions.get(dc_code, {}).get(legion_code, "")

        high_medium = [r for r in recs if r.get("confidence") in ("HIGH", "MEDIUM")]
        speculative = [r for r in recs if r.get("confidence") == "SPECULATIVE"]
        entries = []

        for r in high_medium:
            dc_code = r["dc_code"]
            # legion_code is the short key e.g. "L3" — extract from legion match
            match = next(
                (m for m in legion_matches if m.get("dc_code") == dc_code
                 and m.get("confidence") in ("HIGH", "MEDIUM")),
                {}
            )
            legion_code = match.get("legion_code", "")
            test_stubs = [
                {
                    "test": t["test"],
                    "description": t["description"],
                    "approach": t["approach"],
                    "status": None,  # fill in: pass | fail | skip
                }
                for t in r.get("tests", [])
            ]
            entries.append({
                "dc_code": dc_code,
                "dc": _dc_block(dc_code),
                "legion": {
                    "code": legion_code,
                    "name": r["legion"],
                    "description": _legion_description(dc_code, legion_code),
                },
                "location": r["location"],
                "confidence": r["confidence"],
                "tests": test_stubs,
            })

        for r in speculative:
            dc_code = r["dc_code"]
            match = next(
                (m for m in legion_matches if m.get("dc_code") == dc_code
                 and m.get("confidence") == "SPECULATIVE"),
                {}
            )
            legion_code = match.get("legion_code", "")
            entries.append({
                "dc_code": dc_code,
                "dc": _dc_block(dc_code),
                "legion": {
                    "code": legion_code,
                    "name": r["legion"],
                    "description": _legion_description(dc_code, legion_code),
                },
                "location": r["location"],
                "confidence": "SPECULATIVE",
                "note": r["note"],
                "tests": [],
            })

        data = {
            "qa_test_recommendations": {
                "high_medium_count": len(high_medium),
                "speculative_count": len(speculative),
                "recommendations": entries,
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    # ── JSON renderer ─────────────────────────────────────────────────────────

    def _render_json(self) -> str:
        return json.dumps(OutputFormatter._json_safe(self.results), indent=2, default=str)

    # ── Markdown renderer ─────────────────────────────────────────────────────

    def _render_markdown(self) -> str:
        lines = []
        summary = self.results.get("summary", {})
        gaps = self.results.get("gaps", [])
        dc_findings = self.results.get("drift_classes", [])
        gamma = summary.get("gamma_variants", {}).get("overall", {})

        lines.append("# X-Verba Governance Report")
        lines.append(
            f"*Generated {self.results.get('scan_date', '')} by Super Semantics*"
        )
        lines.append("")
        lines.append(
            f"**Repository:** `{self.results.get('repo', '')}`  "
        )
        lines.append(
            f"**Identity Key:** `{self.results.get('identity_key', '')}`  "
        )
        lines.append(
            f"**Context Profile:** `{self.results.get('context_profile', 'ai-app')}`"
        )
        framework_scope = "all" if self.results.get("all_frameworks") else "openai, langchain, langgraph (default)"
        lines.append(
            f"**Framework Scope:** `{framework_scope}`"
        )
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## What we found")
        lines.append("")

        ai_count = summary.get("ai_integrations_detected", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        coverage = summary.get("governance_coverage", "N/A")
        gamma_val = summary.get("structural_gamma")
        files = summary.get("files_scanned", 0)

        lines.append(
            f"X-Verba scanned **{files} files** and found "
            f"**{ai_count} AI integration points**."
        )
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Critical findings | **{critical}** |")
        lines.append(f"| High findings | {high} |")
        lines.append(f"| Governance coverage | {coverage} |")
        gamma_display = str(gamma_val) if gamma_val is not None else "N/A"
        lines.append(
            f"| Structural Gamma proxy | {gamma_display} "
            f"({'below threshold' if gamma_val is not None and gamma_val < 0.9 else 'N/A' if gamma_val is None else 'at threshold'}) |"
        )
        lines.append("")

        # v0.4.0 — governance intelligence, if present
        tendency = summary.get("tendency")
        if tendency:
            lines.append(f"| Tendency state | {tendency.get('state', 'N/A')} |")
            lines.append("")

        if critical > 0 or high > 0:
            lines.append("---")
            lines.append("")
            lines.append("## Governance gaps")
            lines.append("")
            for gap in gaps:
                if gap.get("severity") in ["critical", "high"]:
                    label = (
                        "CRITICAL" if gap["severity"] == "critical"
                        else "HIGH"
                    )
                    lines.append(f"### {label} — `{gap['location']}`")
                    lines.append("")
                    lines.append(gap["plain_english"])
                    lines.append("")
                    lines.append(f"**What is missing:** {gap['what_is_missing']}")
                    lines.append("")
                    lines.append(
                        f"**Consequence if not addressed:** {gap['consequence']}"
                    )
                    lines.append("")
                    lines.append(f"*VERBA term: {gap['verba_term']}*")
                    lines.append("")

        if dc_findings:
            lines.append("---")
            lines.append("")
            lines.append("## Failure mode candidates")
            lines.append("")
            for finding in dc_findings:
                # R1 + R5: aggregate DC-I11 gets its own concise block
                if finding.get("aggregate") and finding.get("dc_code") == "DC-I11":
                    count = finding.get("aggregate_count", 0)
                    locs = finding.get("aggregate_locations", [])
                    lines.append(
                        f"### DC-I11 {finding.get('dc_name', 'Evaluative Decoupling')} "
                        f"(Tier {finding.get('tier', '')}) — informational"
                    )
                    lines.append("")
                    lines.append(
                        f"**{count} AI call {'site' if count == 1 else 'sites'} "
                        f"without a governance checkpoint** (scan-level aggregate)"
                    )
                    lines.append("")
                    lines.append(finding.get("plain_english", ""))
                    lines.append("")
                    lines.append(
                        "**Recommendation:** Implement a governance checkpoint layer "
                        "at your API entry points rather than per-call-site."
                    )
                    if locs:
                        lines.append("")
                        lines.append("**Representative locations:**")
                        for loc in locs[:10]:
                            lines.append(f"- `{loc}`")
                    lines.append("")
                    continue

                lines.append(
                    f"### {finding['dc_code']} {finding['dc_name']} "
                    f"(Tier {finding['tier']})"
                )
                lines.append("")
                lines.append(f"**Location:** `{finding['location']}`")
                lines.append("")
                lines.append(finding["plain_english"])
                lines.append("")
                so = finding.get("stabiliser_recommendation", {})
                lines.append(
                    f"**Recommended operator:** "
                    f"{so.get('primary_so', '')} {so.get('so_name', '')}"
                )
                lines.append("")

        legion_matches = self.results.get("legion_matches") or []
        if legion_matches:
            tier1 = [m for m in legion_matches if m.get("confidence") in ("HIGH", "MEDIUM")]
            tier2 = [m for m in legion_matches if m.get("confidence") == "SPECULATIVE"]
            lines.append("---")
            lines.append("")
            lines.append("## Drift Class Detection (Legion Analysis)")
            lines.append("")
            lines.append(
                f"**{len(tier1)} Tier 1** (HIGH/MEDIUM) · "
                f"**{len(tier2)} Tier 2** (SPECULATIVE)"
            )
            lines.append("")
            for m in tier1:
                so_recs = m.get("so_recommendations", [])
                so = so_recs[0] if so_recs else {}
                lines.append(
                    f"### [{m.get('confidence')}] {m.get('dc_code', '')} — "
                    f"{m.get('legion_name', m.get('legion_code', ''))}"
                )
                lines.append("")
                lines.append(f"**Location:** `{m.get('location', '')}`")
                lines.append("")
                lines.append(m.get("plain_english", ""))
                lines.append("")
                if so:
                    lines.append(
                        f"**Stabilising Operator:** {so.get('so_code', '')} "
                        f"{so.get('so_name', '')}"
                    )
                    lines.append("")
            if tier2:
                lines.append("### SPECULATIVE matches (manual review required)")
                lines.append("")
                for m in tier2:
                    lines.append(
                        f"- `{m.get('dc_code', '')}` {m.get('legion_name', '')} "
                        f"at `{m.get('location', '')}` — "
                        f"matched: `{m.get('matched_pattern', '')}`"
                    )
                lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("## Governance score")
        lines.append("")
        gamma_value = gamma.get("value")
        gamma_status = gamma.get("status", "UNKNOWN")
        gamma_str = f"{gamma_value:.2f}" if gamma_value is not None else "N/A"
        lines.append(f"**Structural Gamma:** {gamma_str} [{gamma_status}]")
        lines.append("")
        lines.append(_gamma_interpretation(gamma_status, gamma_value))
        lines.append("")
        lines.append(f"> {GAMMA_PROXY_NOTE}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Next steps")
        lines.append("")
        lines.append("1. Fill in the null fields in `.verba/governance.yaml`")
        lines.append("2. Complete the test stubs in `.verba/test_case_matrix.yaml`")
        lines.append("3. Open in Verba Studio for AI-assisted policy authoring")
        lines.append(
            "4. Add `x-verba qa . --schema .verba/governance.yaml` "
            "to your CI/CD pipeline (coming v0.2)"
        )
        lines.append("")
        lines.append(
            "*Generated by X-Verba — https://github.com/4vish/x-verba*"
        )

        return "\n".join(lines)


