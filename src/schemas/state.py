"""TEL-C2-045 — Agent state (Telecom Network Firmware Change-Window Risk Brief, Cat 2).

ADR-005: State is a flat TypedDict — never a validation/BaseModel instance. Complex fields are stored
as JSON strings (``NotRequired[str]`` + ``# JSON:``); nodes ``json.dumps`` on write / ``json.loads`` on read.

Advisory / read-only: the agent produces an *ex-ante* Change-Window Risk Brief. It never schedules,
deploys, sends a device command, or auto-rolls-back a change. Any credential / My-Number / phone / email
that a change package may inadvertently carry is deterministically redacted from every supplied string
leaf before it persists (S-1 input hygiene) and again before it surfaces (S-3 output); personal names are
best-effort (label-anchored — no NER/LLM). The final GO/NO-GO and owner assignment stay with an
authorized human via HumanGate — the agent only proposes candidate owners.

All agent-specific fields are NotRequired (populated progressively; absent at empty-start invoke).
"""

from __future__ import annotations


from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Agent state for the firmware change-window risk-brief workflow."""

    # ── pre_process (ChangePackageValidate — S-1 normalize + validated request) ──
    validated_input: str  # JSON: {change_id, change_plan, assets[], window, rollback_plan, customer_impact_criteria}
    input_format: str  # "json" | "text" | "empty"
    enriched_context: str  # JSON: {source, channel} (read-only caller context)

    # ── inner workflow (classify → risk_evaluate → brief_synthesis → human_gate) ──
    classified_assets: str  # JSON: [{asset_id, asset_type, criticality_tier, dependencies[], source}]
    ingest_count: int  # assets classified (0 → out-of-scope safe brief)
    window_assessment: str  # JSON: {window, within_low_traffic, adequate_for_rollback, note}
    risk_findings: str  # JSON: [{dimension, severity, detail, citation}]
    change_brief: str  # JSON: synthesized brief body (draft, pre-HumanGate)
    review_decision: str  # JSON: {requires_cab_review, exceptions[], candidate_owners[]}
    result: str  # JSON: assembled Change-Window Risk Brief report

    # ── post_process (BriefCompose — S-3 gate + S-4 audit) ────────────────────
    formatted_output: str  # JSON: final response envelope (brief + DRAFT disclaimer)
    disclaimer: str  # mandatory "DRAFT / not a CAB ruling" advisory disclaimer
    audit_logged: bool  # True once the terminal audit event is emitted

    # ── degraded-path signalling (SUCCESS + error_code, never status=ERROR) ──
    error_code: str  # INJECTION_REJECTED | INPUT_TOO_LONG | INPUT_REJECTED | NO_ASSETS
    error_message: str  # operator-facing detail
