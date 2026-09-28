"""TEL-C2-045 — post_process node: BriefCompose (S-3 output gate + S-4 audit).

Formats the terminal Change-Window Risk Brief into the response envelope. **S-3 output boundary:**
``execute()`` scrubs the whole report (redacts credential / My-Number sequences + neutralizes any
prompt-injection markers echoed from the change package), **enforces (fail-closed)** citation
completeness — a grounded risk brief whose findings are not cited to their rubric / asset sources is
never presented; it degrades to a safe ``needs_review`` answer with the brief body withheld
(``error_code=CITATION_INCOMPLETE``, still SUCCESS so post / S-4 / disclaimer run) — and appends the
mandatory DRAFT advisory disclaimer. ``_extra_security_gate_output()`` enforces disclaimer preservation
and may raise. S-4: emit a terminal audit event (status kind / counts only — never raw change content).
Runs on the full brief, the citation-blocked branch, and the out-of-scope safe branch.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import Redactor
from src.utils.audit import emit_trace_event

_DISCLAIMER = (
    "本ブリーフは実施前（ex-ante）の参考用 DRAFT であり、CAB の裁定ではありません。変更の GO/NO-GO・最終承認・"
    "accountability は認可された人間（CAB / 変更マネージャー）の判断です。本エージェントは助言専用で、変更の"
    "スケジュール・実施・機器へのコマンド送信・自動 rollback を一切行いません。owner は候補提示のみで、確定は"
    "HumanGate（認可済み人手）が行います。"
)

_CITATION_INCOMPLETE_MSG = (
    "リスクブリーフの一部に検証可能な出典（rubric / asset の根拠）が確認できなかったため、"
    "根拠不十分なブリーフの提示を差し控えました。対象資産・rubric 根拠が揃った承認済み変更パッケージで"
    "再実行してください。"
)
_NEEDS_REVIEW_NOTE = (
    "Grounding could not be verified for the risk brief; the draft is withheld pending valid rubric / "
    "asset citations and authorized human (CAB) review."
)


class PostProcessNode(FunctionNode):
    """Scrub + verify citations + append DRAFT disclaimer + emit audit."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 preservation check: the mandatory DRAFT disclaimer must be present in the envelope.

        SDK 1.0.0 contract: receives the **result dict from `execute()`**; returns the (possibly
        filtered) result. MAY raise to block an output missing the mandatory disclaimer.
        """
        out = result.get("formatted_output", "")
        if out and ("DRAFT" not in out or "助言" not in out):
            raise ValueError("S-3: mandatory DRAFT advisory disclaimer missing from output")
        return dict(result)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        report: dict[str, Any] = json.loads(state.get("result", "{}") or "{}")
        # S-3 output boundary — redact secrets / neutralize injection across the whole report.
        report = Redactor.scrub(report)

        citations = report.get("citations", [])
        grounded = report.get("status_kind") == "risk_brief"
        risk_findings = report.get("risk_findings", [])
        # S-3 per-entry authoritative correspondence: every presented risk finding must carry BOTH its own
        # local rubric citation AND an exact top-level {dimension, source} citation for the same dimension —
        # not merely a non-empty citation list. A partially ungrounded finding (missing its local citation),
        # or a top-level citation belonging to a DIFFERENT dimension, must fail closed. (Assets are grounded
        # by construction: AssetImpactKB always assigns a tier source; findings are the per-entry unit whose
        # grounding a caller/rubric gap can drop.)
        cited_sources = {
            c.get("dimension"): c.get("source") for c in citations if c.get("dimension") and c.get("source")
        }
        citation_complete = (not grounded) or (
            bool(risk_findings)
            and all(f.get("citation") for f in risk_findings)
            and all(cited_sources.get(f.get("dimension")) == f.get("citation") for f in risk_findings)
        )

        # S-3 fail-closed: a risk brief with ANY finding lacking its verifiable rubric citation (missing
        # local citation, or no exact top-level {dimension, source} for that finding) is never presented.
        # Degrade to a safe needs_review answer (SUCCESS + error_code), withhold the brief body, and still
        # run the disclaimer + terminal S-4 audit.
        if grounded and not citation_complete:
            error_code = state.get("error_code") or "CITATION_INCOMPLETE"
            blocked: dict[str, Any] = {
                "status_kind": "needs_review",
                "change_id": report.get("change_id"),
                "asset_window_summary": {},
                "risk_findings": [],  # incomplete brief body withheld
                "rollback_assessment": {},
                "contributing_risk_factors": [],
                "recommended_conditions": [],
                "human_approval_status": {
                    "requires_cab_review": True,
                    "decision_authority": "authorized human (CAB / change manager)",
                    "note": _NEEDS_REVIEW_NOTE,
                },
                "citations": [],
                "citation_complete": False,
                "message": _CITATION_INCOMPLETE_MSG,
                "disclaimer": _DISCLAIMER,
            }
            emit_trace_event(
                "post_process.citation_blocked",
                {"finding_count": len(report.get("risk_findings", [])), "error_code": error_code},
                state,
            )
            return {
                "formatted_output": json.dumps(blocked, ensure_ascii=False),
                "disclaimer": _DISCLAIMER,
                "audit_logged": True,
                "error_code": error_code,
                "status": AgentStatus.SUCCESS.value,
            }

        formatted = {
            "status_kind": report.get("status_kind"),
            "change_id": report.get("change_id"),
            "asset_window_summary": report.get("asset_window_summary", {}),
            "risk_findings": report.get("risk_findings", []),
            "rollback_assessment": report.get("rollback_assessment", {}),
            "contributing_risk_factors": report.get("contributing_risk_factors", []),
            "recommended_conditions": report.get("recommended_conditions", []),
            "human_approval_status": report.get("human_approval_status", {}),
            "citations": citations,
            "citation_complete": citation_complete,
            "message": report.get("message"),
            "disclaimer": _DISCLAIMER,
        }
        emit_trace_event(
            "post_process.complete",
            {
                "status_kind": report.get("status_kind"),
                "finding_count": len(report.get("risk_findings", [])),
                "citation_complete": citation_complete,
                "error_code": state.get("error_code"),
            },
            state,
        )
        return {
            "formatted_output": json.dumps(formatted, ensure_ascii=False),
            "disclaimer": _DISCLAIMER,
            "audit_logged": True,
            "status": AgentStatus.SUCCESS.value,
        }
