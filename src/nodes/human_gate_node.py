"""TEL-C2-045 — inner workflow step 4 (terminal): human_gate.

**Deterministic HITL gate.** Routes material decisions / uncertainty to authorized change approval (CAB):
sets ``requires_cab_review``, records exceptions (unmet preconditions), and proposes **candidate** owners
only — the final GO/NO-GO and owner assignment stay with an authorized human. Assembles the terminal
Change-Window Risk Brief (``result``). On the rejected / 0-asset safe branch it emits the out-of-scope
safe answer (``citations=[]``) — no fabricated risk brief.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.utils.audit import emit_trace_event

_OUT_OF_SCOPE = (
    "変更パッケージ内に分類可能なネットワーク資産が見つかりませんでした。対象資産（コア/BNG/集約/RAN/"
    "アクセス/CPE 等）、保守 window、rollback 計画を明示した承認済みファーム変更パッケージをご提供いただくか、"
    "ライブ監視・incident 対応は NMS / observability 系の capability にお回しください。"
    "（本エージェントは実施前の助言専用で、変更のスケジュール・実施・機器へのコマンド送信は行いません。）"
)

# Candidate (placeholder) owners only — final assignment is an authorized-human decision at CAB.
_CANDIDATE_OWNERS = ["<change-manager: TBD (authorized human)>", "<risk-owner: TBD (CAB)>"]


class HumanGateNode(FunctionNode):
    """Deterministic HITL gate + terminal brief assembly (or out-of-scope safe answer)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Safe branch — rejected / 0-asset input.
        if state.get("error_code") or state.get("ingest_count", 0) == 0:
            emit_trace_event("human_gate.safe", {"reason": state.get("error_code") or "no_assets"}, state)
            report: dict[str, Any] = {
                "status_kind": "out_of_scope",
                "message": _OUT_OF_SCOPE,
                "risk_findings": [],
                "citations": [],
            }
            return {"result": json.dumps(report, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}

        brief = json.loads(state.get("change_brief") or "{}")
        window_assessment = json.loads(state.get("window_assessment") or "{}")
        findings = brief.get("risk_findings", [])

        high = [f for f in findings if f["severity"] == "high"]
        exceptions = self._exceptions(findings, window_assessment, brief)
        requires_cab_review = bool(high) or bool(exceptions) or not window_assessment.get("within_low_traffic")

        review_decision = {
            "requires_cab_review": requires_cab_review,
            "exceptions": exceptions,
            "candidate_owners": list(_CANDIDATE_OWNERS),
            "decision_authority": "authorized human (CAB / change manager) — agent is advisory only",
        }
        report = {
            "status_kind": "risk_brief",
            "change_id": brief.get("change_id"),
            "asset_window_summary": brief.get("asset_window_summary", {}),
            "risk_findings": findings,
            "rollback_assessment": brief.get("rollback_assessment", {}),
            "contributing_risk_factors": brief.get("contributing_risk_factors", []),
            "recommended_conditions": brief.get("recommended_conditions", []),
            "human_approval_status": review_decision,
            "citations": brief.get("citations", []),
        }
        emit_trace_event(
            "human_gate.complete",
            {"requires_cab_review": requires_cab_review, "high_count": len(high), "exception_count": len(exceptions)},
            state,
        )
        return {
            "review_decision": json.dumps(review_decision, ensure_ascii=False),
            "result": json.dumps(report, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }

    @staticmethod
    def _exceptions(
        findings: list[dict[str, Any]], window_assessment: dict[str, Any], brief: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Unmet preconditions that must be resolved by an authorized human before approval."""
        out: list[dict[str, str]] = []
        for f in findings:
            if f["severity"] == "high":
                out.append({"dimension": f["dimension"], "detail": f["detail"], "owner": "<TBD: authorized human>"})
        if window_assessment.get("adequate_for_rollback") is None:
            out.append(
                {
                    "dimension": "rollback_completeness",
                    "detail": "Window duration undocumented — rollback headroom unverified.",
                    "owner": "<TBD: change manager>",
                }
            )
        return out
