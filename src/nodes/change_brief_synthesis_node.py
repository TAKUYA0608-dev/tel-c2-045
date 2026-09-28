"""TEL-C2-045 — inner workflow step 3: change_brief_synthesis.

Structures the multiple risk factors + rollback assessment + recommended conditions into a cited change
brief body. **Never an approval decision** — it produces evidence and recommended conditions only; the
GO/NO-GO stays with an authorized human (HumanGate → CAB). Deterministic template-based assembly — no
LLM; the brief body is composed from the grounded rubric findings. No-ops (skip guard) on rejected /
0-asset input.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.utils.audit import emit_trace_event

# Recommended mitigating condition per risk dimension (surfaced when severity is medium/high).
_CONDITIONS: dict[str, str] = {
    "rollback_completeness": "Attach a validated, time-boxed rollback plan and confirm the maintenance "
    "window has enough headroom to execute it before scheduling.",
    "dependency_coupling": "Enumerate and stage downstream-dependent elements; verify blast-radius "
    "isolation (e.g., redundancy / drain) before the change.",
    "blast_radius": "Limit the change to one criticality tier per window where possible, or stage it "
    "with progressive rollout + health checks.",
    "customer_impact": "Document explicit customer-impact criteria and a monitored acceptance threshold; "
    "line up NOC watch for the window.",
    "window_validity": "Reschedule into the conventional low-traffic maintenance band, or obtain CAB "
    "sign-off for an out-of-band window.",
}


class ChangeBriefSynthesisNode(FunctionNode):
    """Synthesize the cited change-brief body (never an approval)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Skip guard — rejected / 0-asset input. Emit a count-only S-4 event before the no-op return so
        # every execute() path carries a domain audit event.
        if state.get("error_code") or state.get("ingest_count", 0) == 0:
            emit_trace_event(
                "change_brief_synthesis.skipped", {"reason": state.get("error_code") or "no_assets"}, state
            )
            return {}

        classified = json.loads(state.get("classified_assets") or "[]")
        window_assessment = json.loads(state.get("window_assessment") or "{}")
        findings = json.loads(state.get("risk_findings") or "[]")
        pkg = json.loads(state.get("validated_input") or "{}")

        asset_summary = [
            {
                "asset_id": c["asset_id"],
                "asset_type": c["asset_type"],
                "criticality_tier": c["criticality_tier"],
                "blast_radius": c["blast_radius"],
                "dependencies": c["dependencies"],
            }
            for c in classified
        ]
        rollback_present = bool((pkg.get("rollback_plan") or "").strip())
        rollback_assessment = {
            "rollback_plan_present": rollback_present,
            "window_adequate_for_rollback": window_assessment.get("adequate_for_rollback"),
            "note": window_assessment.get("note"),
        }

        # Recommended conditions — one per medium/high risk dimension (deduplicated, ordered).
        conditions: list[dict[str, str]] = []
        seen: set[str] = set()
        for f in findings:
            if f["severity"] in ("high", "medium") and f["dimension"] not in seen:
                seen.add(f["dimension"])
                cond = _CONDITIONS.get(f["dimension"])
                if cond:
                    conditions.append(
                        {"for": f["dimension"], "severity": f["severity"], "condition": cond, "citation": f["citation"]}
                    )

        citations = self._citations(classified, findings, window_assessment)
        brief_body = {
            "change_id": pkg.get("change_id"),
            "asset_window_summary": {"assets": asset_summary, "window_assessment": window_assessment},
            "risk_findings": findings,
            "rollback_assessment": rollback_assessment,
            "recommended_conditions": conditions,
            "contributing_risk_factors": [
                f"{f['dimension']} ({f['severity']})" for f in findings if f["severity"] in ("high", "medium")
            ],
            "citations": citations,
        }
        emit_trace_event(
            "change_brief_synthesis.complete",
            {"condition_count": len(conditions), "citation_count": len(citations)},
            state,
        )
        return {"change_brief": json.dumps(brief_body, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}

    @staticmethod
    def _citations(
        classified: list[dict[str, Any]], findings: list[dict[str, Any]], window_assessment: dict[str, Any]
    ) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        seen: set[str] = set()
        for c in classified:
            src = c.get("source")
            if src and src not in seen:
                seen.add(src)
                out.append({"asset_id": c["asset_id"], "source": src})
        for f in findings:
            src = f.get("citation")
            if src and src not in seen:
                seen.add(src)
                out.append({"dimension": f["dimension"], "source": src})
        return out
