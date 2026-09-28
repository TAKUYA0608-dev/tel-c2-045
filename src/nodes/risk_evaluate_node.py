"""TEL-C2-045 — inner workflow step 2: risk_evaluate.

**Deterministic rubric** (ChangeControlRubric — no LLM; reproducible severity scoring). Scores the
change across five dimensions — rollback completeness / dependency coupling /
blast radius / customer impact / maintenance-window validity — into severity-tagged findings, each with
a rubric citation. No-ops (skip guard) on rejected / 0-asset input.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import ChangeControlRubric
from src.utils.audit import emit_trace_event


class RiskEvaluateNode(FunctionNode):
    """Score the change into severity-tagged risk findings (deterministic rubric)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Skip guard — rejected / 0-asset input. Emit a count-only S-4 event before the no-op return so
        # every execute() path carries a domain audit event.
        if state.get("error_code") or state.get("ingest_count", 0) == 0:
            emit_trace_event("risk_evaluate.skipped", {"reason": state.get("error_code") or "no_assets"}, state)
            return {}

        classified = json.loads(state.get("classified_assets") or "[]")
        window_assessment = json.loads(state.get("window_assessment") or "{}")
        pkg = json.loads(state.get("validated_input") or "{}")

        findings = ChangeControlRubric.evaluate(classified, window_assessment, pkg)
        severities = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
        emit_trace_event(
            "risk_evaluate.complete", {"finding_count": len(findings), "severity_counts": severities}, state
        )
        return {"risk_findings": json.dumps(findings, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}
