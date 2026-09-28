"""TEL-C2-045 — inner workflow step 1: asset_window_classify.

**Deterministic.** Classifies each target asset's criticality tier + downstream dependencies
(AssetImpactKB) and assesses the maintenance window (ChangeControlRubric). Sets ``ingest_count``;
**0 classifiable assets → out-of-scope safe brief** (the agent never fabricates a risk brief for a
change package with no identifiable network assets).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import AssetImpactKB, ChangeControlRubric
from src.utils.audit import emit_trace_event


class AssetWindowClassifyNode(FunctionNode):
    """Classify target-asset criticality tiers + assess the maintenance window."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        pkg = json.loads(state.get("validated_input") or state.get("user_input") or "{}")
        canonical = json.dumps(pkg, ensure_ascii=False)

        # Skip guard — rejected / empty input propagated from pre_process.
        if state.get("error_code"):
            emit_trace_event("asset_window_classify.skip", {"reason": state.get("error_code")}, state)
            return {
                "validated_input": canonical,
                "classified_assets": "[]",
                "ingest_count": 0,
                "window_assessment": "{}",
                "status": AgentStatus.SUCCESS.value,
            }

        classified = AssetImpactKB.classify(pkg.get("assets") or [])
        if not classified:
            emit_trace_event("asset_window_classify.no_assets", {"asset_count": 0}, state)
            return {
                "validated_input": canonical,
                "classified_assets": "[]",
                "ingest_count": 0,
                "window_assessment": "{}",
                "error_code": "NO_ASSETS",
                "error_message": "no classifiable network assets in the change package",
                "status": AgentStatus.SUCCESS.value,
            }

        window_assessment = ChangeControlRubric.assess_window(
            pkg.get("window") or {}, rollback_present=bool((pkg.get("rollback_plan") or "").strip())
        )
        emit_trace_event(
            "asset_window_classify.complete",
            {
                "ingest_count": len(classified),
                "max_tier": AssetImpactKB.max_tier(classified),
                "within_low_traffic": window_assessment.get("within_low_traffic"),
            },
            state,
        )
        return {
            "validated_input": canonical,
            "classified_assets": json.dumps(classified, ensure_ascii=False),
            "ingest_count": len(classified),
            "window_assessment": json.dumps(window_assessment, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
