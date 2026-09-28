"""TEL-C2-045 — inner domain workflow graph (Cat 2).

Instantiated by ChangeWindowRiskWorkflowGraphNode.get_subgraph() in graph.py. Linear topology with
per-node skip guards (the portable Cat 2 form; conditional edges don't propagate across the subgraph
boundary):

    START → asset_window_classify → risk_evaluate → change_brief_synthesis → human_gate → END

On rejected / 0-asset input, asset_window_classify sets ingest_count=0 (+error_code); risk_evaluate and
change_brief_synthesis no-op and human_gate emits the out-of-scope safe answer — no fabricated brief.
"""

from __future__ import annotations
from typing import Any

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState

from src.nodes.asset_window_classify_node import AssetWindowClassifyNode
from src.nodes.change_brief_synthesis_node import ChangeBriefSynthesisNode
from src.nodes.human_gate_node import HumanGateNode
from src.nodes.risk_evaluate_node import RiskEvaluateNode
from src.schemas.state import State


class ChangeWindowRiskWorkflow(BaseGraph):
    """Inner graph: asset_window_classify → risk_evaluate → change_brief_synthesis → human_gate."""

    @property
    def name(self) -> str:
        return "ChangeWindowRiskWorkflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        pass

    def register_nodes(self) -> None:
        # No super() — BaseGraph.register_nodes() is abstract.
        self._nodes["asset_window_classify"] = AssetWindowClassifyNode()
        self._nodes["risk_evaluate"] = RiskEvaluateNode()
        self._nodes["change_brief_synthesis"] = ChangeBriefSynthesisNode()
        self._nodes["human_gate"] = HumanGateNode()

    def add_edges(self) -> None:
        # Static linear backbone; the 0-asset / rejected skip is handled by per-node guards.
        self._sg.add_edge(START, "asset_window_classify")
        self._sg.add_edge("asset_window_classify", "risk_evaluate")
        self._sg.add_edge("risk_evaluate", "change_brief_synthesis")
        self._sg.add_edge("change_brief_synthesis", "human_gate")
        self._sg.add_edge("human_gate", END)

    def route(self, state: AgentState) -> str:
        """Required by the BaseGraph ABC. Linear topology → not wired to a conditional edge."""
        if state.get("error_code") or state.get("ingest_count", 0) == 0:
            return "human_gate"
        return "risk_evaluate"

    def get_output(self, state: AgentState) -> dict[str, Any]:
        return {
            "output": state.get("result"),
            "status": state.get("status"),
            "ingest_count": state.get("ingest_count", 0),
            "error_code": state.get("error_code"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
