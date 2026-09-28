"""TEL-C2-045 — outer graph (Cat 2).

AgentBaseGraph 5-node backbone; domain complexity in the `main` slot via
ChangeWindowRiskWorkflowGraphNode (a GraphNode wrapping the inner ChangeWindowRiskWorkflow).

    START → initialize → pre_process → main(GraphNode) → post_process → finalize → END

Advisory / read-only: the agent composes an *ex-ante* Change-Window Risk Brief — it never schedules,
deploys, sends a device command, or auto-rolls-back a change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState

from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State

if TYPE_CHECKING:
    from src.graph.domain_workflow_graph import ChangeWindowRiskWorkflow


class ChangeWindowRiskWorkflowGraphNode(GraphNode):
    """`main` slot — wraps the inner ChangeWindowRiskWorkflow (composition criterion #9)."""

    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False
    _subgraph: ClassVar[ChangeWindowRiskWorkflow | None] = (
        None  # class-level cache (SDK how-to compose-agents-graphnode.md) — not mutable node-instance state (CoE §9)
    )

    def get_subgraph(self) -> ChangeWindowRiskWorkflow:
        # Cache the inner-workflow instance (BaseGraph.invoke() _ensure_compiled is idempotent →
        # skips per-request DAG compile).
        if self._subgraph is None:
            from src.graph.domain_workflow_graph import ChangeWindowRiskWorkflow

            ChangeWindowRiskWorkflowGraphNode._subgraph = ChangeWindowRiskWorkflow(config=self._parent_config())
        return cast("ChangeWindowRiskWorkflow", self._subgraph)

    def extract_input(self, state: AgentState) -> str:
        return cast(str, state.get("validated_input", state.get("user_input", "")))

    def merge_output(self, state: AgentState, sub_result: dict[str, Any]) -> dict[str, Any]:
        # The outer pre_process degraded reason (INJECTION_REJECTED / INPUT_TOO_LONG) takes precedence:
        # the inner subgraph runs on a fresh state (it only receives `validated_input` via
        # extract_input, not the outer error_code), so on a rejected input it independently reports
        # NO_ASSETS. Preferring the outer error_code preserves the true degraded reason for the terminal
        # S-4 audit; a genuine 0-asset on a valid package (outer error_code absent)
        # still surfaces the inner NO_ASSETS.
        return {
            "result": sub_result.get("output"),
            "ingest_count": sub_result.get("ingest_count", state.get("ingest_count", 0)),
            "error_code": state.get("error_code") or sub_result.get("error_code"),
            "status": sub_result.get("status"),
        }

    def _parent_config(self) -> dict[str, Any]:
        return {}


class Graph(AgentBaseGraph):
    """Outer Cat 2 graph for TEL-C2-045."""

    @property
    def name(self) -> str:
        return "TelecomNetworkFirmwareChangeWindowRiskAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = ChangeWindowRiskWorkflowGraphNode()
        self._nodes["post_process"] = PostProcessNode()

    def get_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """Framework default, plus the guarantee that a success is never empty.

        The Marketplace runner rejects a successful invocation whose output is
        missing — verified on a deployed Pod — and a degraded run
        (SUCCESS + error_code) produces no artefact for the framework default
        to surface. Report the degradation instead: this states what happened,
        it does not invent an answer.

        Only on SUCCESS. A request refused by the framework's S-2 gate (status
        ERROR) must keep publishing nothing — answering a hostile input with a
        notice would undo the refusal, and the runner treats a non-success
        invocation as a failure regardless, so there is nothing to rescue.
        """
        out: dict[str, Any] = super().get_output(state)
        if not out.get("output") and str(state.get("status", "")).lower().endswith("success"):
            code = state.get("error_code") or "NO_CONTENT"
            out["output"] = (
                "This request could not be completed "
                f"(error_code={code}). No content was produced; "
                "see error_code and error_log for the degradation cause."
            )
        return out


# server.py / AgentRegistry expect a module-level alias for the agent class.
TelecomNetworkFirmwareChangeWindowRiskAgent = Graph
