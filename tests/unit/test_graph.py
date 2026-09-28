# TEL-C2-045 — Unit Tests: Cat 2 graph wiring (outer GraphNode + inner workflow)

import pytest

from src.graph.domain_workflow_graph import ChangeWindowRiskWorkflow
from src.graph.graph import (
    ChangeWindowRiskWorkflowGraphNode,
    Graph,
    TelecomNetworkFirmwareChangeWindowRiskAgent,
)
from src.schemas.state import State


class TestOuterGraph:
    def test_registry_alias(self):
        assert TelecomNetworkFirmwareChangeWindowRiskAgent is Graph

    def test_name_and_state_schema(self):
        g = Graph()
        assert g.name == "TelecomNetworkFirmwareChangeWindowRiskAgent"
        assert g.state_schema is State

    def test_main_slot_is_graphnode(self):
        g = Graph()
        g.register_nodes()
        assert isinstance(g._nodes["main"], ChangeWindowRiskWorkflowGraphNode)
        for slot in ("pre_process", "main", "post_process"):
            assert slot in g._nodes

    def test_error_strategy_propagate_and_no_hitl(self):
        assert ChangeWindowRiskWorkflowGraphNode.error_strategy == "propagate"
        assert ChangeWindowRiskWorkflowGraphNode.propagate_hitl is False

    def test_get_subgraph_is_cached(self):
        node = ChangeWindowRiskWorkflowGraphNode()
        assert node.get_subgraph() is node.get_subgraph()

    def test_extract_input_prefers_validated(self):
        node = ChangeWindowRiskWorkflowGraphNode()
        assert node.extract_input({"validated_input": "V", "user_input": "U"}) == "V"
        assert node.extract_input({"user_input": "U"}) == "U"

    def test_merge_output_surfaces_fields(self):
        node = ChangeWindowRiskWorkflowGraphNode()
        merged = node.merge_output({}, {"output": '{"x":1}', "ingest_count": 3, "status": "success",
                                        "error_code": None})
        assert merged["result"] == '{"x":1}' and merged["ingest_count"] == 3
        assert merged["status"] == "success"

    def test_merge_output_falls_back_to_state_error(self):
        node = ChangeWindowRiskWorkflowGraphNode()
        merged = node.merge_output({"error_code": "NO_ASSETS", "ingest_count": 0}, {"output": None})
        assert merged["error_code"] == "NO_ASSETS" and merged["ingest_count"] == 0


class TestInnerWorkflow:
    def test_inner_registers_four_nodes(self):
        wf = ChangeWindowRiskWorkflow(config={})
        wf.register_nodes()
        for slot in ("asset_window_classify", "risk_evaluate", "change_brief_synthesis", "human_gate"):
            assert slot in wf._nodes

    def test_route_zero_ingest_to_human_gate(self):
        wf = ChangeWindowRiskWorkflow(config={})
        assert wf.route({"ingest_count": 0}) == "human_gate"
        assert wf.route({"error_code": "NO_ASSETS", "ingest_count": 2}) == "human_gate"

    def test_route_normal_to_risk_evaluate(self):
        wf = ChangeWindowRiskWorkflow(config={})
        assert wf.route({"ingest_count": 2}) == "risk_evaluate"

    def test_name_state_schema_and_get_output(self):
        wf = ChangeWindowRiskWorkflow(config={})
        assert wf.name == "ChangeWindowRiskWorkflow" and wf.state_schema is State
        out = wf.get_output({"result": "R", "status": "success", "ingest_count": 1})
        assert out["output"] == "R" and out["ingest_count"] == 1


class TestServerModule:
    def test_server_imports(self):
        try:
            import src.api.server as server
        except ModuleNotFoundError as exc:
            pytest.skip(f"platform module unavailable in the local stub env: {exc}")
        assert server.app is not None and server.agent is not None
