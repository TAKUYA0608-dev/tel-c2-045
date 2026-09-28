# Template Design Specification — TEL-C2-045

Telecom Network Firmware Change-Window Risk Brief Agent (Cat 2).

## Position in AgentCore Architecture

- **Agent Class**: `TelecomNetworkFirmwareChangeWindowRiskAgent` (module-level alias of `Graph`)
- **L1 Base**: **AgentBaseGraph** (Cat 2 — outer 5-node backbone; direct L1 inheritance, no L2)
- **Category**: Cat 2 — a multi-step domain workflow (validate → classify → risk-evaluate → synthesize →
  human-gate → compose) producing an *ex-ante* Change-Window Risk Brief; TEL industry
- **Three-Layer Separation**: State = flat TypedDict; Node = L1 inheritance (`execute(self, state: dict) -> dict`
  override only); Graph = outer `AgentBaseGraph` + **`GraphNode` in the `main` slot** wrapping an inner `BaseGraph`

## Architecture Overview

Cat 2 pattern — the `main` slot is a **`GraphNode`** (`ChangeWindowRiskWorkflowGraphNode`, **subgraph
cached**) that wraps the inner `ChangeWindowRiskWorkflow` (`BaseGraph`). The inner graph is a **static
linear backbone with per-node skip guards**. **Advisory / read-only: the agent never schedules,
deploys, sends device commands, or auto-rolls-back a change** — it composes a pre-change risk brief that
an authorized human (CAB / change manager) uses to make the final GO/NO-GO decision.

### Node Configuration

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | schema_version, session_id, trust_level | user_input | (framework) | InitializeNode (default) |
| pre_process | `PreProcessNode` (ChangePackageValidate) — S-1 normalize + size cap; redact credential / My-Number / phone / email (+ best-effort labelled name); extract change slots | user_input | validated_input, input_format, enriched_context | FunctionNode.execute |
| main | `ChangeWindowRiskWorkflowGraphNode` (GraphNode) → inner workflow | validated_input | result, ingest_count | GraphNode |
| post_process | `PostProcessNode` (BriefCompose) — S-3 output sanitize (injection neutralize + redact credential / My-Number / phone / email + best-effort labelled name) + citation completeness + mandatory DRAFT disclaimer + S-4 audit | result | formatted_output, disclaimer, audit_logged | FunctionNode.execute |
| finalize | response_metadata, total_time_ms | | (framework) | FinalizeNode (default) |

**Inner workflow (`ChangeWindowRiskWorkflow` : BaseGraph):**

```
START → asset_window_classify → risk_evaluate → change_brief_synthesis → human_gate → END
```

| Inner node | Responsibility |
|---|---|
| AssetWindowClassify | **deterministic** — classify each target asset's criticality tier + downstream dependencies (AssetImpactKB) and assess the maintenance window; sets `ingest_count`; **0 assets → out-of-scope safe brief** |
| RiskEvaluate | **deterministic rubric** (ChangeControlRubric — no LLM; reproducible severity scoring) — score rollback completeness / dependency coupling / blast radius / customer impact / window validity into severity-tagged findings |
| ChangeBriefSynthesis | structure the multiple risk factors + rollback assessment + recommended conditions into a cited brief body — **never** an approval decision |
| HumanGate | **deterministic** — route material decisions / uncertainty to authorized change approval (CAB): set `requires_cab_review`, record exceptions, and propose **candidate** owners only; assemble the final brief; on the safe branch emit the out-of-scope answer |

### Data Flow

```
START → initialize → pre_process → main(GraphNode → inner linear workflow) → post_process → finalize → END
                                     ↓ (retry, max 3)
                                   pre_process
```

Rejected / 0-asset input sets `error_code` + `ingest_count=0`; `risk_evaluate` and `change_brief_synthesis`
no-op (skip guard, **each still emitting a count-only S-4 event** — every `execute()` path carries a
domain audit event) and `human_gate` emits the out-of-scope safe answer — **no fabricated risk brief**.

### State Definition

| Field | Type | Purpose |
|-------|------|---------|
| validated_input | str (JSON) | `{change_id, change_plan, assets[], window, rollback_plan, customer_impact_criteria}` (credential / My-Number / phone / email redacted; labelled names best-effort — every supplied string leaf, identifiers + nested window strings included, passes S-1 hygiene) |
| classified_assets / ingest_count | str/int | asset tier + dependencies / 0 → out-of-scope safe brief |
| window_assessment | str (JSON) | `{window, within_low_traffic, adequate_for_rollback, note}` |
| risk_findings | str (JSON) | `[{dimension, severity, detail, citation}]` |
| change_brief / review_decision | str (JSON) | synthesized brief body / `{requires_cab_review, exceptions[], candidate_owners[]}` |
| result / formatted_output | str (JSON) | inner brief report / final envelope |
| disclaimer / audit_logged | str/bool | mandatory DRAFT disclaimer + terminal audit |
| error_code / error_message | str | degraded path (SUCCESS + error_code, never status=ERROR) |

**State Constraints:** flat TypedDict; JSON strings for complex fields (ADR-005); `enriched_context` is a
JSON string. **Privacy contract (deterministic — no LLM/NER):** credential-shaped tokens, My-Number
(12-digit), phone numbers (JP mobile / landline / international) and email addresses are redacted from
**every supplied string leaf** (free-text slots, identifiers, and nested `window` strings) at S-1 before
they persist to `validated_input` and again at S-3 before they surface. Personal names are **best-effort**
— redacted only when carried after a contact / owner / approver / 担当 / 氏名 label (label-anchored); a
free-standing personal name in prose (no label) is not detected, which is acceptable because the brief is
advisory / re-redacted at S-3 and the deterministic classification is unaffected by any residual token.

## Framework Utilization

- [x] **GraphNode-in-main** (Cat 2 composition, criterion #9) — `error_strategy="propagate"`, `propagate_hitl=False`, **subgraph cached**
- [x] S-1 `required_trust_level=VERIFIED_EXTERNAL` on all `FunctionNode` nodes (pre/post + 4 inner)
- [x] S-2 input hook `_extra_security_gate_input()` (pre) — **no-op that never raises and never returns status=ERROR** (SDK 1.0.0); a `status=ERROR` here would short-circuit `__call__` so `route()` would go straight to `finalize`, skipping main / post_process. **Prompt-injection / oversize are rejected inside `execute()` as a degraded `status=SUCCESS` + `error_code` (INJECTION_REJECTED / INPUT_TOO_LONG)** with the untrusted body discarded (`validated_input="{}"`) — so main / post_process (disclaimer / redaction / S-4 audit) always run and the out-of-scope safe answer is delivered
- [x] S-3 output gate `_extra_security_gate_output()` (post) — mandatory-disclaimer preservation; **may raise** (SDK 1.0.0). `execute()` additionally neutralizes injection markers and redacts credential / My-Number / phone / email (+ best-effort labelled name) from any echoed change-package text before it enters the envelope
- [x] S-4 `emit_trace_event()` in every `execute()` (asset tiers / severities / counts only — no raw change content); terminal audit always fires

## Import Isolation Confirmation
- [x] No `agenticstar` SDK (Level 0) import — PB-4
- [x] Import targets: `framework/`, `langgraph`, and `src.` only

## Design Decision Record

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| L1 base type | AgentBaseGraph | Fixed pipeline, no autonomous loop |
| Composition | **GraphNode-in-main + inner BaseGraph (cached)** | Cat 2 multi-step domain workflow |
| Inner topology | **Linear + per-node skip guards** | Conditional edges don't propagate across the subgraph boundary |
| Risk evaluation | **Deterministic rubric (ChangeControlRubric)** | Auditable, reproducible severity scoring; fully deterministic — no LLM anywhere in this template |
| Injection / oversize handling | **Degraded SUCCESS + error_code in `execute()`** | Rejected input discards the untrusted body but still runs main / post_process (disclaimer / S-4 audit); `status=ERROR` would short-circuit `__call__`. S-3 injection-marker neutralization stays as defense-in-depth |
| Change accountability | **HumanGate — advisory only** | Final GO/NO-GO + owner assignment stay with an authorized human; agent proposes candidate owners only |
| Rejection signalling | SUCCESS + error_code | Guarantees post_process S-3/S-4 always run (SDK 1.0.0) |

## Open Items (Stage ③ implementation MR)
- Node implementations + inner workflow graph (shipped in the implementation MR).
- Seeded `AssetImpactKB` (telecom NW element tiers: core / BNG / aggregation / RAN / access / CPE) +
  `ChangeControlRubric` (rollback / dependency / blast-radius / customer-impact / window rubric sections).
- Unit + integration + PB tests; coverage ≥ 80%.
