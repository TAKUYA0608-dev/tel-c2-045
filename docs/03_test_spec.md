# Test Specification — TEL-C2-045

Telecom Network Firmware Change-Window Risk Brief Agent (Cat 2).

## Test Strategy
- Coverage target: **80%+** (achieved **95%** on `tests/unit` + `tests/integration`, `--cov=src`).
- Test types: Unit (pre/post + 4 inner nodes + deterministic services) / Unit (Cat 2 graph wiring) /
  Integration (end-to-end pre → inner linear workflow → post) / Proof-of-Boundary.
- Advisory / read-only: every path is asserted to be non-mutating — the agent produces an *ex-ante*
  brief and never schedules / deploys / commands a device / auto-rolls-back.

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict | `State(AgentState)`, NotRequired primitives + JSON strings; no PII | ✅ PASS |
| TC-02 | S-2 hook never raises / never ERROR | `_extra_security_gate_input` is a no-op returning state (SDK 1.0.0); injection/oversize are degraded `SUCCESS + error_code` in `execute()`, so main/post_process always run | ✅ PASS |
| TC-03 | No JWT/Credential in `src/` | `gate-credential-scan`: 0 violations (patterns built by concatenation) | ✅ PASS |
| TC-05 | S-4: no duplicate lifecycle events | only domain `emit_trace_event` calls in `execute()` | ✅ PASS |
| TC-06 | S-2 `_security_gate_input()` not overridden | `@final`; only `_extra_*` extended | ✅ PASS |
| TC-07 | S-3 `_security_gate_output()` not overridden | `@final`; may raise via `_extra_*` | ✅ PASS |
| TC-08 | `required_trust_level` enforced | VERIFIED_EXTERNAL on all 6 `FunctionNode` subclasses (`check_trust_level.py` PASS) | ✅ PASS |
| TC-11 | S-4: ≥1 domain `emit_trace_event()` per `execute()` | emitted on every path (incl. degraded / safe branch) | ✅ PASS |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Expected Result | Result |
|-------|----------|----------------|--------|
| PB-1 | `emit_trace_event()` fires from `shared.utils.audit_logger` | No silent failures (best-effort shim) | ✅ (real SDK on CI) |
| PB-2 | Post-invoke State is primitives only | No Pydantic/dataclass; complex fields are JSON strings | ✅ PASS |
| PB-4 | Import isolation — no Level 0 imports | AST scan: 0 `agenticstar` imports (framework.* only) | ✅ PASS |
| PB-6 | Invoke order S-1 → S-4 → S-2 → execute → S-3 → S-4 | Order verified | ✅ (real SDK on CI; local-stub env-diff) |
| PB-7 | HITL interrupt propagation *(conditional)* | `hitl.enabled=false` → Auto-waived (2 SKIPPED) | ✅ (conditional) |
| Composition | Cat 2 `GraphNode`-in-main wraps inner `BaseGraph` (cached) | gate-composition passes | ✅ (S-0 gate) |

> **Known local/CI difference:** `tests/proof_of_boundary/test_pb_invoke_order.py` monkeypatches
> `framework.nodes.base_node.emit_trace_event`, which exists only in the production SDK
> (`agenticstar-agentcore==1.0.0`), not in the local SDK stub v1.13.0. It **fails locally, passes on CI** with the
> real SDK — same behavior as the shipped reference a sibling template.

## Business Logic Tests

| BL-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | High-risk core change | UPF + gNodeB, no rollback, 14:00–14:30 window | rollback/blast/window findings HIGH; `requires_cab_review=true`; exceptions present | ✅ PASS |
| BL-02 | Low-risk access change | OLT, rollback present, 01:00–03:00 window | all findings LOW; `requires_cab_review=false`; no conditions | ✅ PASS |
| BL-03 | Out-of-scope safe answer | free text with no NW assets | `status_kind=out_of_scope`; `citations=[]`; audited | ✅ PASS |
| BL-04 | Empty input degrades (not ERROR) | `"   "` | `status=SUCCESS` + `error_code=INPUT_REJECTED`; audited | ✅ PASS |
| BL-05 | Window adequacy | short window (20 min) vs rollback | `adequate_for_rollback=false` → rollback finding MEDIUM | ✅ PASS |
| BL-06 | Undocumented duration | window without end | `adequate_for_rollback=None` → rollback finding MEDIUM | ✅ PASS |
| BL-07 | Midnight-crossing window | 23:30–01:00 | duration = 90 min | ✅ PASS |
| BL-08 | Unknown asset type | `asset_type="mystery"` | conservatively T3-access + explicit "could not classify" finding | ✅ PASS |

## Security Tests (S-1 → S-4)

| ID | Test | Expected Result | Result |
|----|------|----------------|--------|
| SEC-01 | Oversize degrades (not ERROR) | input > 20,000 chars → `status=SUCCESS + error_code=INPUT_TOO_LONG`; body discarded; post_process still runs (real `Graph().invoke()` verifies terminal S-4 audit) | ✅ PASS |
| SEC-02 | Injection degrades in `execute()` | injection markers → `status=SUCCESS + error_code=INJECTION_REJECTED`; body discarded → out-of-scope safe answer; real `Graph().invoke()` proves post_process + S-4 audit run (not a `finalize` short-circuit) | ✅ PASS |
| SEC-03 | S-1 My-Number redaction before persist | 12-digit run masked in `validated_input` | ✅ PASS |
| SEC-04 | S-1 credential redaction before persist | `token=…` / `api_key=…` masked before persist | ✅ PASS |
| SEC-04b | S-1 field-level redaction — every supplied field | credential-/My-Number-shaped `asset_id` (and nested `window` strings) masked before persist; end-to-end: secret never reaches `classified_assets`, `result`, or the envelope | ✅ PASS |
| SEC-05 | S-3 injection neutralization in output | any echoed injection marker neutralized in `formatted_output` (defense-in-depth) | ✅ PASS |
| SEC-06 | S-3 credential/PII redaction in output | secrets + My-Number masked in the envelope | ✅ PASS |
| SEC-07 | S-3 disclaimer preservation | `_extra_security_gate_output` raises if DRAFT disclaimer absent | ✅ PASS |
| SEC-08 | Real invoke path — reject reaches post_process | `Graph().invoke()` on injection/oversize: `status=SUCCESS`, `PostProcessNode` in `node_history`, `status_kind=out_of_scope`, DRAFT disclaimer, rejected body absent, and the terminal S-4 audit carries `error_code` (INJECTION_REJECTED / INPUT_TOO_LONG) — captured via `_platform_emit` monkeypatch | ✅ PASS |

## Test Execution Summary
- Suite: `tests/unit` + `tests/integration` = **72 passed, 1 skipped** (platform-module import skip in
  local stub env; `TestGraphInvoke` real `Graph().invoke()` injection/oversize/valid cases all pass).
- Coverage: **95%** (`--cov=src`).
- `python3 scripts/check_trust_level.py src/` = **PASS** (all FunctionNode subclasses declare
  `required_trust_level`).

## Run

```bash
python -m pytest tests/unit tests/integration -q --cov=src --cov-report=term-missing
python3 scripts/check_trust_level.py src/
```
