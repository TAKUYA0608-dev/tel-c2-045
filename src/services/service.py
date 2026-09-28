"""TEL-C2-045 — deterministic domain services (no framework imports).

Three deterministic, auditable services back the Change-Window Risk Brief workflow (fully deterministic —
no LLM is used anywhere in this template; brief text is templated from grounded rubric findings):

- ``AssetImpactKB``  — seeded telecom NW element tiers (core / transport / BNG / aggregation / RAN /
  access / CPE) + downstream dependencies; classifies each target asset's criticality tier.
- ``ChangeControlRubric`` — deterministic rubric that scores a firmware change across rollback
  completeness / dependency coupling / blast radius / customer impact / maintenance-window validity into
  severity-tagged findings.
- ``Redactor`` — deterministic secret / PII redaction + prompt-injection-marker neutralization, applied
  at S-1 (before change content persists to State) and again at S-3 (before it surfaces). Redacts
  credential-shaped tokens, My-Number (12-digit), phone numbers (JP / international) and email addresses
  deterministically; personal names are best-effort (contact / owner / approver / 担当 / 氏名 labels only —
  no NER, no LLM, so free-standing names in prose are not detected — acceptable as the brief is advisory).
- ``safe_identifier`` — caller identifier privacy tokenizer. Every caller-supplied identifier
  (``asset_id`` / ``change_id``) is UNCONDITIONALLY tokenized to a deterministic opaque surrogate — no
  syntactic allowlist — so a bare name in an id field (``Alice`` / ``TaroYamada`` / ``John.Smith``, no
  spaces / no label, which secret- and labelled-name redaction cannot catch) can never leak into a
  citation, the asset / window summary, or the output.

Advisory / read-only: nothing here schedules, deploys, or executes a change — it evaluates an *ex-ante*
change package and produces evidence for an authorized human (CAB / change manager).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, cast

# ── caller-identifier privacy tokenize (a name / secret in an id field can never surface) ──────────
# Two SEPARATE concerns — do not conflate:
#   PRIVACY (safe_identifier): every caller identifier (asset_id / change_id) is UNCONDITIONALLY
#     tokenized to a deterministic opaque surrogate `id:<sha8>` — there is NO syntactic passthrough — so a
#     bare name (`Alice` / `TaroYamada` / `John.Smith`, no spaces / no label, uncatchable by secret- or
#     labelled-name redaction) AND a caller value merely *shaped* like a surrogate (`id:deadbeef`) are both
#     re-hashed; neither can leak into a citation, the asset / window summary, or the output, nor forge an
#     internal join key.
#   PROVENANCE (citations): NOT caller-supplied. Citations are internal, grounded refs into the seeded
#     AssetImpactKB / ChangeControlRubric only (whitelist-by-construction) — a caller `source` field is
#     never copied and never becomes a citation, so there is no forged-surrogate provenance vector here.
# Tokenization is unconditional — a value already shaped like a surrogate is re-hashed, never trusted. The
# same input still maps to the same surrogate within one invocation, so asset_id stays a joinable label.


def _sha8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def safe_identifier(value: Any) -> str:
    """PRIVACY-tokenize a caller identifier to a deterministic opaque surrogate ``id:<sha8>``.

    Unconditional — no syntactic allowlist / no passthrough — so a name (with or without spaces /
    punctuation) AND a caller value merely *shaped* like a surrogate (``id:deadbeef``) are both re-hashed;
    neither can survive into a citation, the asset / window summary, or the output, nor forge an internal
    join key. Same input → same surrogate within one invocation (asset_id stays a joinable label). This is
    a privacy measure only; it asserts nothing about the identifier's authenticity.
    """
    return "id:" + _sha8(str(value or "").strip())


# ── S-1/S-3 redaction (deterministic; secrets + My-Number + phone + email + best-effort name) ──────
# Japanese My-Number (個人番号): any bare 12-digit run a change note may inadvertently carry.
_MY_NUMBER = re.compile(r"(?<!\d)\d{12}(?!\d)")
# Credential-shaped tokens. Prefixes are concatenated so this file carries no literal key material.
_CRED_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*\S+"),
    re.compile(r"\b" + "AKIA" + r"[0-9A-Z]{16}\b"),  # AWS access-key id shape
    re.compile(r"(?i)\b" + "sk" + r"-[A-Za-z0-9]{16,}"),  # provider secret-key shape
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"),  # bearer credential
    re.compile(r"\b" + "eyJ" + r"[A-Za-z0-9._\-]{12,}"),  # JWT header shape
)
# Email addresses.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,3}\.[A-Za-z]{2,24}")
# Phone numbers — JP mobile / landline / international. Deliberately conservative so it does NOT clobber
# IP addresses (dot-separated), maintenance-window times (colon-separated), version strings or numeric
# asset IDs: matches only (a) a dash/space-separated 3-group phone that starts with a leading 0 or +81,
# or (b) a bare 11-digit Japanese mobile run (0[789]0 + 8 digits).
_PHONE_PATTERNS = (
    re.compile(r"(?<![\d.\-])(?:\+81[-\s]?|0)\d{1,4}[-\s]\d{1,4}[-\s]\d{3,4}(?![\d.\-])"),
    re.compile(r"(?<!\d)0[789]0\d{8}(?!\d)"),
)
# Best-effort personal-name redaction (deterministic, no NER / no LLM): a value carried after a
# contact / owner / approver / 担当 / 氏名 label ("担当: 山田太郎", "owner: John Smith"). The label word is
# kept and only its value (bounded, up to a delimiter / newline) is masked. A leading `\w`/`-`/`<` before
# the label is excluded so seeded placeholders such as "<risk-owner: TBD (CAB)>" are NOT mangled.
# Free-standing names in prose (no label) are NOT detected — acceptable as the brief is advisory and
# any residual identifier is re-redacted at S-3.
_NAME_LABEL = re.compile(
    r"(?<![\w\-<])(担当者|担当|氏名|名前|承認者|申請者|approver|owner|contact|assignee|responsible)"
    r"(\s*[:：]\s*)([^\n,;、。]{1,40})",
    re.IGNORECASE,
)
_SECRET_MASK = "[REDACTED]"
_MY_NUMBER_MASK = "[MY-NUMBER-REDACTED]"
_EMAIL_MASK = "[EMAIL-REDACTED]"
_PHONE_MASK = "[PHONE-REDACTED]"
_NAME_MASK = "[NAME-REDACTED]"

# Prompt-injection markers are neutralized (not rejected) at the S-3 output boundary, because the brief
# is fully grounded in deterministic classification + rubric — an injected instruction cannot alter the
# deterministic output, so echoing it back verbatim is the only residual risk.
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the above",
    "disregard previous",
    "system prompt",
    "you are now",
    "###system",
    "<|im_start|>",
    "override the rollback",
)
_INJECTION_MASK = "[neutralized]"


class Redactor:
    """Deterministic secret / PII redaction and injection-marker neutralization."""

    @staticmethod
    def redact_secrets(text: str) -> str:
        """Redact secrets + PII (S-1 before persist / S-3 before surface) — deterministic, no LLM.

        Applied in order: My-Number (12-digit) → email → phone (JP / international) → credential-shaped
        tokens → best-effort personal names (contact / owner / approver / 担当 / 氏名 labels). Personal-name
        coverage is best-effort only (label-anchored; no NER / no LLM), so free-standing names in prose
        are not detected — acceptable because the brief is advisory and re-redacted at S-3.
        """
        if not text:
            return text
        out = _MY_NUMBER.sub(_MY_NUMBER_MASK, text)
        out = _EMAIL.sub(_EMAIL_MASK, out)
        for pat in _PHONE_PATTERNS:
            out = pat.sub(_PHONE_MASK, out)
        for pat in _CRED_PATTERNS:
            out = pat.sub(_SECRET_MASK, out)
        out = _NAME_LABEL.sub(lambda m: f"{m.group(1)}{m.group(2)}{_NAME_MASK}", out)
        return out

    @staticmethod
    def neutralize_injection(text: str) -> str:
        """Neutralize prompt-injection markers in echoed change text (S-3 output boundary)."""
        if not text:
            return text
        out = text
        for marker in _INJECTION_MARKERS:
            out = re.sub(re.escape(marker), _INJECTION_MASK, out, flags=re.IGNORECASE)
        return out

    @classmethod
    def scrub(cls, value: Any) -> Any:
        """Recursively redact secrets + neutralize injection across a JSON-like structure (S-3)."""
        if isinstance(value, str):
            return cls.neutralize_injection(cls.redact_secrets(value))
        if isinstance(value, list):
            return [cls.scrub(v) for v in value]
        if isinstance(value, dict):
            return {k: cls.scrub(v) for k, v in value.items()}
        return value


# ── seeded telecom NW asset-impact KB (criticality tier + downstream dependencies) ────────────────
# Each tier record: {tier, criticality, blast_radius, dependencies[], source}. Sourced from public
# telecom NW topology conventions (3GPP EPC/5GC element roles, metro/access aggregation) — no PII.
_TIER_DB: dict[str, dict[str, Any]] = {
    "core": {
        "tier": "T1-core",
        "criticality": 5,
        "blast_radius": "network-wide",
        "dependencies": ["all subscriber sessions", "signaling/control plane", "downstream aggregation + RAN"],
        "source": "AssetImpactKB §core (5GC/EPC control+user plane)",
    },
    "transport": {
        "tier": "T1-transport",
        "criticality": 5,
        "blast_radius": "multi-region backbone",
        "dependencies": ["optical/MPLS backbone", "multiple downstream metro domains"],
        "source": "AssetImpactKB §transport (DWDM/OTN/MPLS backbone)",
    },
    "bng": {
        "tier": "T1-edge",
        "criticality": 4,
        "blast_radius": "regional broadband",
        "dependencies": ["broadband subscriber sessions", "PPPoE/IPoE termination", "downstream access"],
        "source": "AssetImpactKB §bng (BNG/BRAS edge)",
    },
    "aggregation": {
        "tier": "T2-aggregation",
        "criticality": 3,
        "blast_radius": "metro/regional",
        "dependencies": ["downstream access nodes", "metro traffic aggregation"],
        "source": "AssetImpactKB §aggregation (metro/aggregation router)",
    },
    "ran": {
        "tier": "T2-ran",
        "criticality": 3,
        "blast_radius": "coverage area",
        "dependencies": ["attached cells and UEs in coverage area"],
        "source": "AssetImpactKB §ran (eNodeB/gNodeB/BBU)",
    },
    "access": {
        "tier": "T3-access",
        "criticality": 2,
        "blast_radius": "access segment",
        "dependencies": ["directly attached subscribers on the access node"],
        "source": "AssetImpactKB §access (OLT/DSLAM/cell-site router)",
    },
    "cpe": {
        "tier": "T4-cpe",
        "criticality": 1,
        "blast_radius": "single premise",
        "dependencies": ["single premise / subscriber"],
        "source": "AssetImpactKB §cpe (ONT/ONU/home gateway)",
    },
}

# keyword → canonical asset_type (case-insensitive substring match over asset_type / name).
_ASSET_ALIASES: tuple[tuple[str, str], ...] = (
    ("5gc", "core"),
    ("epc", "core"),
    ("amf", "core"),
    ("smf", "core"),
    ("upf", "core"),
    ("mme", "core"),
    ("pgw", "core"),
    ("sgw", "core"),
    ("hss", "core"),
    ("udm", "core"),
    ("コア", "core"),
    ("core", "core"),
    ("dwdm", "transport"),
    ("otn", "transport"),
    ("mpls", "transport"),
    ("伝送", "transport"),
    ("backbone", "transport"),
    ("transport", "transport"),
    ("bng", "bng"),
    ("bras", "bng"),
    ("aggregation", "aggregation"),
    ("aggr", "aggregation"),
    ("metro", "aggregation"),
    ("集約", "aggregation"),
    ("gnodeb", "ran"),
    ("gnb", "ran"),
    ("enodeb", "ran"),
    ("enb", "ran"),
    ("bbu", "ran"),
    ("基地局", "ran"),
    ("ran", "ran"),
    ("radio", "ran"),
    ("olt", "access"),
    ("dslam", "access"),
    ("access", "access"),
    ("アクセス", "access"),
    ("ont", "cpe"),
    ("onu", "cpe"),
    ("cpe", "cpe"),
    ("宅内", "cpe"),
    ("home gateway", "cpe"),
)

_TIER_RANK = {
    "T1-core": 5,
    "T1-transport": 5,
    "T1-edge": 4,
    "T2-aggregation": 3,
    "T2-ran": 3,
    "T3-access": 2,
    "T4-cpe": 1,
}


class AssetImpactKB:
    """Deterministic asset criticality-tier + dependency classification."""

    @staticmethod
    def _match_type(*hints: str) -> str | None:
        for hint in hints:
            low = (hint or "").lower()
            for kw, canon in _ASSET_ALIASES:
                if kw in low:
                    return canon
        return None

    @classmethod
    def classify(cls, assets: list[Any]) -> list[dict[str, Any]]:
        """Classify each asset's criticality tier + downstream dependencies.

        Unrecognized asset types are classified conservatively as ``T3-access`` (unknown → treat as a
        real, non-trivial node) with an ``unknown_type`` flag so the rubric can surface the ambiguity.
        """
        out: list[dict[str, Any]] = []
        for i, a in enumerate(assets or []):
            if isinstance(a, str):
                a = {"asset_id": f"asset-{i + 1}", "asset_type": a, "name": a}
            if not isinstance(a, dict):
                continue
            # Privacy: the asset_id primary key is UNCONDITIONALLY tokenized to an opaque surrogate (no
            # syntactic passthrough — an already-tokenized id from pre_process is re-hashed, a harmless
            # deterministic double-hash label within this invocation) so a caller name / secret in the id
            # can never reach classified_assets → the brief → a citation → the output.
            asset_id = safe_identifier(str(a.get("asset_id") or a.get("id") or f"asset-{i + 1}"))
            declared = str(a.get("asset_type") or a.get("type") or "")
            name = str(a.get("name") or "")
            canon = cls._match_type(declared, name)
            unknown = canon is None
            rec: Any = _TIER_DB.get(canon or "access")
            out.append(
                {
                    "asset_id": asset_id,
                    "asset_type": canon or (declared or "unknown"),
                    "criticality_tier": rec["tier"],
                    "criticality": rec["criticality"],
                    "blast_radius": rec["blast_radius"],
                    "dependencies": list(rec["dependencies"]),
                    "unknown_type": unknown,
                    "source": rec["source"],
                }
            )
        return out

    @staticmethod
    def max_tier(classified: list[dict[str, Any]]) -> str:
        if not classified:
            return "T4-cpe"
        return cast(str, max((c["criticality_tier"] for c in classified), key=lambda t: _TIER_RANK.get(t, 0)))

    @staticmethod
    def tier_rank(tier: str) -> int:
        return _TIER_RANK.get(tier, 0)


# ── low-traffic maintenance window bounds (conventional overnight NW change window, JST) ──────────
_LOW_TRAFFIC_START_HOUR = 0
_LOW_TRAFFIC_END_HOUR = 5
_MIN_ROLLBACK_MINUTES = 60


class ChangeControlRubric:
    """Deterministic rubric — severity-tagged findings across five change-risk dimensions."""

    RUBRIC = "ChangeControlRubric"

    # ── maintenance-window assessment ────────────────────────────────────────
    @classmethod
    def assess_window(cls, window: dict[str, Any], rollback_present: bool) -> dict[str, Any]:
        window = window if isinstance(window, dict) else {}
        low = window.get("low_traffic")
        start_hour = cls._hour(window.get("start"))
        if low is None:
            low = start_hour is not None and _LOW_TRAFFIC_START_HOUR <= start_hour < _LOW_TRAFFIC_END_HOUR
        duration = window.get("duration_minutes")
        if duration is None:
            duration = cls._duration_minutes(window.get("start"), window.get("end"))
        if duration is None:
            adequate: bool | None = None  # unknown — cannot confirm rollback headroom
        else:
            adequate = bool(rollback_present) and duration >= _MIN_ROLLBACK_MINUTES
        # Whitelist-by-construction: echo only the recognized window fields — never the raw caller dict,
        # which could carry an arbitrary extra key (e.g. a free-text `note` with PII). Recognized string
        # leaves were already S-1 hygiene-redacted and are re-scrubbed at S-3.
        return {
            "window": {
                "start": window.get("start"),
                "end": window.get("end"),
                "low_traffic": window.get("low_traffic"),
                "duration_minutes": duration,
            },
            "within_low_traffic": bool(low),
            "duration_minutes": duration,
            "adequate_for_rollback": adequate,
            "note": (
                "duration unknown — cannot confirm rollback headroom"
                if duration is None
                else ("within low-traffic window" if low else "outside low-traffic window")
            ),
        }

    # ── five-dimension rubric ────────────────────────────────────────────────
    @classmethod
    def evaluate(
        cls, classified: list[dict[str, Any]], window_assessment: dict[str, Any], change_pkg: dict[str, Any]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        max_tier = AssetImpactKB.max_tier(classified)
        rank = AssetImpactKB.tier_rank(max_tier)
        t1_count = sum(1 for c in classified if c["criticality_tier"].startswith("T1"))
        rollback = str(change_pkg.get("rollback_plan") or "").strip()
        criteria = str(change_pkg.get("customer_impact_criteria") or "").strip()

        # 1 — rollback completeness
        if not rollback:
            findings.append(
                cls._f("rollback_completeness", "high", "No rollback plan supplied in the change package.", "rollback")
            )
        elif window_assessment.get("adequate_for_rollback") is False:
            findings.append(
                cls._f(
                    "rollback_completeness",
                    "medium",
                    "Rollback plan present but the maintenance window may be too short to "
                    "execute it (duration < required headroom).",
                    "rollback",
                )
            )
        elif window_assessment.get("adequate_for_rollback") is None:
            findings.append(
                cls._f(
                    "rollback_completeness",
                    "medium",
                    "Rollback plan present but window duration is undocumented — rollback "
                    "headroom cannot be confirmed.",
                    "rollback",
                )
            )
        else:
            findings.append(
                cls._f(
                    "rollback_completeness", "low", "Rollback plan present with adequate window headroom.", "rollback"
                )
            )

        # 2 — dependency coupling
        if rank >= 5:
            findings.append(
                cls._f(
                    "dependency_coupling",
                    "high",
                    f"Change touches {max_tier} assets with broad downstream coupling "
                    f"({t1_count} tier-1 asset(s)).",
                    "dependency",
                )
            )
        elif rank == 4 or t1_count >= 1:
            findings.append(
                cls._f(
                    "dependency_coupling",
                    "medium",
                    f"Change touches high-coupling assets (max {max_tier}).",
                    "dependency",
                )
            )
        else:
            findings.append(
                cls._f("dependency_coupling", "low", f"Downstream coupling limited (max {max_tier}).", "dependency")
            )

        # 3 — blast radius
        if rank >= 5 or t1_count >= 2:
            findings.append(
                cls._f(
                    "blast_radius",
                    "high",
                    f"Potential blast radius is network-/backbone-wide (max {max_tier}, "
                    f"{t1_count} tier-1 asset(s)).",
                    "blast_radius",
                )
            )
        elif rank in (3, 4):
            findings.append(
                cls._f(
                    "blast_radius",
                    "medium",
                    f"Blast radius is regional/coverage-scoped (max {max_tier}).",
                    "blast_radius",
                )
            )
        else:
            findings.append(
                cls._f(
                    "blast_radius", "low", f"Blast radius is access-/premise-local (max {max_tier}).", "blast_radius"
                )
            )

        # 4 — customer impact
        if not criteria:
            findings.append(
                cls._f(
                    "customer_impact",
                    "medium",
                    "Customer-impact criteria not documented in the change package.",
                    "customer_impact",
                )
            )
        elif rank >= 4:
            findings.append(
                cls._f(
                    "customer_impact",
                    "high",
                    "Documented criteria plus tier-1 exposure imply significant customer "
                    "impact if the change regresses.",
                    "customer_impact",
                )
            )
        else:
            findings.append(
                cls._f(
                    "customer_impact",
                    "low",
                    "Customer-impact criteria documented; exposure is bounded.",
                    "customer_impact",
                )
            )

        # 5 — window validity
        if not window_assessment.get("within_low_traffic"):
            findings.append(
                cls._f(
                    "window_validity",
                    "high" if rank >= 4 else "medium",
                    "Maintenance window is outside the conventional low-traffic band.",
                    "window",
                )
            )
        else:
            findings.append(
                cls._f("window_validity", "low", "Maintenance window is within the low-traffic band.", "window")
            )

        # unknown asset types — surface as an explicit finding (do not silently pass)
        unknown = [c["asset_id"] for c in classified if c.get("unknown_type")]
        if unknown:
            findings.append(
                cls._f(
                    "dependency_coupling",
                    "medium",
                    f"Asset type could not be classified for {len(unknown)} asset(s) "
                    f"{unknown} — treated conservatively as access-tier; verify manually.",
                    "dependency",
                )
            )
        return findings

    @classmethod
    def _f(cls, dimension: str, severity: str, detail: str, section: str) -> dict[str, Any]:
        return {"dimension": dimension, "severity": severity, "detail": detail, "citation": f"{cls.RUBRIC} §{section}"}

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _hour(value: Any) -> int | None:
        if value is None:
            return None
        m = re.search(r"(?:^|[T\s])(\d{1,2}):\d{2}", str(value))
        if m:
            h = int(m.group(1))
            return h if 0 <= h <= 23 else None
        return None

    @classmethod
    def _duration_minutes(cls, start: Any, end: Any) -> int | None:
        sh, eh = cls._hour(start), cls._hour(end)
        sm, em = cls._minute(start), cls._minute(end)
        if sh is None or eh is None:
            return None
        delta = (eh * 60 + (em or 0)) - (sh * 60 + (sm or 0))
        if delta < 0:
            delta += 24 * 60  # window crosses midnight
        return delta

    @staticmethod
    def _minute(value: Any) -> int | None:
        if value is None:
            return None
        m = re.search(r"\d{1,2}:(\d{2})", str(value))
        return int(m.group(1)) if m else None
