"""Deterministic recommendation baseline engine for Module 4.

Ranks and proposes benign prototype actions based on risk, confidence, freshness,
and resource constraints.

CRITICAL INVARIANT:
The engine generates PROPOSALS ONLY and NEVER executes any action.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from services.approval.contracts import (
    AllowedAction,
    DomainAlert,
    Recommendation,
    RecommendationStatus,
)
from services.approval.evidence import compute_evidence_hash


@dataclass(frozen=True)
class ResourceConstraints:
    """Configurable prototype resource availability flags."""
    allow_inspect_area: bool = True
    allow_verify_equipment: bool = True
    allow_request_observation: bool = True
    max_active_inspections: int = 5


# Deterministic risk weight mapping
RISK_WEIGHTS: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
}


def _calculate_freshness_score(valid_until_str: str, reference_time_iso: str | None = None) -> float:
    """Calculate normalized freshness score [0.0, 1.0].

    If reference_time is not provided, parses valid_until to gauge validity window.
    Higher score indicates greater remaining freshness before expiration.
    """
    try:
        # Standard ISO-8601 parsing
        vu_dt = datetime.fromisoformat(valid_until_str.replace("Z", "+00:00"))
        if reference_time_iso:
            ref_dt = datetime.fromisoformat(reference_time_iso.replace("Z", "+00:00"))
        else:
            # Deterministic default reference: if not provided, assume reference is valid
            return 1.0

        remaining_seconds = (vu_dt - ref_dt).total_seconds()
        if remaining_seconds <= 0:
            return 0.0
        # Normalize: 3600 seconds (1 hour) or more counts as full freshness 1.0
        return min(1.0, max(0.0, remaining_seconds / 3600.0))
    except Exception:
        return 0.5


def rank_and_generate_recommendation(
    alerts: Sequence[DomainAlert] | DomainAlert,
    *,
    policy_version: str = "1.0.0",
    constraints: ResourceConstraints | None = None,
    reference_time_iso: str | None = None,
    recommendation_id: str | None = None,
    status: str = RecommendationStatus.PENDING_REVIEW.value,
) -> Recommendation:
    """Generate a ranked, deterministic recommendation proposal from DomainAlerts.

    CRITICAL INVARIANT:
    This function generates a PROPOSAL only. It returns a Recommendation data object
    and does NOT perform, trigger, dispatch, or execute any operational action.
    """
    if isinstance(alerts, DomainAlert):
        alert_list = [alerts]
    else:
        alert_list = list(alerts)

    if not alert_list:
        raise ValueError("Cannot generate recommendation for empty alerts.")

    if constraints is None:
        constraints = ResourceConstraints()

    # Sort alerts deterministically
    sorted_alerts = sorted(alert_list, key=lambda a: a.alert_id)
    alert_ids = [a.alert_id for a in sorted_alerts]

    # Aggregate alert metrics deterministically
    max_risk_weight = max(RISK_WEIGHTS.get(a.risk_level.upper(), 0.2) for a in sorted_alerts)
    avg_confidence = sum(a.confidence for a in sorted_alerts) / len(sorted_alerts)
    total_missing_evidence = sum(len(a.missing_evidence) for a in sorted_alerts)
    min_valid_until = min(a.valid_until for a in sorted_alerts)

    freshness_score = _calculate_freshness_score(min_valid_until, reference_time_iso)

    # Compute candidate action scores deterministically
    # 1. Inspect Area: Favored when risk is high, confidence is high, and resource allowed
    score_inspect = 0.0
    if constraints.allow_inspect_area:
        score_inspect = (0.45 * max_risk_weight) + (0.35 * avg_confidence) + (0.20 * freshness_score)
        if total_missing_evidence > 0:
            score_inspect -= 0.15  # Penalize if critical evidence is missing

    # 2. Verify Equipment: Favored for medium/high risk when equipment/sensors may be faulty
    score_verify = 0.0
    if constraints.allow_verify_equipment:
        has_sensor_mention = any(
            "sensor" in a.explanation.lower() or "equipment" in a.explanation.lower()
            for a in sorted_alerts
        )
        bonus = 0.25 if has_sensor_mention else 0.0
        score_verify = (0.35 * max_risk_weight) + (0.30 * avg_confidence) + (0.15 * freshness_score) + bonus

    # 3. Request Another Observation: Favored when evidence is missing or confidence is low
    score_request_obs = 0.0
    if constraints.allow_request_observation:
        obs_bonus = min(0.40, total_missing_evidence * 0.20)
        low_confidence_bonus = max(0.0, (0.75 - avg_confidence) * 0.5)
        score_request_obs = (0.30 * max_risk_weight) + obs_bonus + low_confidence_bonus + (0.15 * freshness_score)

    # 4. Dismiss Alert: Favored when risk is low and confidence is low/insignificant
    score_dismiss = (0.60 * (1.0 - max_risk_weight)) + (0.40 * (1.0 - avg_confidence))

    scored_actions = [
        (score_inspect, AllowedAction.INSPECT_AREA.value),
        (score_verify, AllowedAction.VERIFY_EQUIPMENT.value),
        (score_request_obs, AllowedAction.REQUEST_ANOTHER_OBSERVATION.value),
        (score_dismiss, AllowedAction.DISMISS_ALERT.value),
    ]

    # Deterministic sorting: highest score first; tiebreak alphabetically on action name
    scored_actions.sort(key=lambda item: (-round(item[0], 6), item[1]))
    top_score, selected_action = scored_actions[0]

    # Build deterministic rationale
    rationale = (
        f"Selected '{selected_action}' (score={top_score:.3f}). "
        f"Aggregated metrics: max_risk={max_risk_weight:.2f}, avg_confidence={avg_confidence:.2f}, "
        f"freshness={freshness_score:.2f}, missing_evidence_count={total_missing_evidence}."
    )

    # Compute evidence hash
    ev_hash = compute_evidence_hash(sorted_alerts)

    # Deterministic recommendation_id derivation if not supplied
    if recommendation_id is None:
        seed = f"{ev_hash}:{policy_version}:{selected_action}"
        digest_suffix = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
        recommendation_id = f"REC-{digest_suffix}"

    return Recommendation(
        recommendation_id=recommendation_id,
        alert_ids=alert_ids,
        proposed_task=selected_action,
        rationale=rationale,
        evidence_hash=ev_hash,
        policy_version=policy_version,
        status=status,
        valid_until=min_valid_until,
    )
