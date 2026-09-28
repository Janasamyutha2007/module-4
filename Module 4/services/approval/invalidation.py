"""Invalidation logic for Module 4.

Monitors approved recommendations and invalidates them if:
1. Evidence changes.
2. Recommendation/proposed task or content changes.
3. Policy version changes.
4. Validity window changes.

CRITICAL INVARIANTS:
- Invalidation transitions use the existing state machine.
- Previous approval information is preserved for traceability.
- Requires an explicit new review/approval cycle (Invalidated -> Pending Review).
- Never silently preserves or executes an outdated approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from services.approval.contracts import (
    ApprovalDecision,
    DomainAlert,
    Recommendation,
    RecommendationStatus,
)
from services.approval.evidence import (
    compute_evidence_hash,
    compute_recommendation_hash,
)
from services.approval.state_machine import apply_transition


@dataclass(frozen=True)
class InvalidationRecord:
    """Audit record capturing the invalidation event and preserving prior approval."""
    recommendation_id: str
    invalidation_reason: str
    previous_approval: ApprovalDecision
    invalidated_at: str
    original_evidence_hash: str
    new_evidence_hash: Optional[str]
    original_recommendation_hash: str
    new_recommendation_hash: str


@dataclass(frozen=True)
class InvalidationResult:
    """Outcome of invalidation evaluation."""
    is_invalidated: bool
    reason: str
    recommendation: Recommendation
    invalidation_record: Optional[InvalidationRecord] = None


class InvalidationDetector:
    """Monitors and applies invalidation on approved recommendations."""

    def __init__(self) -> None:
        # History map: recommendation_id -> list of InvalidationRecords
        self._history: dict[str, list[InvalidationRecord]] = {}

    def get_invalidation_history(self, recommendation_id: str) -> list[InvalidationRecord]:
        """Retrieve audit history of invalidations for a recommendation."""
        return list(self._history.get(recommendation_id, []))

    def get_last_invalidation(self, recommendation_id: str) -> Optional[InvalidationRecord]:
        """Retrieve most recent invalidation record for a recommendation."""
        history = self._history.get(recommendation_id, [])
        return history[-1] if history else None

    def check_and_apply_invalidation(
        self,
        recommendation: Recommendation,
        previous_approval: ApprovalDecision,
        *,
        current_alerts: Optional[Sequence[DomainAlert]] = None,
        new_proposed_task: Optional[str] = None,
        new_rationale: Optional[str] = None,
        new_policy_version: Optional[str] = None,
        new_valid_until: Optional[str] = None,
        new_evidence_hash: Optional[str] = None,
        invalidated_at_iso: Optional[str] = None,
    ) -> InvalidationResult:
        """Evaluate if an approved recommendation has become invalid.

        If any approval-bound attribute has changed:
        - transitions state to 'Invalidated' via existing state machine
        - preserves previous approval metadata
        - marks requirement for new review cycle
        """
        # If already Invalidated, handle deterministically
        if recommendation.status == RecommendationStatus.INVALIDATED.value:
            return InvalidationResult(
                is_invalidated=False,
                reason="Recommendation is already in Invalidated state.",
                recommendation=recommendation,
                invalidation_record=self.get_last_invalidation(recommendation.recommendation_id),
            )

        # Invalidation only applies to Approved recommendations
        if recommendation.status != RecommendationStatus.APPROVED.value:
            return InvalidationResult(
                is_invalidated=False,
                reason=f"Recommendation status is '{recommendation.status}'; invalidation only triggers on Approved recommendations.",
                recommendation=recommendation,
            )

        # Determine effective new evidence hash
        effective_new_evidence_hash = recommendation.evidence_hash
        if new_evidence_hash is not None:
            effective_new_evidence_hash = new_evidence_hash
        elif current_alerts is not None:
            effective_new_evidence_hash = compute_evidence_hash(current_alerts)

        effective_new_task = new_proposed_task if new_proposed_task is not None else recommendation.proposed_task
        effective_new_rationale = new_rationale if new_rationale is not None else recommendation.rationale
        effective_new_policy_ver = new_policy_version if new_policy_version is not None else recommendation.policy_version
        effective_new_valid_until = new_valid_until if new_valid_until is not None else recommendation.valid_until

        # Detect changes
        reasons: list[str] = []
        if effective_new_evidence_hash != recommendation.evidence_hash:
            reasons.append(
                f"Evidence changed: original '{recommendation.evidence_hash}' != new '{effective_new_evidence_hash}'"
            )
        if effective_new_task != recommendation.proposed_task:
            reasons.append(
                f"Proposed task changed: original '{recommendation.proposed_task}' != new '{effective_new_task}'"
            )
        if effective_new_rationale != recommendation.rationale:
            reasons.append("Recommendation rationale changed.")
        if effective_new_policy_ver != recommendation.policy_version:
            reasons.append(
                f"Policy version changed: original '{recommendation.policy_version}' != new '{effective_new_policy_ver}'"
            )
        if effective_new_valid_until != recommendation.valid_until:
            reasons.append(
                f"Validity window changed: original '{recommendation.valid_until}' != new '{effective_new_valid_until}'"
            )

        # If no changes detected, approval remains valid
        if not reasons:
            return InvalidationResult(
                is_invalidated=False,
                reason="No approval-bound changes detected. Existing approval remains valid.",
                recommendation=recommendation,
            )

        # Changes detected -> Compute internal recommendation hashes
        orig_rec_hash = compute_recommendation_hash(recommendation)
        new_rec_hash = compute_recommendation_hash(
            proposed_task=effective_new_task,
            rationale=effective_new_rationale,
            valid_until=effective_new_valid_until,
            evidence_hash=effective_new_evidence_hash,
            policy_version=effective_new_policy_ver,
        )

        invalidation_time = (
            invalidated_at_iso
            if invalidated_at_iso is not None
            else datetime.now(timezone.utc).isoformat()
        )
        combined_reason = "; ".join(reasons)

        # Transition strictly through the existing state machine
        invalidated_rec = apply_transition(
            recommendation,
            RecommendationStatus.INVALIDATED.value,
        )

        # Preserve previous approval record
        record = InvalidationRecord(
            recommendation_id=recommendation.recommendation_id,
            invalidation_reason=combined_reason,
            previous_approval=previous_approval,
            invalidated_at=invalidation_time,
            original_evidence_hash=recommendation.evidence_hash,
            new_evidence_hash=effective_new_evidence_hash,
            original_recommendation_hash=orig_rec_hash,
            new_recommendation_hash=new_rec_hash,
        )

        self._history.setdefault(recommendation.recommendation_id, []).append(record)

        return InvalidationResult(
            is_invalidated=True,
            reason=f"Approval invalidated: {combined_reason}",
            recommendation=invalidated_rec,
            invalidation_record=record,
        )

    def reinitiate_review_cycle(self, invalidated_recommendation: Recommendation) -> Recommendation:
        """Explicitly restart review cycle: Invalidated -> Pending Review.

        Enforces that a new human approval cycle is required and rejects direct execution.
        """
        return apply_transition(
            invalidated_recommendation,
            RecommendationStatus.PENDING_REVIEW.value,
        )
