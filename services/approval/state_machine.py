"""Deterministic state machine for Recommendation lifecycle in Module 4.

Enforces valid transitions among:
  Draft
  Pending Review
  Approved
  Rejected
  Expired
  Invalidated
  Completed

CRITICAL INVARIANTS:
1. No recommendation can become Approved without a valid human ApprovalDecision.
2. Terminal states (Completed, Rejected, Expired) are immutable.
3. No invalid transition is silently accepted.
4. Transitions are 100% deterministic.
"""

from __future__ import annotations

from typing import Optional

from services.approval.contracts import (
    ApprovalDecision,
    DecisionType,
    Recommendation,
    RecommendationStatus,
)


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal or unsupported state transition is attempted."""
    pass


class TerminalStateError(InvalidStateTransitionError):
    """Raised when attempting to transition out of a terminal state."""
    pass


# Terminal states that cannot transition further
TERMINAL_STATES = frozenset({
    RecommendationStatus.COMPLETED.value,
    RecommendationStatus.REJECTED.value,
    RecommendationStatus.EXPIRED.value,
})

# Allowed base state transitions graph
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    RecommendationStatus.DRAFT.value: frozenset({
        RecommendationStatus.PENDING_REVIEW.value,
    }),
    RecommendationStatus.PENDING_REVIEW.value: frozenset({
        RecommendationStatus.APPROVED.value,
        RecommendationStatus.REJECTED.value,
        RecommendationStatus.EXPIRED.value,
    }),
    RecommendationStatus.APPROVED.value: frozenset({
        RecommendationStatus.COMPLETED.value,
        RecommendationStatus.INVALIDATED.value,
    }),
    RecommendationStatus.INVALIDATED.value: frozenset({
        RecommendationStatus.PENDING_REVIEW.value,
    }),
    RecommendationStatus.REJECTED.value: frozenset(),
    RecommendationStatus.EXPIRED.value: frozenset(),
    RecommendationStatus.COMPLETED.value: frozenset(),
}


def validate_transition(
    current_status: str,
    target_status: str,
    *,
    approval_decision: Optional[ApprovalDecision] = None,
) -> None:
    """Validate whether transitioning from current_status to target_status is permitted.

    Raises:
        TerminalStateError: If current_status is a terminal state.
        InvalidStateTransitionError: If the transition is illegal or invariants are violated.
    """
    if current_status not in RecommendationStatus.values():
        raise InvalidStateTransitionError(f"Unknown current status: '{current_status}'.")
    if target_status not in RecommendationStatus.values():
        raise InvalidStateTransitionError(f"Unknown target status: '{target_status}'.")

    # Invariant: Terminal states cannot be altered
    if current_status in TERMINAL_STATES:
        raise TerminalStateError(
            f"Cannot transition from terminal state '{current_status}' to '{target_status}'."
        )

    # Invariant: Must follow valid transitions graph
    allowed_targets = VALID_TRANSITIONS.get(current_status, frozenset())
    if target_status not in allowed_targets:
        raise InvalidStateTransitionError(
            f"Illegal transition: '{current_status}' -> '{target_status}'. "
            f"Permitted targets from '{current_status}': {sorted(allowed_targets) or 'None'}."
        )

    # Invariant: Transition to Approved REQUIRES a valid human ApprovalDecision with decision == APPROVED
    if target_status == RecommendationStatus.APPROVED.value:
        if approval_decision is None:
            raise InvalidStateTransitionError(
                "Transition to 'Approved' is strictly forbidden without a valid human ApprovalDecision."
            )
        if approval_decision.decision != DecisionType.APPROVED.value:
            raise InvalidStateTransitionError(
                f"Cannot transition to 'Approved' with decision '{approval_decision.decision}'."
            )


def apply_transition(
    recommendation: Recommendation,
    target_status: str,
    *,
    approval_decision: Optional[ApprovalDecision] = None,
) -> Recommendation:
    """Deterministically transition a recommendation to a target status.

    Returns a new Recommendation instance with updated status.
    Guarantees no state transitions occur if validation fails.
    """
    validate_transition(
        recommendation.status,
        target_status,
        approval_decision=approval_decision,
    )

    return Recommendation(
        recommendation_id=recommendation.recommendation_id,
        alert_ids=list(recommendation.alert_ids),
        proposed_task=recommendation.proposed_task,
        rationale=recommendation.rationale,
        evidence_hash=recommendation.evidence_hash,
        policy_version=recommendation.policy_version,
        status=target_status,
        valid_until=recommendation.valid_until,
    )
