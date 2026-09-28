"""Human Approval Validation for Module 4.

Validates incoming human operator ApprovalDecision against the active Recommendation,
its evidence binding, role authorization, freshness/expiration, replay prevention,
and enforces valid transitions strictly through the state machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Set

from services.approval.auth import ConfigurableAuthorizationPolicy
from services.approval.contracts import (
    ApprovalDecision,
    DecisionType,
    Recommendation,
    RecommendationStatus,
)
from services.approval.state_machine import (
    TERMINAL_STATES,
    InvalidStateTransitionError,
    TerminalStateError,
    apply_transition,
)


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating an ApprovalDecision."""
    is_valid: bool
    reason: str
    error_code: Optional[str] = None
    updated_recommendation: Optional[Recommendation] = None


def _parse_iso(timestamp_str: str) -> datetime:
    """Helper to parse ISO-8601 timestamps."""
    return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))


class ApprovalValidator:
    """Validates human approval decisions and applies state transitions."""

    def __init__(
        self,
        auth_policy: Optional[ConfigurableAuthorizationPolicy] = None,
        processed_decision_ids: Optional[Set[str]] = None,
    ) -> None:
        self.auth_policy = auth_policy or ConfigurableAuthorizationPolicy(default_allow=True)
        self.processed_decision_ids: set[str] = (
            set(processed_decision_ids) if processed_decision_ids is not None else set()
        )

    def validate_and_apply(
        self,
        decision: ApprovalDecision,
        recommendation: Optional[Recommendation],
        *,
        reference_time_iso: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> ValidationResult:
        """Validate an ApprovalDecision and apply transition to the Recommendation.

        Enforces all 14 validation requirements:
        1. Recommendation exists
        2. recommendation_id matches
        3. evidence_hash matches
        4. Operator role is authorized
        5. Recommendation has not expired
        6. signed_at is within validity period
        7. Decision is APPROVED or REJECTED
        8. Non-empty justification reason present
        9. Replay prevention (decision_id)
        10. Cross-recommendation approval blocked
        11. Terminal states cannot receive decisions
        12-14. Delegates transition exclusively to the state machine
        """
        # 1. Recommendation exists
        if recommendation is None:
            return ValidationResult(
                is_valid=False,
                reason="Recommendation does not exist.",
                error_code="RECOMMENDATION_NOT_FOUND",
            )

        # 2 & 10. recommendation_id exact match (A cannot approve B)
        if decision.recommendation_id != recommendation.recommendation_id:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Recommendation ID mismatch: decision targets '{decision.recommendation_id}' "
                    f"but active recommendation is '{recommendation.recommendation_id}'."
                ),
                error_code="RECOMMENDATION_ID_MISMATCH",
            )

        # 3. evidence_hash exact match
        if decision.evidence_hash != recommendation.evidence_hash:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Evidence hash mismatch: decision contains '{decision.evidence_hash}' "
                    f"but recommendation contains '{recommendation.evidence_hash}'."
                ),
                error_code="EVIDENCE_HASH_MISMATCH",
            )

        # 4. Operator role is authorized
        is_auth, auth_msg = self.auth_policy.check_authorization(
            role=decision.role,
            decision=decision.decision,
            recommendation=recommendation,
            risk_level=risk_level,
        )
        if not is_auth:
            return ValidationResult(
                is_valid=False,
                reason=f"Operator authorization failed: {auth_msg}",
                error_code="UNAUTHORIZED_ROLE",
            )

        # 5 & 6. Validity period and expiration check
        try:
            valid_until_dt = _parse_iso(recommendation.valid_until)
            signed_at_dt = _parse_iso(decision.signed_at)

            # Check decision signed_at against validity window
            if signed_at_dt > valid_until_dt:
                return ValidationResult(
                    is_valid=False,
                    reason=(
                        f"Decision signed_at '{decision.signed_at}' exceeds recommendation "
                        f"valid_until '{recommendation.valid_until}'."
                    ),
                    error_code="RECOMMENDATION_EXPIRED",
                )

            # Check current/reference time if provided
            if reference_time_iso is not None:
                ref_dt = _parse_iso(reference_time_iso)
                if ref_dt > valid_until_dt:
                    return ValidationResult(
                        is_valid=False,
                        reason=(
                            f"Current time '{reference_time_iso}' exceeds recommendation "
                            f"valid_until '{recommendation.valid_until}'."
                        ),
                        error_code="RECOMMENDATION_EXPIRED",
                    )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                reason=f"Timestamp parsing error: {e}",
                error_code="INVALID_TIMESTAMP",
            )

        # 7. Decision is valid: APPROVED or REJECTED
        if decision.decision not in DecisionType.values():
            return ValidationResult(
                is_valid=False,
                reason=f"Invalid decision value '{decision.decision}'. Must be APPROVED or REJECTED.",
                error_code="INVALID_DECISION",
            )

        # 8. Required reason is present
        if not decision.reason or not decision.reason.strip():
            return ValidationResult(
                is_valid=False,
                reason="A non-empty justification reason is required for all approval decisions.",
                error_code="MISSING_REASON",
            )

        # 9. Replay prevention: same decision_id cannot be processed twice
        if decision.decision_id in self.processed_decision_ids:
            return ValidationResult(
                is_valid=False,
                reason=f"Replay detected: decision_id '{decision.decision_id}' has already been processed.",
                error_code="REPLAY_DETECTED",
            )

        # 11. Terminal states cannot receive decisions
        if recommendation.status in TERMINAL_STATES:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Recommendation is in terminal state '{recommendation.status}' "
                    f"and cannot receive further decisions."
                ),
                error_code="TERMINAL_STATE",
            )

        # 12, 13, 14. Enforce state transition strictly through state machine
        target_status = (
            RecommendationStatus.APPROVED.value
            if decision.decision == DecisionType.APPROVED.value
            else RecommendationStatus.REJECTED.value
        )

        try:
            updated_rec = apply_transition(
                recommendation,
                target_status,
                approval_decision=decision if target_status == RecommendationStatus.APPROVED.value else None,
            )
        except (InvalidStateTransitionError, TerminalStateError) as e:
            return ValidationResult(
                is_valid=False,
                reason=f"State machine transition rejected: {e}",
                error_code="STATE_MACHINE_REJECTED",
            )

        # Record decision_id to prevent replay
        self.processed_decision_ids.add(decision.decision_id)

        return ValidationResult(
            is_valid=True,
            reason="Decision successfully validated and applied.",
            updated_recommendation=updated_rec,
        )
