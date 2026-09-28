"""Approval Service Coordinator for Module 4 (Global/Central AI).

Coordinates:
- Ingestion of DomainAlert events and deterministic Recommendation generation
- Human ApprovalDecision ingestion, validation, and state machine transition
- Emission of DecisionStatus events with cryptographic audit references
- Tamper-evident, append-only audit trail logging for all decision attempts
- Invalidation handling when evidence or context changes
- STRICT NON-EXECUTION: Never executes or triggers any operational action.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence, Union

from services.approval.audit import (
    AuditEntry,
    AuditLedger,
    AuditVerificationResult,
    verify_audit_ledger,
)
from services.approval.auth import (
    ConfigurableAuthorizationPolicy,
    RolePermission,
)
from services.approval.contracts import (
    ApprovalDecision,
    DecisionStatus,
    DecisionType,
    DomainAlert,
    EventEnvelope,
    Recommendation,
    RecommendationStatus,
)
from services.approval.engine import (
    ResourceConstraints,
    rank_and_generate_recommendation,
)
from services.approval.evidence import compute_evidence_hash
from services.approval.invalidation import (
    InvalidationDetector,
    InvalidationRecord,
    InvalidationResult,
)
from services.approval.validator import (
    ApprovalValidator,
    ValidationResult,
)


def _current_iso_timestamp() -> str:
    """Generate current UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).isoformat()


class ApprovalService:
    """Central AI Approval Service coordinator for Module 4."""

    def __init__(
        self,
        *,
        auth_policy: Optional[ConfigurableAuthorizationPolicy] = None,
        policy_version: str = "1.0.0",
        producer_id: str = "module-4-approval-service",
        constraints: Optional[ResourceConstraints] = None,
    ) -> None:
        self.policy_version = policy_version
        self.producer_id = producer_id
        self.constraints = constraints or ResourceConstraints()

        # Authorization, validation, and invalidation engines
        self.auth_policy = auth_policy or ConfigurableAuthorizationPolicy(default_allow=True)
        self.validator = ApprovalValidator(auth_policy=self.auth_policy)
        self.invalidation_detector = InvalidationDetector()
        self.audit_ledger = AuditLedger()

        # In-memory stores
        self._recommendations: dict[str, Recommendation] = {}
        self._alerts: dict[str, list[DomainAlert]] = {}
        self._approvals: dict[str, ApprovalDecision] = {}

    def get_recommendation(self, recommendation_id: str) -> Optional[Recommendation]:
        """Retrieve active recommendation by ID."""
        return self._recommendations.get(recommendation_id)

    def process_domain_alert(
        self,
        envelope: EventEnvelope,
        *,
        reference_time_iso: Optional[str] = None,
    ) -> EventEnvelope:
        """Process incoming DomainAlert envelope and produce a Recommendation envelope.

        - Binds ordered evidence to compute evidence_hash.
        - Generates ranked deterministic Recommendation.
        - Status set to 'Pending Review'.
        - Emits EventEnvelope containing Recommendation.
        - Non-executable proposal only.
        """
        payload = envelope.payload

        # Parse alert(s) from payload
        if "alert_id" in payload:
            alerts = [DomainAlert.from_dict(payload)]
        elif "alerts" in payload and isinstance(payload["alerts"], list):
            alerts = [DomainAlert.from_dict(a) for a in payload["alerts"]]
        else:
            raise ValueError("Payload does not contain valid DomainAlert data.")

        # Deterministically generate recommendation
        recommendation = rank_and_generate_recommendation(
            alerts,
            policy_version=self.policy_version,
            constraints=self.constraints,
            reference_time_iso=reference_time_iso,
            status=RecommendationStatus.PENDING_REVIEW.value,
        )

        # Store in-memory state
        rec_id = recommendation.recommendation_id
        self._recommendations[rec_id] = recommendation
        self._alerts[rec_id] = alerts

        # Wrap in outbound EventEnvelope
        out_msg_id = f"MSG-REC-{uuid.uuid4().hex[:12].upper()}"
        out_envelope = EventEnvelope(
            message_id=out_msg_id,
            message_type="Recommendation",
            schema_version="1.0.0",
            run_id=envelope.run_id,
            producer=self.producer_id,
            produced_at=_current_iso_timestamp(),
            correlation_id=envelope.correlation_id,
            causation_id=envelope.message_id,
            payload=recommendation.to_dict(),
        )

        return out_envelope

    def process_approval_decision(
        self,
        envelope: EventEnvelope,
        *,
        reference_time_iso: Optional[str] = None,
    ) -> EventEnvelope:
        """Process incoming ApprovalDecision envelope and emit DecisionStatus envelope.

        - Validates decision against active recommendation, evidence_hash, role, expiry, replay.
        - Transitions state strictly through the state machine.
        - Appends audit entry to AuditLedger for BOTH accepted and rejected attempts.
        - Sets audit_ref to the audit entry hash.
        - Emits EventEnvelope containing DecisionStatus.
        """
        decision = ApprovalDecision.from_dict(envelope.payload)
        rec = self._recommendations.get(decision.recommendation_id)

        # Extract risk level from original alerts if available for role checks
        risk_level: Optional[str] = None
        if rec and rec.recommendation_id in self._alerts:
            alerts = self._alerts[rec.recommendation_id]
            if alerts:
                risk_level = max(a.risk_level for a in alerts)

        # Validate decision using existing validator
        validation_result: ValidationResult = self.validator.validate_and_apply(
            decision,
            rec,
            reference_time_iso=reference_time_iso,
            risk_level=risk_level,
        )

        committed_timestamp = _current_iso_timestamp()

        if validation_result.is_valid and validation_result.updated_recommendation is not None:
            updated_rec = validation_result.updated_recommendation
            old_status = rec.status if rec else "Pending Review"
            self._recommendations[decision.recommendation_id] = updated_rec

            if decision.decision == DecisionType.APPROVED.value:
                self._approvals[decision.recommendation_id] = decision

            transition_str = f"{old_status} -> {updated_rec.status}"
            status_outcome = updated_rec.status
            audit_decision = decision.decision
        else:
            # Decision attempt rejected
            current_status = rec.status if rec else "None"
            transition_str = f"{current_status} -> {current_status} (Attempt Rejected: {validation_result.reason})"
            status_outcome = "Rejected"
            audit_decision = f"{decision.decision}_REJECTED"

        # Record attempt in the append-only AuditLedger (Accepted and Rejected attempts)
        audit_entry: AuditEntry = self.audit_ledger.append_entry(
            operator_id=decision.operator_id,
            role=decision.role,
            decision=audit_decision,
            timestamp=decision.signed_at,
            recommendation_id=decision.recommendation_id,
            decision_id=decision.decision_id,
            evidence_hash=decision.evidence_hash,
            state_transition=transition_str,
            reason=validation_result.reason,
        )

        # Construct DecisionStatus
        event_id = f"EVT-DEC-{uuid.uuid4().hex[:12].upper()}"
        decision_status = DecisionStatus(
            event_id=event_id,
            recommendation_id=decision.recommendation_id,
            decision_id=decision.decision_id,
            status=status_outcome,
            reason=validation_result.reason,
            committed_at=committed_timestamp,
            audit_ref=audit_entry.entry_hash,
        )

        out_msg_id = f"MSG-STAT-{uuid.uuid4().hex[:12].upper()}"
        out_envelope = EventEnvelope(
            message_id=out_msg_id,
            message_type="DecisionStatus",
            schema_version="1.0.0",
            run_id=envelope.run_id,
            producer=self.producer_id,
            produced_at=committed_timestamp,
            correlation_id=envelope.correlation_id,
            causation_id=envelope.message_id,
            payload=decision_status.to_dict(),
        )

        return out_envelope

    def check_and_apply_invalidation(
        self,
        recommendation_id: str,
        *,
        current_alerts: Optional[Sequence[DomainAlert]] = None,
        new_proposed_task: Optional[str] = None,
        new_rationale: Optional[str] = None,
        new_policy_version: Optional[str] = None,
        new_valid_until: Optional[str] = None,
        new_evidence_hash: Optional[str] = None,
        invalidated_at_iso: Optional[str] = None,
    ) -> InvalidationResult:
        """Evaluate and apply invalidation on an approved recommendation.

        - If invalidated, updates recommendation state to 'Invalidated'.
        - Preserves previous approval in InvalidationRecord.
        - Logs invalidation event into AuditLedger.
        """
        rec = self._recommendations.get(recommendation_id)
        if rec is None:
            raise KeyError(f"Recommendation '{recommendation_id}' not found.")

        prev_approval = self._approvals.get(recommendation_id)
        if prev_approval is None:
            # If no stored approval, synthesize a minimal representation from rec
            prev_approval = ApprovalDecision(
                decision_id="DEC-UNKNOWN",
                recommendation_id=rec.recommendation_id,
                evidence_hash=rec.evidence_hash,
                operator_id="SYSTEM",
                role="UNKNOWN",
                decision="APPROVED",
                reason="Prior approval metadata not in local memory.",
                signed_at=_current_iso_timestamp(),
            )

        inv_result = self.invalidation_detector.check_and_apply_invalidation(
            rec,
            prev_approval,
            current_alerts=current_alerts,
            new_proposed_task=new_proposed_task,
            new_rationale=new_rationale,
            new_policy_version=new_policy_version,
            new_valid_until=new_valid_until,
            new_evidence_hash=new_evidence_hash,
            invalidated_at_iso=invalidated_at_iso,
        )

        if inv_result.is_invalidated:
            self._recommendations[recommendation_id] = inv_result.recommendation

            # Record invalidation in audit ledger
            self.audit_ledger.append_entry(
                operator_id=prev_approval.operator_id,
                role=prev_approval.role,
                decision="INVALIDATED",
                timestamp=inv_result.invalidation_record.invalidated_at if inv_result.invalidation_record else _current_iso_timestamp(),
                recommendation_id=recommendation_id,
                decision_id=prev_approval.decision_id,
                evidence_hash=inv_result.invalidation_record.new_evidence_hash or rec.evidence_hash if inv_result.invalidation_record else rec.evidence_hash,
                state_transition="Approved -> Invalidated",
                reason=inv_result.reason,
            )

        return inv_result

    def reinitiate_review_cycle(self, recommendation_id: str) -> Recommendation:
        """Restart review cycle for an invalidated recommendation."""
        rec = self._recommendations.get(recommendation_id)
        if rec is None:
            raise KeyError(f"Recommendation '{recommendation_id}' not found.")

        updated_rec = self.invalidation_detector.reinitiate_review_cycle(rec)
        self._recommendations[recommendation_id] = updated_rec
        return updated_rec

    def verify_audit(self) -> AuditVerificationResult:
        """Verify the integrity of the audit ledger."""
        return verify_audit_ledger(self.audit_ledger)
