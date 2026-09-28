"""Unit tests for Invalidation Logic in Module 4.

Covers:
1. Changed evidence invalidates an approved recommendation.
2. Changed proposed task/recommendation content invalidates approval.
3. Changed policy version invalidates approval.
4. Changed validity window invalidates approval.
5. Unchanged evidence/content does not unnecessarily invalidate approval.
6. Invalidated state requires a new review/approval cycle.
7. Previous approval information is preserved for traceability.
8. Invalidation uses the existing state machine rather than directly mutating state.
9. Repeated invalidation is handled deterministically.
"""

import unittest
from services.approval.contracts import (
    AllowedAction,
    ApprovalDecision,
    DecisionType,
    DomainAlert,
    Recommendation,
    RecommendationStatus,
)
from services.approval.evidence import compute_evidence_hash
from services.approval.invalidation import (
    InvalidationDetector,
    InvalidationRecord,
)
from services.approval.state_machine import (
    InvalidStateTransitionError,
    TerminalStateError,
    apply_transition,
)


class TestInvalidation(unittest.TestCase):

    def setUp(self):
        self.detector = InvalidationDetector()

        self.alert_1 = DomainAlert(
            alert_id="ALT-INV-01",
            supporting_event_ids=["EVT-01"],
            risk_level="HIGH",
            confidence=0.85,
            explanation="Pressure buildup in boiler section.",
            missing_evidence=[],
            valid_until="2026-09-24T22:00:00Z",
        )
        self.evidence_hash = compute_evidence_hash([self.alert_1])

        self.approved_rec = Recommendation(
            recommendation_id="REC-INV-100",
            alert_ids=["ALT-INV-01"],
            proposed_task=AllowedAction.INSPECT_AREA.value,
            rationale="High pressure requires immediate field inspection.",
            evidence_hash=self.evidence_hash,
            policy_version="1.0.0",
            status=RecommendationStatus.APPROVED.value,
            valid_until="2026-09-24T22:00:00Z",
        )

        self.approval_decision = ApprovalDecision(
            decision_id="DEC-INV-001",
            recommendation_id="REC-INV-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-77",
            role="CHIEF_ENGINEER",
            decision=DecisionType.APPROVED.value,
            reason="Confirmed critical sensor reading.",
            signed_at="2026-09-24T20:00:00Z",
        )

    # 1. Changed evidence invalidates an approved recommendation
    def test_changed_evidence_invalidates_approval(self):
        # Altered alert evidence
        altered_alert = DomainAlert(
            alert_id="ALT-INV-01",
            supporting_event_ids=["EVT-01"],
            risk_level="HIGH",
            confidence=0.99,  # altered confidence
            explanation="Pressure buildup in boiler section.",
            missing_evidence=[],
            valid_until="2026-09-24T22:00:00Z",
        )
        result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            current_alerts=[altered_alert],
        )
        self.assertTrue(result.is_invalidated)
        self.assertEqual(result.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("Evidence changed", result.reason)

    # 2. Changed proposed task / recommendation content invalidates approval
    def test_changed_content_invalidates_approval(self):
        # Altered proposed task
        res_task = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_proposed_task=AllowedAction.VERIFY_EQUIPMENT.value,
        )
        self.assertTrue(res_task.is_invalidated)
        self.assertEqual(res_task.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("Proposed task changed", res_task.reason)

        # Altered rationale
        res_rat = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_rationale="Different justification statement.",
        )
        self.assertTrue(res_rat.is_invalidated)
        self.assertEqual(res_rat.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("rationale changed", res_rat.reason)

    # 3. Changed policy version invalidates approval
    def test_changed_policy_version_invalidates_approval(self):
        result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_policy_version="2.0.0",
        )
        self.assertTrue(result.is_invalidated)
        self.assertEqual(result.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("Policy version changed", result.reason)

    # 4. Changed validity window invalidates approval
    def test_changed_validity_window_invalidates_approval(self):
        result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_valid_until="2026-09-24T23:59:59Z",
        )
        self.assertTrue(result.is_invalidated)
        self.assertEqual(result.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("Validity window changed", result.reason)

    # 5. Unchanged evidence/content does not unnecessarily invalidate approval
    def test_unchanged_evidence_does_not_invalidate_approval(self):
        result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            current_alerts=[self.alert_1],  # Identical alert
        )
        self.assertFalse(result.is_invalidated)
        self.assertEqual(result.recommendation.status, RecommendationStatus.APPROVED.value)
        self.assertIn("No approval-bound changes detected", result.reason)

    # 6. Invalidated state requires a new review/approval cycle
    def test_invalidated_state_requires_new_review_cycle(self):
        # First invalidate the recommendation
        inv_result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_policy_version="2.0.0",
        )
        invalidated_rec = inv_result.recommendation
        self.assertEqual(invalidated_rec.status, RecommendationStatus.INVALIDATED.value)

        # Invalidated cannot directly jump to Completed or Approved
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(invalidated_rec, RecommendationStatus.COMPLETED.value)
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(
                invalidated_rec,
                RecommendationStatus.APPROVED.value,
                approval_decision=self.approval_decision,
            )

        # Explicitly restart review cycle: Invalidated -> Pending Review
        pending_rec = self.detector.reinitiate_review_cycle(invalidated_rec)
        self.assertEqual(pending_rec.status, RecommendationStatus.PENDING_REVIEW.value)

    # 7. Previous approval information is preserved for traceability
    def test_previous_approval_information_preserved(self):
        result = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_policy_version="1.5.0",
            invalidated_at_iso="2026-09-24T21:00:00Z",
        )
        self.assertTrue(result.is_invalidated)
        record = result.invalidation_record
        self.assertIsNotNone(record)

        # Verifying preserved approval metadata
        self.assertEqual(record.recommendation_id, "REC-INV-100")
        self.assertEqual(record.previous_approval.decision_id, "DEC-INV-001")
        self.assertEqual(record.previous_approval.operator_id, "OPR-77")
        self.assertEqual(record.previous_approval.role, "CHIEF_ENGINEER")
        self.assertEqual(record.previous_approval.reason, "Confirmed critical sensor reading.")
        self.assertEqual(record.invalidated_at, "2026-09-24T21:00:00Z")

        # History retrieval
        history = self.detector.get_invalidation_history("REC-INV-100")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].previous_approval.decision_id, "DEC-INV-001")

    # 8. Invalidation uses the existing state machine rather than directly mutating state
    def test_invalidation_uses_state_machine(self):
        # Attempting invalidation on a recommendation that is NOT in Approved state
        # (e.g. Draft) should NOT trigger state transition
        draft_rec = Recommendation(
            recommendation_id="REC-DRAFT",
            alert_ids=["ALT-1"],
            proposed_task="inspect area",
            rationale="Test",
            evidence_hash="sha256:" + "3" * 64,
            policy_version="1.0.0",
            status=RecommendationStatus.DRAFT.value,
            valid_until="2026-09-24T22:00:00Z",
        )
        res = self.detector.check_and_apply_invalidation(
            draft_rec,
            self.approval_decision,
            new_policy_version="2.0.0",
        )
        self.assertFalse(res.is_invalidated)
        self.assertEqual(res.recommendation.status, RecommendationStatus.DRAFT.value)

    # 9. Repeated invalidation is handled deterministically
    def test_repeated_invalidation_handled_deterministically(self):
        # Initial invalidation
        res1 = self.detector.check_and_apply_invalidation(
            self.approved_rec,
            self.approval_decision,
            new_policy_version="2.0.0",
        )
        self.assertTrue(res1.is_invalidated)
        self.assertEqual(res1.recommendation.status, RecommendationStatus.INVALIDATED.value)

        # Checking invalidation again on the already-invalidated recommendation
        res2 = self.detector.check_and_apply_invalidation(
            res1.recommendation,
            self.approval_decision,
            new_policy_version="2.0.0",
        )
        self.assertFalse(res2.is_invalidated)
        self.assertEqual(res2.recommendation.status, RecommendationStatus.INVALIDATED.value)
        self.assertIn("already in Invalidated state", res2.reason)
        # History length remains 1 (no duplicate pollution)
        self.assertEqual(len(self.detector.get_invalidation_history("REC-INV-100")), 1)


if __name__ == "__main__":
    unittest.main()
