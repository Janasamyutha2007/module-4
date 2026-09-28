"""Unit tests for Human Approval Validation in Module 4.

Covers:
1. Valid approval succeeds.
2. Valid rejection succeeds.
3. Wrong recommendation_id is rejected.
4. Wrong evidence_hash is rejected.
5. Unauthorized role is rejected.
6. Expired recommendation is rejected.
7. Invalid decision value is rejected.
8. Missing required reason is rejected.
9. Replayed decision_id is rejected.
10. Decision for Recommendation A cannot approve Recommendation B.
11. Decision on a terminal recommendation is rejected.
12. Approval cannot bypass the state machine.
13. Valid approval produces the expected state transition.
14. Valid rejection produces the expected state transition.
"""

import unittest
from services.approval.auth import (
    ConfigurableAuthorizationPolicy,
    RolePermission,
)
from services.approval.contracts import (
    AllowedAction,
    ApprovalDecision,
    DecisionType,
    Recommendation,
    RecommendationStatus,
)
from services.approval.validator import (
    ApprovalValidator,
    ValidationResult,
)


class TestApprovalValidator(unittest.TestCase):

    def setUp(self):
        self.auth_policy = ConfigurableAuthorizationPolicy(
            role_permissions={
                "VALID_OPERATOR": RolePermission(can_approve=True, can_reject=True),
                "READ_ONLY_ROLE": RolePermission(can_approve=False, can_reject=False),
            },
            default_allow=False,
        )
        self.validator = ApprovalValidator(auth_policy=self.auth_policy)

        self.evidence_hash = "sha256:" + "1" * 64
        self.rec_a = Recommendation(
            recommendation_id="REC-AAA-100",
            alert_ids=["ALT-100"],
            proposed_task=AllowedAction.INSPECT_AREA.value,
            rationale="Area inspection needed.",
            evidence_hash=self.evidence_hash,
            policy_version="1.0.0",
            status=RecommendationStatus.PENDING_REVIEW.value,
            valid_until="2026-09-24T20:00:00Z",
        )
        self.rec_b = Recommendation(
            recommendation_id="REC-BBB-200",
            alert_ids=["ALT-200"],
            proposed_task=AllowedAction.VERIFY_EQUIPMENT.value,
            rationale="Equipment check needed.",
            evidence_hash="sha256:" + "2" * 64,
            policy_version="1.0.0",
            status=RecommendationStatus.PENDING_REVIEW.value,
            valid_until="2026-09-24T20:00:00Z",
        )

        self.valid_decision = ApprovalDecision(
            decision_id="DEC-001",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="Confirmed anomaly signature on field camera.",
            signed_at="2026-09-24T18:00:00Z",
        )

    # 1. Valid approval succeeds
    def test_valid_approval_succeeds(self):
        result = self.validator.validate_and_apply(self.valid_decision, self.rec_a)
        self.assertTrue(result.is_valid)
        self.assertIsNotNone(result.updated_recommendation)
        self.assertEqual(result.updated_recommendation.status, RecommendationStatus.APPROVED.value)

    # 2. Valid rejection succeeds
    def test_valid_rejection_succeeds(self):
        reject_decision = ApprovalDecision(
            decision_id="DEC-002",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.REJECTED.value,
            reason="False positive sensor reading.",
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(reject_decision, self.rec_a)
        self.assertTrue(result.is_valid)
        self.assertIsNotNone(result.updated_recommendation)
        self.assertEqual(result.updated_recommendation.status, RecommendationStatus.REJECTED.value)

    # 3. Wrong recommendation_id is rejected
    def test_wrong_recommendation_id_rejected(self):
        mismatched_id_decision = ApprovalDecision(
            decision_id="DEC-003",
            recommendation_id="REC-OTHER-999",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="Valid reason",
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(mismatched_id_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "RECOMMENDATION_ID_MISMATCH")

    # 4. Wrong evidence_hash is rejected
    def test_wrong_evidence_hash_rejected(self):
        mismatched_evidence_decision = ApprovalDecision(
            decision_id="DEC-004",
            recommendation_id="REC-AAA-100",
            evidence_hash="sha256:" + "9" * 64,  # altered hash
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="Valid reason",
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(mismatched_evidence_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "EVIDENCE_HASH_MISMATCH")

    # 5. Unauthorized role is rejected
    def test_unauthorized_role_rejected(self):
        unauth_decision = ApprovalDecision(
            decision_id="DEC-005",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-12",
            role="READ_ONLY_ROLE",
            decision=DecisionType.APPROVED.value,
            reason="Valid reason",
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(unauth_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "UNAUTHORIZED_ROLE")

    # 6. Expired recommendation is rejected
    def test_expired_recommendation_rejected(self):
        # signed_at is past valid_until
        expired_decision = ApprovalDecision(
            decision_id="DEC-006",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="Valid reason",
            signed_at="2026-09-24T21:00:00Z",  # valid_until is 20:00:00Z
        )
        result = self.validator.validate_and_apply(expired_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "RECOMMENDATION_EXPIRED")

        # Current reference time past valid_until
        result2 = self.validator.validate_and_apply(
            self.valid_decision,
            self.rec_a,
            reference_time_iso="2026-09-24T21:30:00Z",
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.error_code, "RECOMMENDATION_EXPIRED")

    # 7. Invalid decision value is rejected
    def test_invalid_decision_value_rejected(self):
        # Simulate bypass of contract constructor
        invalid_decision = ApprovalDecision(
            decision_id="DEC-007",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="Valid reason",
            signed_at="2026-09-24T18:00:00Z",
        )
        object.__setattr__(invalid_decision, "decision", "DEFER")
        result = self.validator.validate_and_apply(invalid_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "INVALID_DECISION")

    # 8. Missing required reason is rejected
    def test_missing_required_reason_rejected(self):
        no_reason_decision = ApprovalDecision(
            decision_id="DEC-008",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.APPROVED.value,
            reason="   ",  # whitespace only
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(no_reason_decision, self.rec_a)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "MISSING_REASON")

    # 9. Replayed decision_id is rejected
    def test_replayed_decision_id_rejected(self):
        # First processing succeeds
        res1 = self.validator.validate_and_apply(self.valid_decision, self.rec_a)
        self.assertTrue(res1.is_valid)

        # Replaying identical decision_id fails
        res2 = self.validator.validate_and_apply(self.valid_decision, self.rec_a)
        self.assertFalse(res2.is_valid)
        self.assertEqual(res2.error_code, "REPLAY_DETECTED")

    # 10. Decision for Recommendation A cannot approve Recommendation B
    def test_decision_for_a_cannot_approve_b(self):
        # Decision targets rec_a; attempted against rec_b
        result = self.validator.validate_and_apply(self.valid_decision, self.rec_b)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "RECOMMENDATION_ID_MISMATCH")

    # 11. Decision on a terminal recommendation is rejected
    def test_decision_on_terminal_recommendation_rejected(self):
        terminal_rec = Recommendation(
            recommendation_id="REC-AAA-100",
            alert_ids=["ALT-100"],
            proposed_task=AllowedAction.INSPECT_AREA.value,
            rationale="Area inspection needed.",
            evidence_hash=self.evidence_hash,
            policy_version="1.0.0",
            status=RecommendationStatus.COMPLETED.value,  # Terminal
            valid_until="2026-09-24T20:00:00Z",
        )
        result = self.validator.validate_and_apply(self.valid_decision, terminal_rec)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "TERMINAL_STATE")

    # 12. Approval cannot bypass the state machine
    def test_approval_cannot_bypass_state_machine(self):
        # Recommendation is in Draft state (cannot transition directly to Approved)
        draft_rec = Recommendation(
            recommendation_id="REC-AAA-100",
            alert_ids=["ALT-100"],
            proposed_task=AllowedAction.INSPECT_AREA.value,
            rationale="Area inspection needed.",
            evidence_hash=self.evidence_hash,
            policy_version="1.0.0",
            status=RecommendationStatus.DRAFT.value,
            valid_until="2026-09-24T20:00:00Z",
        )
        result = self.validator.validate_and_apply(self.valid_decision, draft_rec)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "STATE_MACHINE_REJECTED")

    # 13. Valid approval produces the expected state transition
    def test_valid_approval_produces_approved_state(self):
        self.assertEqual(self.rec_a.status, RecommendationStatus.PENDING_REVIEW.value)
        result = self.validator.validate_and_apply(self.valid_decision, self.rec_a)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.updated_recommendation.status, RecommendationStatus.APPROVED.value)

    # 14. Valid rejection produces the expected state transition
    def test_valid_rejection_produces_rejected_state(self):
        reject_decision = ApprovalDecision(
            decision_id="DEC-014",
            recommendation_id="REC-AAA-100",
            evidence_hash=self.evidence_hash,
            operator_id="OPR-99",
            role="VALID_OPERATOR",
            decision=DecisionType.REJECTED.value,
            reason="Unsubstantiated risk alert.",
            signed_at="2026-09-24T18:00:00Z",
        )
        result = self.validator.validate_and_apply(reject_decision, self.rec_a)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.updated_recommendation.status, RecommendationStatus.REJECTED.value)


if __name__ == "__main__":
    unittest.main()
