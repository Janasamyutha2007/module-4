"""Unit tests for State Machine and Configurable Role Authorization.

Covers:
1. Draft -> Pending Review succeeds.
2. Pending Review -> Approved cannot happen without valid approval.
3. Pending Review -> Rejected works when a valid rejection is processed.
4. Pending Review -> Expired works when validity expires.
5. Approved -> Completed works only through the appropriate valid path.
6. Invalid transitions are rejected.
7. Terminal states cannot be arbitrarily changed.
8. Unauthorized approval is rejected.
9. Authorized approval can pass the authorization check.
10. Authorization policy is configurable.
11. State transitions are deterministic.
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
from services.approval.state_machine import (
    InvalidStateTransitionError,
    TerminalStateError,
    apply_transition,
    validate_transition,
)


class TestStateMachineAndAuth(unittest.TestCase):

    def setUp(self):
        self.base_rec = Recommendation(
            recommendation_id="REC-TEST-001",
            alert_ids=["ALT-101"],
            proposed_task=AllowedAction.INSPECT_AREA.value,
            rationale="Test rationale.",
            evidence_hash="sha256:" + "c" * 64,
            policy_version="1.0.0",
            status=RecommendationStatus.DRAFT.value,
            valid_until="2026-09-24T22:00:00Z",
        )
        self.valid_approval = ApprovalDecision(
            decision_id="DEC-TEST-001",
            recommendation_id="REC-TEST-001",
            evidence_hash="sha256:" + "c" * 64,
            operator_id="OPR-01",
            role="ROLE_ALPHA",
            decision=DecisionType.APPROVED.value,
            reason="Verified safe to inspect.",
            signed_at="2026-09-24T20:00:00Z",
        )
        self.valid_rejection = ApprovalDecision(
            decision_id="DEC-TEST-002",
            recommendation_id="REC-TEST-001",
            evidence_hash="sha256:" + "c" * 64,
            operator_id="OPR-01",
            role="ROLE_ALPHA",
            decision=DecisionType.REJECTED.value,
            reason="Unnecessary inspection.",
            signed_at="2026-09-24T20:00:00Z",
        )

    # 1. Draft -> Pending Review succeeds
    def test_draft_to_pending_review_succeeds(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)
        self.assertEqual(rec_pending.status, RecommendationStatus.PENDING_REVIEW.value)

    # 2. Pending Review -> Approved cannot happen without valid approval
    def test_pending_review_to_approved_requires_valid_approval(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)

        # Attempting without approval decision
        with self.assertRaises(InvalidStateTransitionError) as ctx:
            apply_transition(rec_pending, RecommendationStatus.APPROVED.value, approval_decision=None)
        self.assertIn("strictly forbidden without a valid human ApprovalDecision", str(ctx.exception))

        # Attempting with a REJECTED decision to enter Approved state
        with self.assertRaises(InvalidStateTransitionError) as ctx2:
            apply_transition(rec_pending, RecommendationStatus.APPROVED.value, approval_decision=self.valid_rejection)
        self.assertIn("Cannot transition to 'Approved' with decision 'REJECTED'", str(ctx2.exception))

        # With valid approval decision
        rec_approved = apply_transition(
            rec_pending,
            RecommendationStatus.APPROVED.value,
            approval_decision=self.valid_approval,
        )
        self.assertEqual(rec_approved.status, RecommendationStatus.APPROVED.value)

    # 3. Pending Review -> Rejected works when a valid rejection is processed
    def test_pending_review_to_rejected(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)
        rec_rejected = apply_transition(rec_pending, RecommendationStatus.REJECTED.value)
        self.assertEqual(rec_rejected.status, RecommendationStatus.REJECTED.value)

    # 4. Pending Review -> Expired works when validity expires
    def test_pending_review_to_expired(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)
        rec_expired = apply_transition(rec_pending, RecommendationStatus.EXPIRED.value)
        self.assertEqual(rec_expired.status, RecommendationStatus.EXPIRED.value)

    # 5. Approved -> Completed works only through the appropriate valid path
    def test_approved_to_completed_valid_path(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)
        rec_approved = apply_transition(
            rec_pending,
            RecommendationStatus.APPROVED.value,
            approval_decision=self.valid_approval,
        )
        rec_completed = apply_transition(rec_approved, RecommendationStatus.COMPLETED.value)
        self.assertEqual(rec_completed.status, RecommendationStatus.COMPLETED.value)

        # Direct transition Draft -> Completed is forbidden
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(self.base_rec, RecommendationStatus.COMPLETED.value)

        # Direct transition Pending Review -> Completed is forbidden
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(rec_pending, RecommendationStatus.COMPLETED.value)

    # 6. Invalid transitions are rejected
    def test_invalid_transitions_are_rejected(self):
        # Draft cannot jump directly to Approved
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(
                self.base_rec,
                RecommendationStatus.APPROVED.value,
                approval_decision=self.valid_approval,
            )

        # Draft cannot jump to Expired
        with self.assertRaises(InvalidStateTransitionError):
            apply_transition(self.base_rec, RecommendationStatus.EXPIRED.value)

    # 7. Terminal states cannot be arbitrarily changed
    def test_terminal_states_cannot_be_changed(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)

        # Terminal state: Completed
        rec_approved = apply_transition(
            rec_pending,
            RecommendationStatus.APPROVED.value,
            approval_decision=self.valid_approval,
        )
        rec_completed = apply_transition(rec_approved, RecommendationStatus.COMPLETED.value)
        with self.assertRaises(TerminalStateError):
            apply_transition(rec_completed, RecommendationStatus.PENDING_REVIEW.value)
        with self.assertRaises(TerminalStateError):
            apply_transition(rec_completed, RecommendationStatus.APPROVED.value)

        # Terminal state: Rejected
        rec_rejected = apply_transition(rec_pending, RecommendationStatus.REJECTED.value)
        with self.assertRaises(TerminalStateError):
            apply_transition(rec_rejected, RecommendationStatus.PENDING_REVIEW.value)

        # Terminal state: Expired
        rec_expired = apply_transition(rec_pending, RecommendationStatus.EXPIRED.value)
        with self.assertRaises(TerminalStateError):
            apply_transition(rec_expired, RecommendationStatus.APPROVED.value)

    # 8. Unauthorized approval is rejected
    def test_unauthorized_approval_is_rejected(self):
        policy = ConfigurableAuthorizationPolicy(
            role_permissions={
                "TRAINEE": RolePermission(can_approve=False, can_reject=True),
                "LIMITED_LEAD": RolePermission(
                    can_approve=True,
                    allowed_tasks={"verify equipment"},  # does NOT allow 'inspect area'
                ),
                "TIER_1": RolePermission(
                    can_approve=True,
                    max_risk_level="MEDIUM",  # cannot approve HIGH risk
                ),
            },
            default_allow=False,
        )

        rec = Recommendation(
            recommendation_id="REC-AUTH-01",
            alert_ids=["ALT-1"],
            proposed_task="inspect area",
            rationale="Test",
            evidence_hash="sha256:" + "d" * 64,
            policy_version="1.0.0",
            status="Pending Review",
            valid_until="2026-09-24T23:00:00Z",
        )

        # Unknown role
        ok, reason = policy.check_authorization(role="GUEST", decision="APPROVED", recommendation=rec)
        self.assertFalse(ok)
        self.assertIn("not recognized", reason)

        # Role not permitted to approve
        ok, reason = policy.check_authorization(role="TRAINEE", decision="APPROVED", recommendation=rec)
        self.assertFalse(ok)
        self.assertIn("not permitted to issue APPROVAL", reason)

        # Role restricted by task
        ok, reason = policy.check_authorization(role="LIMITED_LEAD", decision="APPROVED", recommendation=rec)
        self.assertFalse(ok)
        self.assertIn("not authorized to approve task 'inspect area'", reason)

        # Role restricted by risk
        ok, reason = policy.check_authorization(
            role="TIER_1", decision="APPROVED", recommendation=rec, risk_level="HIGH"
        )
        self.assertFalse(ok)
        self.assertIn("insufficient for risk level 'HIGH'", reason)

    # 9. Authorized approval can pass the authorization check
    def test_authorized_approval_passes(self):
        policy = ConfigurableAuthorizationPolicy(
            role_permissions={
                "COMMAND_ROLE": RolePermission(
                    can_approve=True,
                    can_reject=True,
                    allowed_tasks=None,  # all allowed
                    max_risk_level="CRITICAL",
                ),
            }
        )
        rec = Recommendation(
            recommendation_id="REC-AUTH-02",
            alert_ids=["ALT-2"],
            proposed_task="inspect area",
            rationale="Test",
            evidence_hash="sha256:" + "e" * 64,
            policy_version="1.0.0",
            status="Pending Review",
            valid_until="2026-09-24T23:00:00Z",
        )
        ok, reason = policy.check_authorization(
            role="COMMAND_ROLE", decision="APPROVED", recommendation=rec, risk_level="HIGH"
        )
        self.assertTrue(ok)
        self.assertIn("is authorized", reason)

    # 10. Authorization policy is configurable
    def test_authorization_policy_is_configurable(self):
        policy = ConfigurableAuthorizationPolicy(default_allow=False)

        rec = Recommendation(
            recommendation_id="REC-AUTH-03",
            alert_ids=["ALT-3"],
            proposed_task="verify equipment",
            rationale="Test",
            evidence_hash="sha256:" + "f" * 64,
            policy_version="1.0.0",
            status="Pending Review",
            valid_until="2026-09-24T23:00:00Z",
        )

        # Initially unrecognized
        ok, _ = policy.check_authorization(role="DYNAMIC_SUPERVISOR", decision="APPROVED", recommendation=rec)
        self.assertFalse(ok)

        # Dynamically configure role
        policy.configure_role(
            "DYNAMIC_SUPERVISOR",
            RolePermission(can_approve=True, allowed_tasks={"verify equipment"}),
        )
        ok, _ = policy.check_authorization(role="DYNAMIC_SUPERVISOR", decision="APPROVED", recommendation=rec)
        self.assertTrue(ok)

        # Dynamically remove role
        policy.remove_role("DYNAMIC_SUPERVISOR")
        ok, _ = policy.check_authorization(role="DYNAMIC_SUPERVISOR", decision="APPROVED", recommendation=rec)
        self.assertFalse(ok)

    # 11. State transitions are deterministic
    def test_state_transitions_are_deterministic(self):
        rec_pending = apply_transition(self.base_rec, RecommendationStatus.PENDING_REVIEW.value)

        # Re-applying same transition multiple times produces identical result
        app1 = apply_transition(
            rec_pending,
            RecommendationStatus.APPROVED.value,
            approval_decision=self.valid_approval,
        )
        app2 = apply_transition(
            rec_pending,
            RecommendationStatus.APPROVED.value,
            approval_decision=self.valid_approval,
        )

        self.assertEqual(app1.status, app2.status)
        self.assertEqual(app1.recommendation_id, app2.recommendation_id)
        self.assertEqual(app1.evidence_hash, app2.evidence_hash)
        self.assertEqual(app1.proposed_task, app2.proposed_task)


if __name__ == "__main__":
    unittest.main()
