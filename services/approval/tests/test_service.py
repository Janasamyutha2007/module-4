"""End-to-End integration tests for ApprovalService in Module 4.

Covers:
1. DomainAlert -> Recommendation -> Pending Review
2. Valid approval -> Approved -> DecisionStatus -> audit entry
3. Valid rejection -> Rejected -> DecisionStatus -> audit entry
4. Wrong recommendation_id -> rejected -> audit attempt preserved
5. Wrong evidence_hash -> rejected -> audit attempt preserved
6. Unauthorized role -> rejected -> audit attempt preserved
7. Expired recommendation -> rejected -> audit attempt preserved
8. Replay -> first decision accepted -> second identical decision rejected -> both attempts auditable
9. Evidence/context changes after approval -> Approved becomes Invalidated -> previous approval preserved -> new review required
10. Tampered audit entry -> verification detects tampering
11. Competing/concurrent decision attempts -> deterministic final state -> competing attempts remain auditable
12. Non-execution invariant -> verify that the service does NOT execute the proposed task, no operational side effects
"""

import unittest
from services.approval.audit import AuditEntry
from services.approval.auth import (
    ConfigurableAuthorizationPolicy,
    RolePermission,
)
from services.approval.contracts import (
    AllowedAction,
    ApprovalDecision,
    DecisionStatus,
    DecisionType,
    DomainAlert,
    EventEnvelope,
    Recommendation,
    RecommendationStatus,
)
from services.approval.service import ApprovalService


class TestApprovalServiceEndToEnd(unittest.TestCase):

    def setUp(self):
        self.auth_policy = ConfigurableAuthorizationPolicy(
            role_permissions={
                "VALID_OPERATOR": RolePermission(can_approve=True, can_reject=True),
                "LIMITED_OPERATOR": RolePermission(
                    can_approve=True,
                    allowed_tasks={AllowedAction.VERIFY_EQUIPMENT.value},
                ),
            },
            default_allow=False,
        )
        self.service = ApprovalService(auth_policy=self.auth_policy)

        # Baseline alert envelope
        self.alert_payload = {
            "alert_id": "ALT-E2E-001",
            "supporting_event_ids": ["EVT-001", "EVT-002"],
            "risk_level": "HIGH",
            "confidence": 0.90,
            "explanation": "High thermal radiance detected in containment sector 4.",
            "missing_evidence": [],
            "valid_until": "2026-09-24T22:00:00Z",
        }
        self.alert_envelope = EventEnvelope(
            message_id="MSG-E2E-ALERT-01",
            message_type="DomainAlert",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-3-domain-sensor",
            produced_at="2026-09-24T12:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id="ROOT-CAUSE-01",
            payload=self.alert_payload,
        )

    # 1. DomainAlert -> Recommendation -> Pending Review
    def test_domain_alert_to_recommendation_pending_review(self):
        out_envelope = self.service.process_domain_alert(self.alert_envelope)

        self.assertEqual(out_envelope.message_type, "Recommendation")
        self.assertEqual(out_envelope.correlation_id, "CORR-E2E-01")
        self.assertEqual(out_envelope.causation_id, "MSG-E2E-ALERT-01")

        rec_data = out_envelope.payload
        self.assertIn("recommendation_id", rec_data)
        self.assertEqual(rec_data["status"], RecommendationStatus.PENDING_REVIEW.value)
        self.assertEqual(rec_data["alert_ids"], ["ALT-E2E-001"])
        self.assertIn(rec_data["proposed_task"], AllowedAction.values())
        self.assertTrue(rec_data["evidence_hash"].startswith("sha256:"))

        # Check internal service state
        active_rec = self.service.get_recommendation(rec_data["recommendation_id"])
        self.assertIsNotNone(active_rec)
        self.assertEqual(active_rec.status, RecommendationStatus.PENDING_REVIEW.value)

    # 2. Valid approval -> Approved -> DecisionStatus -> audit entry
    def test_valid_approval_workflow(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-001",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Confirmed physical thermal reading with secondary probe.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-01",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        self.assertEqual(status_env.message_type, "DecisionStatus")

        status_data = status_env.payload
        self.assertEqual(status_data["status"], RecommendationStatus.APPROVED.value)
        self.assertEqual(status_data["recommendation_id"], rec["recommendation_id"])
        self.assertEqual(status_data["decision_id"], "DEC-E2E-001")
        self.assertTrue(status_data["audit_ref"].startswith("sha256:"))

        # Check active recommendation updated
        active_rec = self.service.get_recommendation(rec["recommendation_id"])
        self.assertEqual(active_rec.status, RecommendationStatus.APPROVED.value)

        # Check audit entry
        self.assertEqual(len(self.service.audit_ledger), 1)
        audit_entry = self.service.audit_ledger[0]
        self.assertEqual(audit_entry.entry_hash, status_data["audit_ref"])
        self.assertEqual(audit_entry.decision, "APPROVED")
        self.assertEqual(audit_entry.state_transition, "Pending Review -> Approved")

        # Verify audit ledger
        audit_ver = self.service.verify_audit()
        self.assertTrue(audit_ver.is_valid)

    # 3. Valid rejection -> Rejected -> DecisionStatus -> audit entry
    def test_valid_rejection_workflow(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-002",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.REJECTED.value,
            "reason": "Sensor thermal reading is deemed a calibration artifact.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-02",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        status_data = status_env.payload
        self.assertEqual(status_data["status"], RecommendationStatus.REJECTED.value)

        # Check active recommendation updated
        active_rec = self.service.get_recommendation(rec["recommendation_id"])
        self.assertEqual(active_rec.status, RecommendationStatus.REJECTED.value)

        # Audit entry check
        self.assertEqual(len(self.service.audit_ledger), 1)
        self.assertEqual(self.service.audit_ledger[0].decision, "REJECTED")
        self.assertEqual(self.service.audit_ledger[0].state_transition, "Pending Review -> Rejected")
        self.assertTrue(self.service.verify_audit().is_valid)

    # 4. Wrong recommendation_id -> rejected -> audit attempt preserved
    def test_wrong_recommendation_id_rejected(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-003",
            "recommendation_id": "REC-NON-EXISTENT-999",  # Wrong ID
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Approved without checking ID.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-03",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        status_data = status_env.payload
        self.assertEqual(status_data["status"], "Rejected")
        self.assertIn("does not exist", status_data["reason"])

        # Audit entry must be preserved for failed attempt
        self.assertEqual(len(self.service.audit_ledger), 1)
        entry = self.service.audit_ledger[0]
        self.assertEqual(entry.decision, "APPROVED_REJECTED")
        self.assertIn("Attempt Rejected", entry.state_transition)

        # Original recommendation remains Pending Review
        active_rec = self.service.get_recommendation(rec["recommendation_id"])
        self.assertEqual(active_rec.status, RecommendationStatus.PENDING_REVIEW.value)

    # 5. Wrong evidence_hash -> rejected -> audit attempt preserved
    def test_wrong_evidence_hash_rejected(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-004",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": "sha256:" + "0" * 64,  # Altered/wrong evidence hash
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Approved with stale hash.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-04",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        status_data = status_env.payload
        self.assertEqual(status_data["status"], "Rejected")
        self.assertIn("Evidence hash mismatch", status_data["reason"])

        # Preserved in audit
        self.assertEqual(len(self.service.audit_ledger), 1)
        self.assertEqual(self.service.audit_ledger[0].decision, "APPROVED_REJECTED")
        self.assertTrue(self.service.verify_audit().is_valid)

    # 6. Unauthorized role -> rejected -> audit attempt preserved
    def test_unauthorized_role_rejected(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-005",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-LIMITED",
            "role": "LIMITED_OPERATOR",  # Can only verify equipment, but rec proposed 'inspect area'
            "decision": DecisionType.APPROVED.value,
            "reason": "Attempting unauthorized approval.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-05",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        status_data = status_env.payload
        self.assertEqual(status_data["status"], "Rejected")
        self.assertIn("Operator authorization failed", status_data["reason"])

        # Preserved in audit
        self.assertEqual(len(self.service.audit_ledger), 1)
        self.assertEqual(self.service.audit_ledger[0].decision, "APPROVED_REJECTED")

    # 7. Expired recommendation -> rejected -> audit attempt preserved
    def test_expired_recommendation_rejected(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-006",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Late approval attempt.",
            "signed_at": "2026-09-24T23:30:00Z",  # valid_until is 22:00:00Z
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-06",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T23:30:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        status_env = self.service.process_approval_decision(dec_env)
        status_data = status_env.payload
        self.assertEqual(status_data["status"], "Rejected")
        self.assertIn("exceeds recommendation valid_until", status_data["reason"])

        # Preserved in audit
        self.assertEqual(len(self.service.audit_ledger), 1)
        self.assertEqual(self.service.audit_ledger[0].decision, "APPROVED_REJECTED")

    # 8. Replay -> first accepted, second rejected, both auditable
    def test_replay_workflow(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-REPLAY-001",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Legitimate initial approval.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-07",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )

        # Attempt 1: Accepted
        res1 = self.service.process_approval_decision(dec_env)
        self.assertEqual(res1.payload["status"], RecommendationStatus.APPROVED.value)

        # Attempt 2: Replay of same decision envelope
        res2 = self.service.process_approval_decision(dec_env)
        self.assertEqual(res2.payload["status"], "Rejected")
        self.assertIn("Replay detected", res2.payload["reason"])

        # Both attempts are recorded in the audit ledger
        self.assertEqual(len(self.service.audit_ledger), 2)
        self.assertEqual(self.service.audit_ledger[0].decision, "APPROVED")
        self.assertEqual(self.service.audit_ledger[1].decision, "APPROVED_REJECTED")
        self.assertIn("Replay detected", self.service.audit_ledger[1].reason)

        # Ledger remains cryptographically valid and verifies
        self.assertTrue(self.service.verify_audit().is_valid)

    # 9. Evidence changes after approval -> Approved becomes Invalidated
    def test_invalidation_after_approval(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        # Approve recommendation
        decision_payload = {
            "decision_id": "DEC-E2E-009",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Approved before new telemetry arrives.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-09",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )
        self.service.process_approval_decision(dec_env)
        self.assertEqual(
            self.service.get_recommendation(rec["recommendation_id"]).status,
            RecommendationStatus.APPROVED.value,
        )

        # Evidence changes: New telemetry arrives
        new_alert = DomainAlert(
            alert_id="ALT-E2E-001",
            supporting_event_ids=["EVT-001", "EVT-002", "EVT-003"],  # altered
            risk_level="CRITICAL",  # altered
            confidence=0.98,
            explanation="Containment breach imminent.",
            missing_evidence=[],
            valid_until="2026-09-24T22:00:00Z",
        )

        inv_result = self.service.check_and_apply_invalidation(
            rec["recommendation_id"],
            current_alerts=[new_alert],
        )
        self.assertTrue(inv_result.is_invalidated)
        self.assertEqual(
            self.service.get_recommendation(rec["recommendation_id"]).status,
            RecommendationStatus.INVALIDATED.value,
        )

        # Previous approval preserved
        self.assertIsNotNone(inv_result.invalidation_record)
        self.assertEqual(inv_result.invalidation_record.previous_approval.decision_id, "DEC-E2E-009")

        # Invalidation recorded in audit
        self.assertEqual(len(self.service.audit_ledger), 2)
        self.assertEqual(self.service.audit_ledger[1].decision, "INVALIDATED")

        # Restart review cycle: Invalidated -> Pending Review
        pending_rec = self.service.reinitiate_review_cycle(rec["recommendation_id"])
        self.assertEqual(pending_rec.status, RecommendationStatus.PENDING_REVIEW.value)

    # 10. Tampered audit entry -> verification detects tampering
    def test_tampered_audit_entry_detected(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-010",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Authentic approval reason.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-10",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )
        self.service.process_approval_decision(dec_env)

        # Audit is initially valid
        self.assertTrue(self.service.verify_audit().is_valid)

        # Directly tamper with an in-memory entry in the ledger
        orig_entry = self.service.audit_ledger.entries[0]
        tampered_entry = AuditEntry(
            sequence_number=orig_entry.sequence_number,
            operator_id="OPR-MALICIOUS",  # tampered
            role=orig_entry.role,
            decision=orig_entry.decision,
            timestamp=orig_entry.timestamp,
            recommendation_id=orig_entry.recommendation_id,
            decision_id=orig_entry.decision_id,
            evidence_hash=orig_entry.evidence_hash,
            state_transition=orig_entry.state_transition,
            reason=orig_entry.reason,
            prev_audit_hash=orig_entry.prev_audit_hash,
            entry_hash=orig_entry.entry_hash,
        )
        self.service.audit_ledger._entries[0] = tampered_entry

        # Verification must detect the tampering
        ver_result = self.service.verify_audit()
        self.assertFalse(ver_result.is_valid)
        self.assertTrue(any("Tampered entry detected" in err for err in ver_result.errors))

    # 11. Competing/concurrent decision attempts -> deterministic final state, all auditable
    def test_competing_decision_attempts(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        # Operator 1 submits approval
        dec_env_1 = EventEnvelope(
            message_id="MSG-E2E-COMP-01",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-console-1",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload={
                "decision_id": "DEC-COMP-01",
                "recommendation_id": rec["recommendation_id"],
                "evidence_hash": rec["evidence_hash"],
                "operator_id": "OPR-ALPHA",
                "role": "VALID_OPERATOR",
                "decision": DecisionType.APPROVED.value,
                "reason": "First arrival approval.",
                "signed_at": "2026-09-24T14:00:00Z",
            },
        )
        # Operator 2 submits competing rejection concurrently
        dec_env_2 = EventEnvelope(
            message_id="MSG-E2E-COMP-02",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-console-2",
            produced_at="2026-09-24T14:00:01Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload={
                "decision_id": "DEC-COMP-02",
                "recommendation_id": rec["recommendation_id"],
                "evidence_hash": rec["evidence_hash"],
                "operator_id": "OPR-BETA",
                "role": "VALID_OPERATOR",
                "decision": DecisionType.REJECTED.value,
                "reason": "Second competing decision.",
                "signed_at": "2026-09-24T14:00:01Z",
            },
        )

        # Process first: succeeds
        res1 = self.service.process_approval_decision(dec_env_1)
        self.assertEqual(res1.payload["status"], RecommendationStatus.APPROVED.value)

        # Process second: rejected because recommendation is already in Approved state
        res2 = self.service.process_approval_decision(dec_env_2)
        self.assertEqual(res2.payload["status"], "Rejected")

        # Recommendation deterministic final state is Approved
        self.assertEqual(
            self.service.get_recommendation(rec["recommendation_id"]).status,
            RecommendationStatus.APPROVED.value,
        )

        # Both attempts are permanently retained in the audit ledger
        self.assertEqual(len(self.service.audit_ledger), 2)
        self.assertEqual(self.service.audit_ledger[0].decision_id, "DEC-COMP-01")
        self.assertEqual(self.service.audit_ledger[1].decision_id, "DEC-COMP-02")
        self.assertTrue(self.service.verify_audit().is_valid)

    # 12. Non-execution invariant: service does NOT execute proposed task
    def test_non_execution_invariant(self):
        rec_env = self.service.process_domain_alert(self.alert_envelope)
        rec = rec_env.payload

        decision_payload = {
            "decision_id": "DEC-E2E-012",
            "recommendation_id": rec["recommendation_id"],
            "evidence_hash": rec["evidence_hash"],
            "operator_id": "OPR-ALPHA",
            "role": "VALID_OPERATOR",
            "decision": DecisionType.APPROVED.value,
            "reason": "Valid approval.",
            "signed_at": "2026-09-24T14:00:00Z",
        }
        dec_env = EventEnvelope(
            message_id="MSG-E2E-DEC-12",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-E2E-001",
            producer="module-5-operator-console",
            produced_at="2026-09-24T14:00:00Z",
            correlation_id="CORR-E2E-01",
            causation_id=rec_env.message_id,
            payload=decision_payload,
        )
        status_env = self.service.process_approval_decision(dec_env)

        # Invariant checks on service and recommendation:
        # 1. Recommendation is purely a data structure
        rec_obj = self.service.get_recommendation(rec["recommendation_id"])
        self.assertFalse(hasattr(rec_obj, "execute"))
        self.assertFalse(hasattr(rec_obj, "dispatch"))
        self.assertFalse(hasattr(rec_obj, "run"))

        # 2. Service does NOT execute the task or provide execution dispatch
        self.assertFalse(hasattr(self.service, "execute_task"))
        self.assertFalse(hasattr(self.service, "dispatch_task"))
        self.assertFalse(hasattr(self.service, "run_operational_action"))

        # 3. Status is 'Approved', not 'Completed' or 'Running'
        self.assertEqual(rec_obj.status, RecommendationStatus.APPROVED.value)
        self.assertEqual(status_env.payload["status"], RecommendationStatus.APPROVED.value)


if __name__ == "__main__":
    unittest.main()
