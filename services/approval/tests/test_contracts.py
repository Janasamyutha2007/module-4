"""Unit tests for Module 4 local data contracts and envelopes."""

import unittest
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


class TestModule4Contracts(unittest.TestCase):

    def test_domain_alert_creation_and_serialization(self):
        alert_dict = {
            "alert_id": "ALT-2026-001",
            "supporting_event_ids": ["EVT-100", "EVT-101"],
            "risk_level": "HIGH",
            "confidence": 0.88,
            "explanation": "Temperature anomaly detected in pump unit A3.",
            "missing_evidence": ["sensor_calibration_log"],
            "valid_until": "2026-09-24T14:00:00Z",
        }
        alert = DomainAlert.from_dict(alert_dict)
        self.assertEqual(alert.alert_id, "ALT-2026-001")
        self.assertEqual(alert.supporting_event_ids, ["EVT-100", "EVT-101"])
        self.assertEqual(alert.risk_level, "HIGH")
        self.assertEqual(alert.confidence, 0.88)
        self.assertEqual(alert.explanation, "Temperature anomaly detected in pump unit A3.")
        self.assertEqual(alert.missing_evidence, ["sensor_calibration_log"])
        self.assertEqual(alert.valid_until, "2026-09-24T14:00:00Z")

        # Roundtrip serialization
        serialized = alert.to_dict()
        self.assertEqual(serialized, alert_dict)

    def test_recommendation_allowed_actions_and_statuses(self):
        # Valid actions
        for action in [
            "inspect area",
            "verify equipment",
            "request another observation",
            "dismiss alert",
        ]:
            rec = Recommendation(
                recommendation_id="REC-001",
                alert_ids=["ALT-001"],
                proposed_task=action,
                rationale="Deterministic rule matched.",
                evidence_hash="sha256:" + "a" * 64,
                policy_version="1.0.0",
                status="Pending Review",
                valid_until="2026-09-24T15:00:00Z",
            )
            self.assertEqual(rec.proposed_task, action)

        # Disallowed action should raise ValueError
        with self.assertRaises(ValueError):
            Recommendation(
                recommendation_id="REC-002",
                alert_ids=["ALT-001"],
                proposed_task="execute shutdown sequence",  # Not in allowed benign actions
                rationale="Invalid active operational action",
                evidence_hash="sha256:" + "a" * 64,
                policy_version="1.0.0",
                status="Pending Review",
                valid_until="2026-09-24T15:00:00Z",
            )

        # Disallowed status should raise ValueError
        with self.assertRaises(ValueError):
            Recommendation(
                recommendation_id="REC-003",
                alert_ids=["ALT-001"],
                proposed_task="inspect area",
                rationale="Valid rationale",
                evidence_hash="sha256:" + "a" * 64,
                policy_version="1.0.0",
                status="In Progress",  # Not in allowed statuses
                valid_until="2026-09-24T15:00:00Z",
            )

    def test_approval_decision_validation(self):
        decision_dict = {
            "decision_id": "DEC-9001",
            "recommendation_id": "REC-001",
            "evidence_hash": "sha256:" + "b" * 64,
            "operator_id": "OPR-42",
            "role": "SECURITY_SUPERVISOR",
            "decision": "APPROVED",
            "reason": "Confirmed physical telemetry variance.",
            "signed_at": "2026-09-24T12:30:00Z",
        }
        decision = ApprovalDecision.from_dict(decision_dict)
        self.assertEqual(decision.decision, "APPROVED")
        self.assertEqual(decision.to_dict(), decision_dict)

        # Invalid decision type
        invalid_dict = dict(decision_dict, decision="MAYBE")
        with self.assertRaises(ValueError):
            ApprovalDecision.from_dict(invalid_dict)

    def test_decision_status_roundtrip(self):
        status_dict = {
            "event_id": "EVT-STAT-001",
            "recommendation_id": "REC-001",
            "decision_id": "DEC-9001",
            "status": "Approved",
            "reason": "Decision successfully validated and committed to audit ledger.",
            "committed_at": "2026-09-24T12:30:05Z",
            "audit_ref": "audit-entry-hash-001",
        }
        status = DecisionStatus.from_dict(status_dict)
        self.assertEqual(status.status, "Approved")
        self.assertEqual(status.audit_ref, "audit-entry-hash-001")
        self.assertEqual(status.to_dict(), status_dict)

    def test_event_envelope_wrapping(self):
        envelope_data = {
            "message_id": "MSG-7788",
            "message_type": "DomainAlert",
            "schema_version": "1.0.0",
            "run_id": "RUN-2026-09-24",
            "producer": "module-3-domain-sensor",
            "produced_at": "2026-09-24T12:00:00Z",
            "correlation_id": "CORR-1122",
            "causation_id": "CAUSE-0011",
            "payload": {
                "alert_id": "ALT-001",
                "supporting_event_ids": ["EVT-1"],
                "risk_level": "LOW",
                "confidence": 0.95,
                "explanation": "Minor pressure variance.",
                "missing_evidence": [],
                "valid_until": "2026-09-24T13:00:00Z",
            },
        }
        envelope = EventEnvelope.from_dict(envelope_data)
        self.assertEqual(envelope.message_id, "MSG-7788")
        self.assertEqual(envelope.producer, "module-3-domain-sensor")
        self.assertIn("alert_id", envelope.payload)

        # Verify JSON serialization
        json_output = envelope.to_json()
        self.assertIn('"message_id": "MSG-7788"', json_output)


if __name__ == "__main__":
    unittest.main()
