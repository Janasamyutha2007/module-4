"""Unit tests for Evidence Binding and Recommendation Engine.

Covers:
1. Same evidence produces the same evidence_hash.
2. Changed evidence produces a different evidence_hash.
3. Same recommendation inputs produce the same recommendation_hash.
4. Changed proposal changes recommendation_hash.
5. Changed policy version changes recommendation_hash.
6. Recommendation generation is deterministic.
7. Only the four allowed actions can be produced.
8. Recommendation remains non-executable.
"""

import re
import unittest
from services.approval.contracts import (
    AllowedAction,
    DomainAlert,
    Recommendation,
    RecommendationStatus,
)
from services.approval.engine import (
    ResourceConstraints,
    rank_and_generate_recommendation,
)
from services.approval.evidence import (
    compute_alert_content_hash,
    compute_evidence_hash,
    compute_recommendation_hash,
)


class TestEvidenceAndEngine(unittest.TestCase):

    def setUp(self):
        self.alert_1 = DomainAlert(
            alert_id="ALT-001",
            supporting_event_ids=["EVT-10", "EVT-11"],
            risk_level="HIGH",
            confidence=0.85,
            explanation="Thermal leak detected in Sector B.",
            missing_evidence=[],
            valid_until="2026-09-24T18:00:00Z",
        )
        self.alert_2 = DomainAlert(
            alert_id="ALT-002",
            supporting_event_ids=["EVT-20"],
            risk_level="MEDIUM",
            confidence=0.60,
            explanation="Pressure drop in valve V-4.",
            missing_evidence=["valve_calibration_report"],
            valid_until="2026-09-24T19:00:00Z",
        )

    # 1. Same evidence produces the same evidence_hash
    def test_same_evidence_produces_same_evidence_hash(self):
        hash1 = compute_evidence_hash([self.alert_1, self.alert_2])
        hash2 = compute_evidence_hash([self.alert_2, self.alert_1])  # Order permutation
        self.assertEqual(hash1, hash2)
        # Format check: sha256:<64 hex chars>
        self.assertTrue(re.match(r"^sha256:[0-9a-f]{64}$", hash1))

    # 2. Changed evidence produces a different evidence_hash
    def test_changed_evidence_produces_different_evidence_hash(self):
        base_hash = compute_evidence_hash(self.alert_1)

        # Modifying explanation
        modified_explanation = DomainAlert(
            alert_id=self.alert_1.alert_id,
            supporting_event_ids=self.alert_1.supporting_event_ids,
            risk_level=self.alert_1.risk_level,
            confidence=self.alert_1.confidence,
            explanation="Thermal leak corrected in Sector B.",  # altered
            missing_evidence=self.alert_1.missing_evidence,
            valid_until=self.alert_1.valid_until,
        )
        self.assertNotEqual(base_hash, compute_evidence_hash(modified_explanation))

        # Modifying confidence
        modified_conf = DomainAlert(
            alert_id=self.alert_1.alert_id,
            supporting_event_ids=self.alert_1.supporting_event_ids,
            risk_level=self.alert_1.risk_level,
            confidence=0.99,  # altered
            explanation=self.alert_1.explanation,
            missing_evidence=self.alert_1.missing_evidence,
            valid_until=self.alert_1.valid_until,
        )
        self.assertNotEqual(base_hash, compute_evidence_hash(modified_conf))

        # Modifying missing_evidence
        modified_missing = DomainAlert(
            alert_id=self.alert_1.alert_id,
            supporting_event_ids=self.alert_1.supporting_event_ids,
            risk_level=self.alert_1.risk_level,
            confidence=self.alert_1.confidence,
            explanation=self.alert_1.explanation,
            missing_evidence=["infrared_image"],  # altered
            valid_until=self.alert_1.valid_until,
        )
        self.assertNotEqual(base_hash, compute_evidence_hash(modified_missing))

    # 3. Same recommendation inputs produce the same recommendation_hash
    def test_same_recommendation_inputs_produce_same_recommendation_hash(self):
        rec_hash1 = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )
        rec_hash2 = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )
        self.assertEqual(rec_hash1, rec_hash2)
        self.assertTrue(re.match(r"^sha256:[0-9a-f]{64}$", rec_hash1))

    # 4. Changed proposal changes recommendation_hash
    def test_changed_proposal_changes_recommendation_hash(self):
        base_rec_hash = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )

        # Alter proposed task
        altered_task_hash = compute_recommendation_hash(
            proposed_task="verify equipment",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )
        self.assertNotEqual(base_rec_hash, altered_task_hash)

        # Alter rationale
        altered_rationale_hash = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="Different rationale text.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )
        self.assertNotEqual(base_rec_hash, altered_rationale_hash)

    # 5. Changed policy version changes recommendation_hash
    def test_changed_policy_version_changes_recommendation_hash(self):
        base_rec_hash = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="1.0.0",
        )
        new_version_hash = compute_recommendation_hash(
            proposed_task="inspect area",
            rationale="High risk detected.",
            valid_until="2026-09-24T18:00:00Z",
            evidence_hash="sha256:" + "0" * 64,
            policy_version="2.0.0",
        )
        self.assertNotEqual(base_rec_hash, new_version_hash)

    # 6. Recommendation generation is deterministic
    def test_recommendation_generation_is_deterministic(self):
        rec1 = rank_and_generate_recommendation(
            [self.alert_1, self.alert_2],
            policy_version="1.0.0",
            reference_time_iso="2026-09-24T12:00:00Z",
        )
        rec2 = rank_and_generate_recommendation(
            [self.alert_2, self.alert_1],  # permuted input order
            policy_version="1.0.0",
            reference_time_iso="2026-09-24T12:00:00Z",
        )
        self.assertEqual(rec1.recommendation_id, rec2.recommendation_id)
        self.assertEqual(rec1.proposed_task, rec2.proposed_task)
        self.assertEqual(rec1.rationale, rec2.rationale)
        self.assertEqual(rec1.evidence_hash, rec2.evidence_hash)
        self.assertEqual(rec1.valid_until, rec2.valid_until)
        self.assertEqual(rec1.status, rec2.status)

    # 7. Only the four allowed actions can be produced
    def test_only_four_allowed_actions_can_be_produced(self):
        allowed = AllowedAction.values()

        # High risk, high confidence -> inspect area
        rec_high = rank_and_generate_recommendation([self.alert_1])
        self.assertIn(rec_high.proposed_task, allowed)
        self.assertEqual(rec_high.proposed_task, AllowedAction.INSPECT_AREA.value)

        # Missing evidence, lower confidence -> request another observation
        rec_missing = rank_and_generate_recommendation([self.alert_2])
        self.assertIn(rec_missing.proposed_task, allowed)
        self.assertEqual(rec_missing.proposed_task, AllowedAction.REQUEST_ANOTHER_OBSERVATION.value)

        # Sensor keyword equipment anomaly -> verify equipment
        alert_sensor = DomainAlert(
            alert_id="ALT-003",
            supporting_event_ids=["EVT-30"],
            risk_level="HIGH",
            confidence=0.75,
            explanation="Telemetry sensor malfunction suspected on compressor C-1.",
            missing_evidence=[],
            valid_until="2026-09-24T20:00:00Z",
        )
        rec_sensor = rank_and_generate_recommendation(
            [alert_sensor],
            constraints=ResourceConstraints(allow_inspect_area=False),
        )
        self.assertIn(rec_sensor.proposed_task, allowed)
        self.assertEqual(rec_sensor.proposed_task, AllowedAction.VERIFY_EQUIPMENT.value)

        # Low risk, low confidence -> dismiss alert
        alert_low = DomainAlert(
            alert_id="ALT-004",
            supporting_event_ids=["EVT-40"],
            risk_level="LOW",
            confidence=0.15,
            explanation="Uncorrelated background noise.",
            missing_evidence=[],
            valid_until="2026-09-24T20:00:00Z",
        )
        rec_dismiss = rank_and_generate_recommendation([alert_low])
        self.assertIn(rec_dismiss.proposed_task, allowed)
        self.assertEqual(rec_dismiss.proposed_task, AllowedAction.DISMISS_ALERT.value)

    # 8. Recommendation remains non-executable
    def test_recommendation_remains_non_executable(self):
        rec = rank_and_generate_recommendation([self.alert_1])
        # Assert status is purely proposal / pending review
        self.assertEqual(rec.status, RecommendationStatus.PENDING_REVIEW.value)
        # Assert Recommendation has no execution methods
        self.assertFalse(hasattr(rec, "execute"))
        self.assertFalse(hasattr(rec, "dispatch"))
        self.assertFalse(hasattr(rec, "run"))
        self.assertFalse(hasattr(rec, "trigger"))


if __name__ == "__main__":
    unittest.main()
