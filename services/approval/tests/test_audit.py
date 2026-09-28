"""Unit tests for Audit Ledger and Tamper Verification in Module 4.

Covers:
1. Valid audit entry is appended.
2. Audit entries preserve chronological/history order.
3. Previous audit hash correctly links entries.
4. Audit chain verifies successfully when unchanged.
5. Modified audit entry is detected.
6. Missing/deleted entry is detected.
7. Broken previous-hash link is detected.
8. Invalid state transition is detected.
9. Evidence mismatch is detected.
10. Replayed decision remains auditable and is detected.
11. Rejected decisions remain in the audit.
12. Concurrent/competing decision attempts remain in the audit.
13. Verification is deterministic.
14. Empty audit ledger is handled correctly.
"""

import unittest
from services.approval.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditLedger,
    compute_audit_entry_hash,
    verify_audit_ledger,
)


class TestAuditLedger(unittest.TestCase):

    def setUp(self):
        self.ledger = AuditLedger()
        self.evidence_hash_1 = "sha256:" + "1" * 64
        self.evidence_hash_2 = "sha256:" + "2" * 64

    # 1. Valid audit entry is appended
    def test_valid_audit_entry_appended(self):
        entry = self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_REVIEWER",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-AUD-01",
            decision_id="DEC-AUD-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Confirmed clear area.",
        )
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(entry.sequence_number, 1)
        self.assertEqual(entry.prev_audit_hash, GENESIS_HASH)
        self.assertTrue(entry.entry_hash.startswith("sha256:"))

    # 2. Audit entries preserve chronological/history order
    def test_entries_preserve_chronological_order(self):
        e1 = self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_REVIEWER",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-AUD-01",
            decision_id="DEC-AUD-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Step 1",
        )
        e2 = self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_SUPERVISOR",
            decision="COMPLETED",
            timestamp="2026-09-24T12:05:00Z",
            recommendation_id="REC-AUD-01",
            decision_id="DEC-AUD-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Completed",
            reason="Step 2",
        )
        self.assertEqual(self.ledger.entries[0], e1)
        self.assertEqual(self.ledger.entries[1], e2)
        self.assertEqual(e1.sequence_number, 1)
        self.assertEqual(e2.sequence_number, 2)

    # 3. Previous audit hash correctly links entries
    def test_previous_audit_hash_links_entries(self):
        e1 = self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Reason 1",
        )
        e2 = self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_B",
            decision="COMPLETED",
            timestamp="2026-09-24T12:05:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Completed",
            reason="Reason 2",
        )
        self.assertEqual(e1.prev_audit_hash, GENESIS_HASH)
        self.assertEqual(e2.prev_audit_hash, e1.entry_hash)

    # 4. Audit chain verifies successfully when unchanged
    def test_audit_chain_verifies_successfully(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Approved",
        )
        self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_B",
            decision="COMPLETED",
            timestamp="2026-09-24T12:10:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Completed",
            reason="Completed",
        )
        result = verify_audit_ledger(self.ledger)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.entries_checked, 2)

    # 5. Modified audit entry is detected
    def test_modified_audit_entry_detected(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Legitimate approval",
        )
        # Tamper with entry in a shallow copy list
        tampered_entries = list(self.ledger.entries)
        orig = tampered_entries[0]
        # Modify the reason without updating entry_hash
        tampered_entry = AuditEntry(
            sequence_number=orig.sequence_number,
            operator_id=orig.operator_id,
            role=orig.role,
            decision=orig.decision,
            timestamp=orig.timestamp,
            recommendation_id=orig.recommendation_id,
            decision_id=orig.decision_id,
            evidence_hash=orig.evidence_hash,
            state_transition=orig.state_transition,
            reason="Tampered fraudulent reason",  # altered
            prev_audit_hash=orig.prev_audit_hash,
            entry_hash=orig.entry_hash,
        )
        tampered_entries[0] = tampered_entry

        result = verify_audit_ledger(tampered_entries)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Tampered entry detected" in e for e in result.errors))

    # 6. Missing/deleted entry is detected
    def test_missing_entry_detected(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Entry 1",
        )
        self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_B",
            decision="COMPLETED",
            timestamp="2026-09-24T12:05:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Completed",
            reason="Entry 2",
        )
        # Drop the first entry
        incomplete_entries = [self.ledger.entries[1]]
        result = verify_audit_ledger(incomplete_entries)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Missing or out-of-order entry" in e for e in result.errors))

    # 7. Broken previous-hash link is detected
    def test_broken_previous_hash_link_detected(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Entry 1",
        )
        self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_B",
            decision="COMPLETED",
            timestamp="2026-09-24T12:05:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Completed",
            reason="Entry 2",
        )
        entries = list(self.ledger.entries)
        orig2 = entries[1]
        # Break prev_audit_hash link
        broken_entry = AuditEntry(
            sequence_number=orig2.sequence_number,
            operator_id=orig2.operator_id,
            role=orig2.role,
            decision=orig2.decision,
            timestamp=orig2.timestamp,
            recommendation_id=orig2.recommendation_id,
            decision_id=orig2.decision_id,
            evidence_hash=orig2.evidence_hash,
            state_transition=orig2.state_transition,
            reason=orig2.reason,
            prev_audit_hash="sha256:" + "f" * 64,  # broken link
            entry_hash=orig2.entry_hash,
        )
        entries[1] = broken_entry

        result = verify_audit_ledger(entries)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Broken hash chain link" in e for e in result.errors))

    # 8. Invalid state transition is detected
    def test_invalid_state_transition_detected(self):
        # Entry claiming transition Draft -> Approved directly (illegal bypass)
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Draft -> Approved",  # Illegal transition
            reason="Illegal jump",
        )
        result = verify_audit_ledger(self.ledger)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Illegal state transition" in e for e in result.errors))

    # 9. Evidence mismatch is detected
    def test_evidence_mismatch_detected(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Valid approval",
        )
        # Second entry changes evidence_hash without invalidation
        self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_B",
            decision="COMPLETED",
            timestamp="2026-09-24T12:10:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-02",
            evidence_hash=self.evidence_hash_2,  # mismatched evidence hash
            state_transition="Approved -> Completed",
            reason="Completed with different evidence",
        )
        result = verify_audit_ledger(self.ledger)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Evidence mismatch" in e for e in result.errors))

    # 10. Replayed decision remains auditable and is detected
    def test_replayed_decision_detected(self):
        # First entry: initial approval
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-REPLAY-1",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Initial approval",
        )
        # Suppose a corrupted second entry applies the same decision_id again
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:01:00Z",
            recommendation_id="REC-02",
            decision_id="DEC-REPLAY-1",  # Same decision_id applied again!
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Replayed approval",
        )
        result = verify_audit_ledger(self.ledger)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Replayed decision violation" in e for e in result.errors))

    # 11. Rejected decisions remain in the audit
    def test_rejected_decisions_remain_in_audit(self):
        entry = self.ledger.append_entry(
            operator_id="OPR-05",
            role="ROLE_REVIEWER",
            decision="REJECTED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-REJ-01",
            decision_id="DEC-REJ-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Rejected",
            reason="Alert deemed spurious.",
        )
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(self.ledger.entries[0].decision, "REJECTED")
        result = verify_audit_ledger(self.ledger)
        self.assertTrue(result.is_valid)

    # 12. Concurrent/competing decision attempts remain in the audit
    def test_competing_decision_attempts_remain_in_audit(self):
        # Operator 1 approves first
        e1 = self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_ALPHA",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-COMPETE-01",
            decision_id="DEC-COMP-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Accepted by Operator 1.",
        )
        # Operator 2 attempts a competing decision that is rejected by validator
        e2 = self.ledger.append_entry(
            operator_id="OPR-02",
            role="ROLE_BETA",
            decision="REJECTED_ATTEMPT",
            timestamp="2026-09-24T12:00:02Z",
            recommendation_id="REC-COMPETE-01",
            decision_id="DEC-COMP-02",
            evidence_hash=self.evidence_hash_1,
            state_transition="Approved -> Approved (Attempt Rejected: Already in Approved state)",
            reason="Competing approval attempt rejected.",
        )
        self.assertEqual(len(self.ledger), 2)
        # Both attempts are permanently retained in audit trail
        self.assertEqual(self.ledger.entries[0].decision_id, "DEC-COMP-01")
        self.assertEqual(self.ledger.entries[1].decision_id, "DEC-COMP-02")

        result = verify_audit_ledger(self.ledger)
        self.assertTrue(result.is_valid)

    # 13. Verification is deterministic
    def test_verification_is_deterministic(self):
        self.ledger.append_entry(
            operator_id="OPR-01",
            role="ROLE_A",
            decision="APPROVED",
            timestamp="2026-09-24T12:00:00Z",
            recommendation_id="REC-01",
            decision_id="DEC-01",
            evidence_hash=self.evidence_hash_1,
            state_transition="Pending Review -> Approved",
            reason="Valid",
        )
        res1 = verify_audit_ledger(self.ledger)
        res2 = verify_audit_ledger(self.ledger)
        self.assertEqual(res1.is_valid, res2.is_valid)
        self.assertEqual(res1.errors, res2.errors)
        self.assertEqual(res1.entries_checked, res2.entries_checked)

    # 14. Empty audit ledger is handled correctly
    def test_empty_audit_ledger_handled(self):
        empty_ledger = AuditLedger()
        result = verify_audit_ledger(empty_ledger)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.entries_checked, 0)
        self.assertEqual(len(result.errors), 0)


if __name__ == "__main__":
    unittest.main()
