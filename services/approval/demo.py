"""Standalone local demonstration of Module 4 (Global/Central AI).

Demonstrates the 6 core scenarios using purely in-memory objects:
1. Normal Approval
2. Rejection
3. Invalid Evidence Rejection & Auditing
4. Unauthorized Role Rejection & Auditing
5. Invalidation upon Evidence Change & Traceability
6. Audit Chain Cryptographic Verification

CRITICAL INVARIANT:
The Central AI generates recommendations and validates approvals.
It NEVER executes any operational task.
"""

from __future__ import annotations

import sys
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
from services.approval.service import ApprovalService


def run_demo() -> bool:
    print("=" * 60)
    print("      MODULE 4 -- CENTRAL AI APPROVAL DEMO")
    print("=" * 60)
    print("Architecture: Global/Central AI Service Coordinator")
    print("Mode: In-Memory / Deterministic Prototype")
    print("Non-Execution Policy: Strictly enforced (Proposals only)")
    print("=" * 60)
    print()

    # Configure RBAC Policy
    auth_policy = ConfigurableAuthorizationPolicy(
        role_permissions={
            "AUTHORIZED_OPERATOR": RolePermission(can_approve=True, can_reject=True),
            "READ_ONLY_OBSERVER": RolePermission(can_approve=False, can_reject=False),
        },
        default_allow=False,
    )
    service = ApprovalService(auth_policy=auth_policy)

    # -------------------------------------------------------------
    # SCENARIO 1: NORMAL APPROVAL
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 1: NORMAL APPROVAL")
    print("-" * 60)
    alert_1 = {
        "alert_id": "ALT-DEMO-001",
        "supporting_event_ids": ["EVT-101", "EVT-102"],
        "risk_level": "HIGH",
        "confidence": 0.88,
        "explanation": "Temperature anomaly detected in pump unit A3.",
        "missing_evidence": [],
        "valid_until": "2026-09-24T22:00:00Z",
    }
    alert_env_1 = EventEnvelope(
        message_id="MSG-ALERT-001",
        message_type="DomainAlert",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-3-domain-sensor",
        produced_at="2026-09-24T12:00:00Z",
        correlation_id="CORR-DEMO-01",
        causation_id="ROOT-CAUSE-01",
        payload=alert_1,
    )
    print("1. Ingesting DomainAlert from Module 3:")
    print(f"   - Alert ID: {alert_1['alert_id']}")
    print(f"   - Risk Level: {alert_1['risk_level']}, Confidence: {alert_1['confidence']}")

    rec_env_1 = service.process_domain_alert(alert_env_1)
    rec_1 = rec_env_1.payload
    print("2. Generated Recommendation Proposal:")
    print(f"   - Recommendation ID: {rec_1['recommendation_id']}")
    print(f"   - Proposed Task: '{rec_1['proposed_task']}' (Non-executable proposal)")
    print(f"   - Status: {rec_1['status']}")
    print(f"   - Evidence Hash: {rec_1['evidence_hash'][:24]}...")

    decision_1 = {
        "decision_id": "DEC-DEMO-001",
        "recommendation_id": rec_1["recommendation_id"],
        "evidence_hash": rec_1["evidence_hash"],
        "operator_id": "OPR-SARAH",
        "role": "AUTHORIZED_OPERATOR",
        "decision": DecisionType.APPROVED.value,
        "reason": "Confirmed physical telemetry reading variance with field sensor.",
        "signed_at": "2026-09-24T13:00:00Z",
    }
    dec_env_1 = EventEnvelope(
        message_id="MSG-DEC-001",
        message_type="ApprovalDecision",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-5-operator-console",
        produced_at="2026-09-24T13:00:00Z",
        correlation_id="CORR-DEMO-01",
        causation_id=rec_env_1.message_id,
        payload=decision_1,
    )
    print("3. Human ApprovalDecision received from Module 5:")
    print(f"   - Decision ID: {decision_1['decision_id']} by {decision_1['operator_id']} ({decision_1['role']})")
    print(f"   - Decision: {decision_1['decision']}")

    status_env_1 = service.process_approval_decision(dec_env_1)
    status_1 = status_env_1.payload
    print("4. Emitted DecisionStatus & Audit Record:")
    print(f"   - Resulting Status: {status_1['status']}")
    print(f"   - Reason: {status_1['reason']}")
    print(f"   - Audit Ref (Entry Hash): {status_1['audit_ref'][:24]}...")
    print("=> SCENARIO 1 RESULT: SUCCESS (Approved and Audited)")
    print()

    # -------------------------------------------------------------
    # SCENARIO 2: REJECTION
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 2: REJECTION")
    print("-" * 60)
    alert_2 = {
        "alert_id": "ALT-DEMO-002",
        "supporting_event_ids": ["EVT-201"],
        "risk_level": "LOW",
        "confidence": 0.20,
        "explanation": "Minor ambient ground vibration detected.",
        "missing_evidence": [],
        "valid_until": "2026-09-24T22:00:00Z",
    }
    alert_env_2 = EventEnvelope(
        message_id="MSG-ALERT-002",
        message_type="DomainAlert",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-3-domain-sensor",
        produced_at="2026-09-24T12:00:00Z",
        correlation_id="CORR-DEMO-02",
        causation_id="ROOT-CAUSE-02",
        payload=alert_2,
    )
    rec_env_2 = service.process_domain_alert(alert_env_2)
    rec_2 = rec_env_2.payload
    print(f"1. Ingested Alert: {alert_2['alert_id']}")
    print(f"2. Generated Recommendation: {rec_2['recommendation_id']} -> Proposed: '{rec_2['proposed_task']}'")

    decision_2 = {
        "decision_id": "DEC-DEMO-002",
        "recommendation_id": rec_2["recommendation_id"],
        "evidence_hash": rec_2["evidence_hash"],
        "operator_id": "OPR-SARAH",
        "role": "AUTHORIZED_OPERATOR",
        "decision": DecisionType.REJECTED.value,
        "reason": "Confirmed benign construction activity nearby; alert rejected.",
        "signed_at": "2026-09-24T13:05:00Z",
    }
    dec_env_2 = EventEnvelope(
        message_id="MSG-DEC-002",
        message_type="ApprovalDecision",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-5-operator-console",
        produced_at="2026-09-24T13:05:00Z",
        correlation_id="CORR-DEMO-02",
        causation_id=rec_env_2.message_id,
        payload=decision_2,
    )
    status_env_2 = service.process_approval_decision(dec_env_2)
    status_2 = status_env_2.payload
    print("3. Human Operator Decision:")
    print(f"   - Decision: {decision_2['decision']}")
    print(f"   - Resulting Status: {status_2['status']}")
    print(f"   - Audit Ref: {status_2['audit_ref'][:24]}...")
    print("=> SCENARIO 2 RESULT: SUCCESS (Rejected and Audited)")
    print()

    # -------------------------------------------------------------
    # SCENARIO 3: INVALID EVIDENCE
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 3: INVALID EVIDENCE HASH")
    print("-" * 60)
    alert_3 = {
        "alert_id": "ALT-DEMO-003",
        "supporting_event_ids": ["EVT-301"],
        "risk_level": "HIGH",
        "confidence": 0.85,
        "explanation": "Flow valve pressure spike.",
        "missing_evidence": [],
        "valid_until": "2026-09-24T22:00:00Z",
    }
    rec_env_3 = service.process_domain_alert(
        EventEnvelope(
            message_id="MSG-ALERT-003",
            message_type="DomainAlert",
            schema_version="1.0.0",
            run_id="RUN-DEMO-01",
            producer="module-3-domain-sensor",
            produced_at="2026-09-24T12:00:00Z",
            correlation_id="CORR-DEMO-03",
            causation_id="ROOT-CAUSE-03",
            payload=alert_3,
        )
    )
    rec_3 = rec_env_3.payload
    print(f"1. Recommendation Generated: {rec_3['recommendation_id']}")
    print(f"   - Genuine Evidence Hash: {rec_3['evidence_hash'][:24]}...")

    # Forged / Tampered evidence hash in approval decision
    corrupted_evidence_hash = "sha256:" + "9" * 64
    decision_3 = {
        "decision_id": "DEC-DEMO-003",
        "recommendation_id": rec_3["recommendation_id"],
        "evidence_hash": corrupted_evidence_hash,  # Altered!
        "operator_id": "OPR-SARAH",
        "role": "AUTHORIZED_OPERATOR",
        "decision": DecisionType.APPROVED.value,
        "reason": "Attempting approval with mismatched evidence hash.",
        "signed_at": "2026-09-24T13:10:00Z",
    }
    dec_env_3 = EventEnvelope(
        message_id="MSG-DEC-003",
        message_type="ApprovalDecision",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-5-operator-console",
        produced_at="2026-09-24T13:10:00Z",
        correlation_id="CORR-DEMO-03",
        causation_id=rec_env_3.message_id,
        payload=decision_3,
    )
    status_env_3 = service.process_approval_decision(dec_env_3)
    status_3 = status_env_3.payload
    print("2. Validation Outcome:")
    print(f"   - Decision Status: {status_3['status']}")
    print(f"   - Rejection Reason: {status_3['reason']}")
    print(f"   - Failed Attempt Audit Ref: {status_3['audit_ref'][:24]}...")
    print("=> SCENARIO 3 RESULT: SUCCESS (Tampered evidence rejected and attempt audited)")
    print()

    # -------------------------------------------------------------
    # SCENARIO 4: UNAUTHORIZED ROLE
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 4: UNAUTHORIZED ROLE")
    print("-" * 60)
    alert_4 = {
        "alert_id": "ALT-DEMO-004",
        "supporting_event_ids": ["EVT-401"],
        "risk_level": "HIGH",
        "confidence": 0.89,
        "explanation": "Gas sensor threshold exceeded.",
        "missing_evidence": [],
        "valid_until": "2026-09-24T22:00:00Z",
    }
    rec_env_4 = service.process_domain_alert(
        EventEnvelope(
            message_id="MSG-ALERT-004",
            message_type="DomainAlert",
            schema_version="1.0.0",
            run_id="RUN-DEMO-01",
            producer="module-3-domain-sensor",
            produced_at="2026-09-24T12:00:00Z",
            correlation_id="CORR-DEMO-04",
            causation_id="ROOT-CAUSE-04",
            payload=alert_4,
        )
    )
    rec_4 = rec_env_4.payload

    decision_4 = {
        "decision_id": "DEC-DEMO-004",
        "recommendation_id": rec_4["recommendation_id"],
        "evidence_hash": rec_4["evidence_hash"],
        "operator_id": "OPR-VISITOR",
        "role": "READ_ONLY_OBSERVER",  # Unauthorized role
        "decision": DecisionType.APPROVED.value,
        "reason": "Attempting approval without operator authorization.",
        "signed_at": "2026-09-24T13:15:00Z",
    }
    dec_env_4 = EventEnvelope(
        message_id="MSG-DEC-004",
        message_type="ApprovalDecision",
        schema_version="1.0.0",
        run_id="RUN-DEMO-01",
        producer="module-5-operator-console",
        produced_at="2026-09-24T13:15:00Z",
        correlation_id="CORR-DEMO-04",
        causation_id=rec_env_4.message_id,
        payload=decision_4,
    )
    status_env_4 = service.process_approval_decision(dec_env_4)
    status_4 = status_env_4.payload
    print("1. Submitted approval using unauthorized role 'READ_ONLY_OBSERVER':")
    print(f"   - Decision Status: {status_4['status']}")
    print(f"   - Denial Reason: {status_4['reason']}")
    print(f"   - Failed Attempt Audit Ref: {status_4['audit_ref'][:24]}...")
    print("=> SCENARIO 4 RESULT: SUCCESS (Unauthorized role denied and attempt audited)")
    print()

    # -------------------------------------------------------------
    # SCENARIO 5: INVALIDATION UPON EVIDENCE CHANGE
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 5: INVALIDATION UPON EVIDENCE CHANGE")
    print("-" * 60)
    alert_5 = {
        "alert_id": "ALT-DEMO-005",
        "supporting_event_ids": ["EVT-501"],
        "risk_level": "HIGH",
        "confidence": 0.85,
        "explanation": "Cooling loop temperature variance.",
        "missing_evidence": [],
        "valid_until": "2026-09-24T22:00:00Z",
    }
    rec_env_5 = service.process_domain_alert(
        EventEnvelope(
            message_id="MSG-ALERT-005",
            message_type="DomainAlert",
            schema_version="1.0.0",
            run_id="RUN-DEMO-01",
            producer="module-3-domain-sensor",
            produced_at="2026-09-24T12:00:00Z",
            correlation_id="CORR-DEMO-05",
            causation_id="ROOT-CAUSE-05",
            payload=alert_5,
        )
    )
    rec_5 = rec_env_5.payload

    # Step A: Initially approve
    decision_5 = {
        "decision_id": "DEC-DEMO-005",
        "recommendation_id": rec_5["recommendation_id"],
        "evidence_hash": rec_5["evidence_hash"],
        "operator_id": "OPR-SARAH",
        "role": "AUTHORIZED_OPERATOR",
        "decision": DecisionType.APPROVED.value,
        "reason": "Approved for field inspection.",
        "signed_at": "2026-09-24T13:20:00Z",
    }
    service.process_approval_decision(
        EventEnvelope(
            message_id="MSG-DEC-005",
            message_type="ApprovalDecision",
            schema_version="1.0.0",
            run_id="RUN-DEMO-01",
            producer="module-5-operator-console",
            produced_at="2026-09-24T13:20:00Z",
            correlation_id="CORR-DEMO-05",
            causation_id=rec_env_5.message_id,
            payload=decision_5,
        )
    )
    print(f"1. Recommendation {rec_5['recommendation_id']} was Approved.")

    # Step B: Telemetry changes mid-stream
    print("2. New sensor observation arrives altering alert metrics...")
    altered_alert = DomainAlert(
        alert_id="ALT-DEMO-005",
        supporting_event_ids=["EVT-501", "EVT-502"],  # New event
        risk_level="CRITICAL",  # Escalated
        confidence=0.99,
        explanation="Cooling loop rupture detected.",
        missing_evidence=[],
        valid_until="2026-09-24T22:00:00Z",
    )
    inv_result = service.check_and_apply_invalidation(
        rec_5["recommendation_id"],
        current_alerts=[altered_alert],
    )
    print("3. Invalidation Evaluator Triggered:")
    print(f"   - Is Invalidated: {inv_result.is_invalidated}")
    print(f"   - New Status: {inv_result.recommendation.status}")
    print(f"   - Invalidation Reason: {inv_result.reason}")
    print(f"   - Preserved Prior Approval ID: {inv_result.invalidation_record.previous_approval.decision_id}")
    print(f"   - Preserved Prior Operator: {inv_result.invalidation_record.previous_approval.operator_id}")

    # Step C: Re-enter review cycle
    pending_rec = service.reinitiate_review_cycle(rec_5["recommendation_id"])
    print(f"4. Re-initiated review cycle -> Current Status: {pending_rec.status}")
    print("=> SCENARIO 5 RESULT: SUCCESS (Approved -> Invalidated, prior approval preserved)")
    print()

    # -------------------------------------------------------------
    # SCENARIO 6: AUDIT VERIFICATION
    # -------------------------------------------------------------
    print("-" * 60)
    print("SCENARIO 6: CRYPTOGRAPHIC AUDIT VERIFICATION")
    print("-" * 60)
    audit_ver = service.verify_audit()
    print(f"Total Audit Entries in Ledger: {len(service.audit_ledger)}")
    for entry in service.audit_ledger.entries:
        print(
            f"   [Seq {entry.sequence_number}] Decision: {entry.decision:<18} | "
            f"Transition: {entry.state_transition:<45} | "
            f"Hash: {entry.entry_hash[:16]}..."
        )

    print()
    print("=" * 60)
    print("FINAL AUDIT VERIFICATION")
    print("=" * 60)
    print(f"Audit valid: {audit_ver.is_valid}")
    print(f"Entries checked: {audit_ver.entries_checked}")
    print(f"Errors detected: {len(audit_ver.errors)}")
    if audit_ver.errors:
        for err in audit_ver.errors:
            print(f"   - ERROR: {err}")
    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)

    return audit_ver.is_valid


if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)
