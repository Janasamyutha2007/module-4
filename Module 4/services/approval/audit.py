"""Append-only, tamper-evident audit ledger and verification for Module 4.

Maintains cryptographic hash-chain linkage:
  entry_hash = sha256(canonical(entry_data + prev_audit_hash))
Enforces:
- Immutable audit history
- Audit verification detecting modification, deletions, broken links,
  invalid state transitions, evidence mismatches, and replayed decisions.
- Recording of both accepted and rejected/competing decision attempts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, List, Optional, Sequence, Tuple

from services.approval.contracts import DecisionType, RecommendationStatus
from services.approval.state_machine import TERMINAL_STATES, VALID_TRANSITIONS

GENESIS_HASH = "sha256:" + "0" * 64
HASH_REGEX = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class AuditEntry:
    """An immutable, cryptographically chained audit record."""
    sequence_number: int
    operator_id: str
    role: str
    decision: str
    timestamp: str
    recommendation_id: str
    decision_id: str
    evidence_hash: str
    state_transition: str
    reason: str
    prev_audit_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_audit_entry_hash(
    *,
    sequence_number: int,
    operator_id: str,
    role: str,
    decision: str,
    timestamp: str,
    recommendation_id: str,
    decision_id: str,
    evidence_hash: str,
    state_transition: str,
    reason: str,
    prev_audit_hash: str,
) -> str:
    """Compute canonical SHA-256 hash for an audit entry."""
    canonical_dict = {
        "decision": decision,
        "decision_id": decision_id,
        "evidence_hash": evidence_hash,
        "operator_id": operator_id,
        "prev_audit_hash": prev_audit_hash,
        "reason": reason,
        "recommendation_id": recommendation_id,
        "role": role,
        "sequence_number": sequence_number,
        "state_transition": state_transition,
        "timestamp": timestamp,
    }
    encoded = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest().lower()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class AuditVerificationResult:
    """Outcome of verifying audit ledger integrity."""
    is_valid: bool
    errors: list[str]
    entries_checked: int


class AuditLedger:
    """Append-only audit ledger."""

    def __init__(self, entries: Optional[Sequence[AuditEntry]] = None) -> None:
        self._entries: list[AuditEntry] = list(entries) if entries else []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __getitem__(self, index: int) -> AuditEntry:
        return self._entries[index]

    def append_entry(
        self,
        *,
        operator_id: str,
        role: str,
        decision: str,
        timestamp: str,
        recommendation_id: str,
        decision_id: str,
        evidence_hash: str,
        state_transition: str,
        reason: str,
    ) -> AuditEntry:
        """Append an immutable audit entry to the ledger."""
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH

        entry_hash = compute_audit_entry_hash(
            sequence_number=seq,
            operator_id=operator_id,
            role=role,
            decision=decision,
            timestamp=timestamp,
            recommendation_id=recommendation_id,
            decision_id=decision_id,
            evidence_hash=evidence_hash,
            state_transition=state_transition,
            reason=reason,
            prev_audit_hash=prev_hash,
        )

        entry = AuditEntry(
            sequence_number=seq,
            operator_id=operator_id,
            role=role,
            decision=decision,
            timestamp=timestamp,
            recommendation_id=recommendation_id,
            decision_id=decision_id,
            evidence_hash=evidence_hash,
            state_transition=state_transition,
            reason=reason,
            prev_audit_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry


def _parse_transition(state_transition_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract (source_state, target_state) from transition string."""
    # Matches patterns like "StateA -> StateB" or "StateA -> StateB (Reason/Note)"
    clean = state_transition_str.split("(")[0].strip()
    if "->" in clean:
        parts = [p.strip() for p in clean.split("->")]
        return parts[0], parts[1]
    return None, None


def verify_audit_ledger(ledger: AuditLedger | Sequence[AuditEntry]) -> AuditVerificationResult:
    """Deterministically replay and verify the integrity of the audit ledger.

    Verifies:
    1. Valid sequence numbers (no missing/deleted entries)
    2. Exact previous-hash linkage
    3. Content integrity (no modified entries)
    4. Valid evidence hash format and consistency
    5. Valid state transitions per recommendation
    6. Replay prevention (no multiple successful applications of same decision_id)
    """
    entries = ledger.entries if isinstance(ledger, AuditLedger) else list(ledger)
    errors: list[str] = []

    if not entries:
        return AuditVerificationResult(is_valid=True, errors=[], entries_checked=0)

    # State tracking per recommendation_id
    rec_states: dict[str, str] = {}
    rec_evidence: dict[str, str] = {}
    seen_successful_decision_ids: set[str] = set()

    for idx, entry in enumerate(entries):
        expected_seq = idx + 1

        # 1. Missing / deleted entry check (sequence gap)
        if entry.sequence_number != expected_seq:
            errors.append(
                f"Missing or out-of-order entry at position {idx}: "
                f"recorded sequence_number {entry.sequence_number}, expected {expected_seq}."
            )

        # 2. Previous hash chain link check
        expected_prev = entries[idx - 1].entry_hash if idx > 0 else GENESIS_HASH
        if entry.prev_audit_hash != expected_prev:
            errors.append(
                f"Broken hash chain link at sequence {entry.sequence_number}: "
                f"prev_audit_hash '{entry.prev_audit_hash}' != expected '{expected_prev}'."
            )

        # 3. Content modification / tamper detection
        recalculated_hash = compute_audit_entry_hash(
            sequence_number=entry.sequence_number,
            operator_id=entry.operator_id,
            role=entry.role,
            decision=entry.decision,
            timestamp=entry.timestamp,
            recommendation_id=entry.recommendation_id,
            decision_id=entry.decision_id,
            evidence_hash=entry.evidence_hash,
            state_transition=entry.state_transition,
            reason=entry.reason,
            prev_audit_hash=entry.prev_audit_hash,
        )
        if recalculated_hash != entry.entry_hash:
            errors.append(
                f"Tampered entry detected at sequence {entry.sequence_number}: "
                f"recalculated '{recalculated_hash}' != recorded '{entry.entry_hash}'."
            )

        # 4. Evidence hash format check
        if not HASH_REGEX.match(entry.evidence_hash):
            errors.append(
                f"Invalid evidence_hash format at sequence {entry.sequence_number}: '{entry.evidence_hash}'."
            )

        # 5. State transition and replay checks
        src_state, dst_state = _parse_transition(entry.state_transition)
        rec_id = entry.recommendation_id

        if src_state and dst_state:
            # Check if this entry changes the active state
            is_effective_transition = (src_state != dst_state)

            # Check if current known state matches source state
            if rec_id in rec_states:
                current_state = rec_states[rec_id]
                if src_state != current_state and is_effective_transition:
                    errors.append(
                        f"Invalid state transition at sequence {entry.sequence_number} for '{rec_id}': "
                        f"transition claims from '{src_state}' but current state is '{current_state}'."
                    )
                if current_state in TERMINAL_STATES and is_effective_transition:
                    errors.append(
                        f"Terminal state violation at sequence {entry.sequence_number} for '{rec_id}': "
                        f"cannot transition from terminal state '{current_state}'."
                    )

            # Check transition legality
            if is_effective_transition:
                allowed_next = VALID_TRANSITIONS.get(src_state, frozenset())
                if dst_state not in allowed_next:
                    errors.append(
                        f"Illegal state transition at sequence {entry.sequence_number}: "
                        f"'{src_state}' -> '{dst_state}' is not permitted by state machine."
                    )

                # Approval invariant check: Approved state requires APPROVED decision
                if dst_state == RecommendationStatus.APPROVED.value and entry.decision != DecisionType.APPROVED.value:
                    errors.append(
                        f"Approval violation at sequence {entry.sequence_number}: "
                        f"transition to 'Approved' with non-approval decision '{entry.decision}'."
                    )

                # Update active state
                rec_states[rec_id] = dst_state

            # Replay detection: check if decision_id was already successfully applied
            if is_effective_transition and dst_state in (
                RecommendationStatus.APPROVED.value,
                RecommendationStatus.REJECTED.value,
            ):
                if entry.decision_id in seen_successful_decision_ids:
                    errors.append(
                        f"Replayed decision violation at sequence {entry.sequence_number}: "
                        f"decision_id '{entry.decision_id}' was applied more than once."
                    )
                else:
                    seen_successful_decision_ids.add(entry.decision_id)

        # 6. Evidence consistency check
        if rec_id in rec_evidence:
            prior_ev = rec_evidence[rec_id]
            current_st = rec_states.get(rec_id)
            # If evidence hash changes without an invalidation transition
            if entry.evidence_hash != prior_ev and current_st != RecommendationStatus.INVALIDATED.value:
                errors.append(
                    f"Evidence mismatch at sequence {entry.sequence_number} for '{rec_id}': "
                    f"evidence_hash changed from '{prior_ev}' to '{entry.evidence_hash}' "
                    f"without invalidation."
                )
        rec_evidence[rec_id] = entry.evidence_hash

    return AuditVerificationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        entries_checked=len(entries),
    )
