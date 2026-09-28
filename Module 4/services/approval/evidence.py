"""Evidence binding and cryptographic hashing for Module 4.

Provides deterministic SHA-256 evidence hashing and internal recommendation hashing.
Formats hashes strictly as:
  sha256:<64 lowercase hexadecimal characters>
"""

from __future__ import annotations

import hashlib
import json
from typing import Sequence, Union

from services.approval.contracts import DomainAlert, Recommendation


def compute_alert_content_hash(alert: DomainAlert) -> str:
    """Compute deterministic SHA-256 content hash of a single DomainAlert.

    Uses a canonical JSON representation sorted by keys.
    """
    canonical_payload = {
        "alert_id": alert.alert_id,
        "confidence": round(float(alert.confidence), 6),
        "explanation": alert.explanation,
        "missing_evidence": sorted(alert.missing_evidence),
        "risk_level": alert.risk_level.upper(),
        "supporting_event_ids": sorted(alert.supporting_event_ids),
        "valid_until": alert.valid_until,
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_evidence_hash(alerts: Union[DomainAlert, Sequence[DomainAlert]]) -> str:
    """Generate deterministic SHA-256 evidence_hash for one or more DomainAlerts.

    Binds ordered alert identifiers and their individual canonical content hashes.
    Output format:
      sha256:<64 lowercase hexadecimal characters>
    """
    if isinstance(alerts, DomainAlert):
        alert_list = [alerts]
    else:
        alert_list = list(alerts)

    if not alert_list:
        raise ValueError("Cannot compute evidence hash for empty alert sequence.")

    # Sort alerts deterministically by alert_id
    sorted_alerts = sorted(alert_list, key=lambda a: a.alert_id)

    # Build canonical list of (alert_id, content_hash)
    evidence_bindings = [
        {
            "alert_id": alert.alert_id,
            "content_hash": compute_alert_content_hash(alert),
        }
        for alert in sorted_alerts
    ]

    canonical_encoded = json.dumps(
        evidence_bindings, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(canonical_encoded).hexdigest().lower()
    return f"sha256:{digest}"


def compute_recommendation_hash(
    recommendation: Recommendation | None = None,
    *,
    proposed_task: str | None = None,
    rationale: str | None = None,
    valid_until: str | None = None,
    evidence_hash: str | None = None,
    policy_version: str | None = None,
) -> str:
    """Compute internal verification/audit recommendation hash.

    Binds:
    - proposal content (proposed_task, rationale, valid_until)
    - evidence_hash
    - policy_version

    Output format:
      sha256:<64 lowercase hexadecimal characters>
    """
    if recommendation is not None:
        task = recommendation.proposed_task
        rat = recommendation.rationale
        val = recommendation.valid_until
        ev_hash = recommendation.evidence_hash
        pol_ver = recommendation.policy_version
    else:
        if None in (proposed_task, rationale, valid_until, evidence_hash, policy_version):
            raise ValueError(
                "Either recommendation or all individual proposal fields must be provided."
            )
        task = proposed_task
        rat = rationale
        val = valid_until
        ev_hash = evidence_hash
        pol_ver = policy_version

    canonical_proposal = {
        "evidence_hash": ev_hash,
        "policy_version": pol_ver,
        "proposed_task": task,
        "rationale": rat,
        "valid_until": val,
    }

    canonical_encoded = json.dumps(
        canonical_proposal, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(canonical_encoded).hexdigest().lower()
    return f"sha256:{digest}"
