"""Local typed data contracts for Module 4 (Approval Service).

These local models reflect the authoritative Module 4 specifications and the
common event envelope. When the shared contracts package becomes available across
the project, these models can be adapted or substituted without altering
core Module 4 business logic.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, List, Optional


class AllowedAction(str, Enum):
    """The four benign actions permitted in the prototype."""
    INSPECT_AREA = "inspect area"
    VERIFY_EQUIPMENT = "verify equipment"
    REQUEST_ANOTHER_OBSERVATION = "request another observation"
    DISMISS_ALERT = "dismiss alert"

    @classmethod
    def values(cls) -> set[str]:
        return {item.value for item in cls}


class RecommendationStatus(str, Enum):
    """Lifecycle states of a Recommendation."""
    DRAFT = "Draft"
    PENDING_REVIEW = "Pending Review"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    EXPIRED = "Expired"
    INVALIDATED = "Invalidated"
    COMPLETED = "Completed"

    @classmethod
    def values(cls) -> set[str]:
        return {item.value for item in cls}


class DecisionType(str, Enum):
    """Permitted human approval decisions."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

    @classmethod
    def values(cls) -> set[str]:
        return {item.value for item in cls}


@dataclass(frozen=True)
class DomainAlert:
    """Module 3 incoming alert contract."""
    alert_id: str
    supporting_event_ids: list[str]
    risk_level: str
    confidence: float
    explanation: str
    missing_evidence: list[str]
    valid_until: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DomainAlert:
        return cls(
            alert_id=str(data["alert_id"]),
            supporting_event_ids=list(data.get("supporting_event_ids", [])),
            risk_level=str(data["risk_level"]),
            confidence=float(data["confidence"]),
            explanation=str(data["explanation"]),
            missing_evidence=list(data.get("missing_evidence", [])),
            valid_until=str(data["valid_until"]),
        )


@dataclass(frozen=True)
class Recommendation:
    """Central AI recommendation proposal contract (strictly non-executable)."""
    recommendation_id: str
    alert_ids: list[str]
    proposed_task: str
    rationale: str
    evidence_hash: str
    policy_version: str
    status: str
    valid_until: str

    def __post_init__(self) -> None:
        if self.proposed_task not in AllowedAction.values():
            raise ValueError(
                f"Invalid proposed_task '{self.proposed_task}'. "
                f"Must be one of: {sorted(AllowedAction.values())}"
            )
        if self.status not in RecommendationStatus.values():
            raise ValueError(
                f"Invalid status '{self.status}'. "
                f"Must be one of: {sorted(RecommendationStatus.values())}"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Recommendation:
        return cls(
            recommendation_id=str(data["recommendation_id"]),
            alert_ids=list(data.get("alert_ids", [])),
            proposed_task=str(data["proposed_task"]),
            rationale=str(data["rationale"]),
            evidence_hash=str(data["evidence_hash"]),
            policy_version=str(data["policy_version"]),
            status=str(data["status"]),
            valid_until=str(data["valid_until"]),
        )


@dataclass(frozen=True)
class ApprovalDecision:
    """Module 5 human/operator decision contract."""
    decision_id: str
    recommendation_id: str
    evidence_hash: str
    operator_id: str
    role: str
    decision: str
    reason: str
    signed_at: str

    def __post_init__(self) -> None:
        if self.decision not in DecisionType.values():
            raise ValueError(
                f"Invalid decision '{self.decision}'. "
                f"Must be one of: {sorted(DecisionType.values())}"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalDecision:
        return cls(
            decision_id=str(data["decision_id"]),
            recommendation_id=str(data["recommendation_id"]),
            evidence_hash=str(data["evidence_hash"]),
            operator_id=str(data["operator_id"]),
            role=str(data["role"]),
            decision=str(data["decision"]),
            reason=str(data["reason"]),
            signed_at=str(data["signed_at"]),
        )


@dataclass(frozen=True)
class DecisionStatus:
    """Module 4 final decision status emission contract."""
    event_id: str
    recommendation_id: str
    decision_id: str
    status: str
    reason: str
    committed_at: str
    audit_ref: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionStatus:
        return cls(
            event_id=str(data["event_id"]),
            recommendation_id=str(data["recommendation_id"]),
            decision_id=str(data["decision_id"]),
            status=str(data["status"]),
            reason=str(data["reason"]),
            committed_at=str(data["committed_at"]),
            audit_ref=str(data["audit_ref"]),
        )


@dataclass(frozen=True)
class EventEnvelope:
    """Common event envelope wrapping all cross-module messages."""
    message_id: str
    message_type: str
    schema_version: str
    run_id: str
    producer: str
    produced_at: str
    correlation_id: str
    causation_id: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EventEnvelope:
        return cls(
            message_id=str(data["message_id"]),
            message_type=str(data["message_type"]),
            schema_version=str(data["schema_version"]),
            run_id=str(data["run_id"]),
            producer=str(data["producer"]),
            produced_at=str(data["produced_at"]),
            correlation_id=str(data["correlation_id"]),
            causation_id=str(data["causation_id"]),
            payload=dict(data.get("payload", {})),
        )
