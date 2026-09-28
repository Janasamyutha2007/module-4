"""Configurable Role-Based Authorization for Module 4.

Provides a pluggable and configurable authorization policy.
NOTE: Does NOT invent fixed project role names. Roles and permissions are completely
configurable and can be replaced by the team's authoritative policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, Set

from services.approval.contracts import (
    AllowedAction,
    DecisionType,
    Recommendation,
)

# Standard risk ranking for comparison
RISK_HIERARCHY: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class RolePermission:
    """Configurable permissions assigned to a role."""
    allowed_tasks: Optional[Set[str]] = None  # None means all benign actions allowed
    max_risk_level: Optional[str] = None      # e.g., "MEDIUM" blocks HIGH or CRITICAL
    can_approve: bool = True
    can_reject: bool = True


class AuthorizationPolicyProtocol(Protocol):
    """Protocol for pluggable authorization policy implementations."""

    def check_authorization(
        self,
        *,
        role: str,
        decision: str,
        recommendation: Recommendation,
        risk_level: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Check whether the given role is authorized to make the decision."""
        ...


class ConfigurableAuthorizationPolicy:
    """Default configurable role-based authorization policy.

    Roles and permissions can be added, updated, cleared, or swapped out dynamically.
    """

    def __init__(
        self,
        role_permissions: Optional[dict[str, RolePermission]] = None,
        *,
        default_allow: bool = False,
    ) -> None:
        self._role_permissions: dict[str, RolePermission] = (
            dict(role_permissions) if role_permissions is not None else {}
        )
        self.default_allow = default_allow

    def configure_role(self, role: str, permission: RolePermission) -> None:
        """Register or update permissions for a specific role."""
        self._role_permissions[role] = permission

    def remove_role(self, role: str) -> None:
        """Remove a role configuration."""
        self._role_permissions.pop(role, None)

    def clear_roles(self) -> None:
        """Remove all role configurations."""
        self._role_permissions.clear()

    def get_role_permission(self, role: str) -> Optional[RolePermission]:
        """Retrieve permission for a given role."""
        return self._role_permissions.get(role)

    def check_authorization(
        self,
        *,
        role: str,
        decision: str,
        recommendation: Recommendation,
        risk_level: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Check whether the given role is authorized to make the decision on the recommendation.

        Returns:
            (True, "Authorized") if authorized.
            (False, "<Reason for denial>") if not authorized.
        """
        permission = self._role_permissions.get(role)

        if permission is None:
            if self.default_allow:
                return True, f"Role '{role}' allowed by default policy."
            return False, f"Role '{role}' is not recognized in the authorization policy."

        # Check decision type permission
        if decision == DecisionType.APPROVED.value and not permission.can_approve:
            return False, f"Role '{role}' is not permitted to issue APPROVAL decisions."
        if decision == DecisionType.REJECTED.value and not permission.can_reject:
            return False, f"Role '{role}' is not permitted to issue REJECTION decisions."

        # Check task restrictions if configured
        if permission.allowed_tasks is not None:
            if recommendation.proposed_task not in permission.allowed_tasks:
                return (
                    False,
                    f"Role '{role}' is not authorized to approve task '{recommendation.proposed_task}'. "
                    f"Permitted tasks: {sorted(permission.allowed_tasks)}.",
                )

        # Check risk level restrictions if configured and present
        if permission.max_risk_level is not None and risk_level is not None:
            max_rank = RISK_HIERARCHY.get(permission.max_risk_level.upper(), 99)
            target_rank = RISK_HIERARCHY.get(risk_level.upper(), 0)
            if target_rank > max_rank:
                return (
                    False,
                    f"Role '{role}' maximum risk clearance is '{permission.max_risk_level}', "
                    f"which is insufficient for risk level '{risk_level}'.",
                )

        return True, f"Role '{role}' is authorized for this decision."
