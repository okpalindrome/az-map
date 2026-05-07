"""
Risk Scorer: assigns severity, blast radius, and lateral movement scores to nodes.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Role name → base risk contribution
ROLE_RISK_MAP: dict[str, float] = {
    "Owner": 9.0,
    "User Access Administrator": 9.0,
    "Role Based Access Control Administrator": 8.5,
    "Contributor": 7.0,
    "Key Vault Administrator": 8.0,
    "Key Vault Secrets User": 6.0,
    "Storage Account Contributor": 7.0,
    "Storage Account Key Operator Service Role": 7.0,
    "Storage Blob Data Contributor": 5.0,
    "Virtual Machine Contributor": 6.0,
    "Automation Contributor": 7.0,
    "Website Contributor": 6.0,
    "Logic App Contributor": 5.5,
}

ENTRA_ROLE_RISK_MAP: dict[str, float] = {
    "Global Administrator": 10.0,
    "Privileged Role Administrator": 9.5,
    "Application Administrator": 8.0,
    "Cloud Application Administrator": 7.5,
    "Authentication Administrator": 7.0,
    "Privileged Authentication Administrator": 9.0,
    "User Administrator": 7.0,
    "Security Administrator": 7.5,
    "Hybrid Identity Administrator": 8.0,
}


def _risk_level(score: float) -> str:
    if score >= 7.5:
        return "critical"
    if score >= 5.0:
        return "risky"
    return "safe"


class RiskScorer:
    def __init__(
        self,
        principal_effective_roles: dict[str, list[dict]],
        directory_roles: list[dict],
        group_memberships: dict[str, list[dict]],
        service_principals: list[dict],
    ):
        self.principal_effective_roles = principal_effective_roles
        self.directory_roles = directory_roles
        self.group_memberships = group_memberships
        self.sp_map = {sp["id"]: sp for sp in service_principals}

        # principal → list of Entra role names
        self._entra_roles: dict[str, list[str]] = {}
        for dr in directory_roles:
            pid = dr["principal_id"]
            self._entra_roles.setdefault(pid, []).append(dr["role_name"])

        # group → member count
        self._group_size: dict[str, int] = {
            gid: len(members) for gid, members in group_memberships.items()
        }

    def score_principal(self, principal_id: str, node_type: str) -> dict:
        """Return {risk_score, risk_level, risk_reasons} for a principal."""
        score = 0.0
        reasons: list[str] = []

        # Azure RBAC roles
        effective_roles = self.principal_effective_roles.get(principal_id, [])
        for ra in effective_roles:
            role_name = ra.get("role_name", "")
            role_score = ROLE_RISK_MAP.get(role_name, 0.0)
            if role_score > 0:
                scope_multiplier = 1.0 if ra.get("scope_level") == "subscription" else 0.7
                contribution = role_score * scope_multiplier
                score = max(score, contribution)
                reasons.append(
                    f"{role_name} at {ra.get('scope_level', 'resource')} scope"
                    + (f" (via group)" if ra.get("inherited_from") else "")
                )

        # Entra directory roles
        entra = self._entra_roles.get(principal_id, [])
        for role_name in entra:
            er_score = ENTRA_ROLE_RISK_MAP.get(role_name, 0.0)
            if er_score > 0:
                score = max(score, er_score)
                reasons.append(f"Entra role: {role_name}")

        # SP-specific boosts
        if node_type == "service_principal":
            sp = self.sp_map.get(principal_id)
            if sp:
                cred_count = sp.get("key_credential_count", 0) + sp.get("password_credential_count", 0)
                if cred_count > 0 and score >= 5.0:
                    score = min(10.0, score + 1.0)
                    reasons.append(f"Has {cred_count} active credential(s)")
                if not sp.get("account_enabled"):
                    score = max(0.0, score - 3.0)

        # Group membership amplifies blast radius (not risk score directly)
        if node_type == "group":
            size = self._group_size.get(principal_id, 0)
            if size > 50:
                score = min(10.0, score + 1.0)
                reasons.append(f"Large group ({size} members) — high blast radius")

        return {
            "risk_score": round(score, 1),
            "risk_level": _risk_level(score),
            "risk_reasons": reasons,
        }
