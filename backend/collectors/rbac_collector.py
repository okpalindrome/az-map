"""Collects Azure RBAC: role definitions and role assignments."""
import logging
from typing import Callable, Optional

import httpx

from ..config import settings
from .base import BaseCollector

logger = logging.getLogger(__name__)

ARM = settings.arm_api_base

# Builtin roles that warrant immediate attention
HIGH_RISK_BUILTIN_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f25e0fa2-a7c8-4377-a976-54943a77a395": "Key Vault Administrator",
    "e147488a-f6f5-4113-8e2d-b22465e65bf6": "Key Vault Crypto Service Encryption User",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "21090545-7ca7-4776-b22c-e363652d74d2": "Key Vault Reader",
    "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
    "81a9662b-bebf-436f-a333-f67b29880f12": "Storage Account Key Operator Service Role",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "974c5e8b-45b9-4653-ba55-5f855dd0fb88": "Storage Queue Data Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "d73bb868-a0df-4d4d-bd69-98a00b01fccb": "Automation Contributor",
    "515c2055-d06d-4e5d-8c29-1b6d9f94d0e0": "Logic App Contributor",
    "60fc6e62-5479-42d4-8bf4-67625fcc2840": "Website Contributor",
}

# Privilege levels for risk scoring
ROLE_PRIVILEGE_LEVELS = {
    "critical": {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
        "f25e0fa2-a7c8-4377-a976-54943a77a395",  # Key Vault Administrator
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # RBAC Administrator
    },
    "high": {
        "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
        "17d1049b-9a84-46fb-8f53-869881c3d3ab",  # Storage Account Contributor
        "81a9662b-bebf-436f-a333-f67b29880f12",  # Storage Key Operator
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",  # Storage Blob Data Contributor
        "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",  # VM Contributor
        "d73bb868-a0df-4d4d-bd69-98a00b01fccb",  # Automation Contributor
    },
    "medium": {
        "4633458b-17de-408a-b874-0445c86b69e6",  # Key Vault Secrets User
        "21090545-7ca7-4776-b22c-e363652d74d2",  # Key Vault Reader
        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",  # Storage Blob Data Reader
        "60fc6e62-5479-42d4-8bf4-67625fcc2840",  # Website Contributor
        "515c2055-d06d-4e5d-8c29-1b6d9f94d0e0",  # Logic App Contributor
    },
}


def _role_privilege_level(role_id: str) -> str:
    clean = role_id.split("/")[-1].lower()
    for level, ids in ROLE_PRIVILEGE_LEVELS.items():
        if clean in ids:
            return level
    return "low"


class RBACCollector(BaseCollector):

    def __init__(self, subscription_id: str, progress_callback: Optional[Callable] = None):
        super().__init__(progress_callback)
        self.subscription_id = subscription_id
        self._sub_scope = f"/subscriptions/{subscription_id}"

    async def get_role_definitions(self, client: httpx.AsyncClient) -> list[dict]:
        url = (
            f"{ARM}{self._sub_scope}/providers/Microsoft.Authorization/roleDefinitions"
            "?api-version=2022-04-01"
        )
        self._report("rbac", "Collecting role definitions...")
        items = await self._paginate_arm(client, url)
        results = []
        for rd in items:
            props = rd.get("properties", {})
            role_id = rd.get("name", "")  # GUID
            perms = props.get("permissions", [{}])
            results.append({
                "role_id": role_id,
                "name": props.get("roleName", ""),
                "description": props.get("description", ""),
                "is_builtin": props.get("type", "") == "BuiltInRole",
                "privilege_level": _role_privilege_level(role_id),
                "permissions": {
                    "actions": perms[0].get("actions", []) if perms else [],
                    "not_actions": perms[0].get("notActions", []) if perms else [],
                    "data_actions": perms[0].get("dataActions", []) if perms else [],
                },
            })
        return results

    async def get_role_assignments(self, client: httpx.AsyncClient) -> list[dict]:
        """Fetch ALL role assignments in the subscription (including at sub level)."""
        url = (
            f"{ARM}{self._sub_scope}/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        )
        self._report("rbac", "Collecting role assignments...")
        items = await self._paginate_arm(client, url)
        results = []
        for ra in items:
            props = ra.get("properties", {})
            scope = props.get("scope", "")
            results.append({
                "assignment_id": ra.get("name", ""),
                "principal_id": props.get("principalId", ""),
                "principal_type": props.get("principalType", "Unknown"),
                "role_definition_id": props.get("roleDefinitionId", ""),
                "scope": scope,
                "scope_level": _scope_level(scope, self.subscription_id),
            })
        return results

    async def collect_all(self, client: httpx.AsyncClient) -> dict:
        import asyncio
        self._report("rbac", "Starting RBAC collection...", 0, 2)
        role_defs, role_assigns = await asyncio.gather(
            self.get_role_definitions(client),
            self.get_role_assignments(client),
            return_exceptions=True,
        )

        def _safe(r, d):
            return d if isinstance(r, Exception) else r

        # Build lookup: role_id → role_name
        defs = _safe(role_defs, [])
        role_name_map = {rd["role_id"]: rd["name"] for rd in defs}

        assigns = _safe(role_assigns, [])
        for ra in assigns:
            rid = ra["role_definition_id"].split("/")[-1]
            ra["role_name"] = role_name_map.get(rid, rid)

        return {
            "role_definitions": defs,
            "role_assignments": assigns,
            "role_name_map": role_name_map,
        }


def _scope_level(scope: str, subscription_id: str) -> str:
    """Classify scope: subscription | resource_group | resource | management_group."""
    s = scope.lower()
    if s == f"/subscriptions/{subscription_id.lower()}":
        return "subscription"
    if s.startswith("/providers/microsoft.management"):
        return "management_group"
    parts = s.split("/")
    if len(parts) == 5 and "resourcegroups" in parts:
        return "resource_group"
    return "resource"
