"""Microsoft Graph API collector: users, groups, service principals, Entra roles."""
import asyncio
import logging
from typing import Callable, Optional

import httpx

from ..config import settings
from .base import BaseCollector

logger = logging.getLogger(__name__)

GRAPH = settings.graph_api_base

# Entra ID directory roles considered privileged
PRIVILEGED_ENTRA_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "User Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Hybrid Identity Administrator",
    "Security Administrator",
    "Intune Administrator",
    "Conditional Access Administrator",
    "Password Administrator",
    "Helpdesk Administrator",
    "Directory Synchronization Accounts",
    "Partner Tier1 Support",
    "Partner Tier2 Support",
}


class GraphCollector(BaseCollector):

    def __init__(self, progress_callback: Optional[Callable] = None):
        super().__init__(progress_callback)

    async def get_tenant_info(self, client: httpx.AsyncClient) -> dict:
        try:
            data = await self._get_graph(client, f"{GRAPH}/organization")
            orgs = data.get("value", [])
            if orgs:
                org = orgs[0]
                return {
                    "tenant_id": org.get("id", ""),
                    "display_name": org.get("displayName", ""),
                    "verified_domains": [d.get("name") for d in org.get("verifiedDomains", [])],
                }
        except Exception as e:
            logger.warning(f"Could not fetch tenant info: {e}")
        return {}

    async def get_users(self, client: httpx.AsyncClient) -> list[dict]:
        self._report("graph", "Collecting users...")
        url = f"{GRAPH}/users"
        params = {
            "$select": "id,displayName,userPrincipalName,jobTitle,mail,accountEnabled,assignedLicenses,userType,createdDateTime",
            "$top": "999",
        }
        items = await self._paginate_graph(client, url, params)
        return [
            {
                "id": u.get("id", ""),
                "display_name": u.get("displayName", ""),
                "upn": u.get("userPrincipalName", ""),
                "job_title": u.get("jobTitle", ""),
                "mail": u.get("mail", ""),
                "account_enabled": u.get("accountEnabled", True),
                "user_type": u.get("userType", "Member"),
                "created_at": u.get("createdDateTime", ""),
                "has_licenses": len(u.get("assignedLicenses", [])) > 0,
            }
            for u in items
        ]

    async def get_groups(self, client: httpx.AsyncClient) -> list[dict]:
        self._report("graph", "Collecting groups...")
        url = f"{GRAPH}/groups"
        params = {
            "$select": "id,displayName,description,groupTypes,securityEnabled,mailEnabled,membershipRule",
            "$top": "999",
        }
        items = await self._paginate_graph(client, url, params)
        return [
            {
                "id": g.get("id", ""),
                "display_name": g.get("displayName", ""),
                "description": g.get("description", ""),
                "security_enabled": g.get("securityEnabled", False),
                "mail_enabled": g.get("mailEnabled", False),
                "is_dynamic": "DynamicMembership" in g.get("groupTypes", []),
                "is_m365": "Unified" in g.get("groupTypes", []),
                "membership_rule": g.get("membershipRule", ""),
            }
            for g in items
        ]

    async def get_group_members(self, client: httpx.AsyncClient, group_id: str) -> list[dict]:
        url = f"{GRAPH}/groups/{group_id}/members"
        params = {"$select": "id,displayName,userPrincipalName,@odata.type"}
        try:
            items = await self._paginate_graph(client, url, params)
            return [
                {
                    "id": m.get("id", ""),
                    "display_name": m.get("displayName", ""),
                    "upn": m.get("userPrincipalName", ""),
                    "type": m.get("@odata.type", "#microsoft.graph.user").split(".")[-1],
                }
                for m in items
            ]
        except Exception as e:
            logger.warning(f"Could not get members of group {group_id}: {e}")
            return []

    async def get_all_group_memberships(
        self, client: httpx.AsyncClient, groups: list[dict]
    ) -> dict[str, list[dict]]:
        """Fetch members for all groups (rate-limited concurrency)."""
        self._report("graph", f"Collecting group memberships ({len(groups)} groups)...")
        sem = asyncio.Semaphore(5)

        async def _fetch(g):
            async with sem:
                return g["id"], await self.get_group_members(client, g["id"])

        results = await asyncio.gather(*[_fetch(g) for g in groups], return_exceptions=True)
        memberships: dict[str, list[dict]] = {}
        for res in results:
            if not isinstance(res, Exception):
                gid, members = res
                memberships[gid] = members
        return memberships

    async def get_service_principals(self, client: httpx.AsyncClient) -> list[dict]:
        self._report("graph", "Collecting service principals...")
        url = f"{GRAPH}/servicePrincipals"
        params = {
            "$select": "id,displayName,appId,servicePrincipalType,accountEnabled,appRoles,keyCredentials,passwordCredentials,tags",
            "$top": "999",
        }
        items = await self._paginate_graph(client, url, params)
        results = []
        for sp in items:
            results.append({
                "id": sp.get("id", ""),
                "display_name": sp.get("displayName", ""),
                "app_id": sp.get("appId", ""),
                "sp_type": sp.get("servicePrincipalType", ""),
                "account_enabled": sp.get("accountEnabled", True),
                "has_key_credentials": len(sp.get("keyCredentials", [])) > 0,
                "has_password_credentials": len(sp.get("passwordCredentials", [])) > 0,
                "key_credential_count": len(sp.get("keyCredentials", [])),
                "password_credential_count": len(sp.get("passwordCredentials", [])),
                "tags": sp.get("tags", []),
            })
        return results

    async def get_app_registrations(self, client: httpx.AsyncClient) -> list[dict]:
        self._report("graph", "Collecting app registrations...")
        url = f"{GRAPH}/applications"
        params = {
            "$select": "id,displayName,appId,createdDateTime,keyCredentials,passwordCredentials,requiredResourceAccess",
            "$top": "999",
        }
        items = await self._paginate_graph(client, url, params)
        return [
            {
                "id": a.get("id", ""),
                "display_name": a.get("displayName", ""),
                "app_id": a.get("appId", ""),
                "created_at": a.get("createdDateTime", ""),
                "has_key_credentials": len(a.get("keyCredentials", [])) > 0,
                "has_password_credentials": len(a.get("passwordCredentials", [])) > 0,
                "requested_permissions": a.get("requiredResourceAccess", []),
            }
            for a in items
        ]

    async def get_directory_roles(self, client: httpx.AsyncClient) -> list[dict]:
        """Fetch active Entra directory role assignments."""
        self._report("graph", "Collecting directory role assignments...")
        url = f"{GRAPH}/roleManagement/directory/roleAssignments"
        params = {"$expand": "principal,roleDefinition"}
        try:
            items = await self._paginate_graph(client, url, params)
        except Exception as e:
            logger.warning(f"Could not fetch Entra role assignments (need Privileged Role Reader): {e}")
            return []

        results = []
        for ra in items:
            principal = ra.get("principal", {}) or {}
            role_def = ra.get("roleDefinition", {}) or {}
            role_name = role_def.get("displayName", "")
            results.append({
                "id": ra.get("id", ""),
                "principal_id": ra.get("principalId", ""),
                "principal_display_name": principal.get("displayName", ""),
                "principal_type": principal.get("@odata.type", "").split(".")[-1],
                "role_id": ra.get("roleDefinitionId", ""),
                "role_name": role_name,
                "is_privileged": role_name in PRIVILEGED_ENTRA_ROLES,
                "directory_scope_id": ra.get("directoryScopeId", "/"),
            })
        return results

    async def get_conditional_access_policies(self, client: httpx.AsyncClient) -> list[dict]:
        """Fetch Conditional Access policies (requires appropriate permissions)."""
        try:
            url = f"{GRAPH}/identity/conditionalAccess/policies"
            data = await self._get_graph(client, url)
            policies = data.get("value", [])
            return [
                {
                    "id": p.get("id", ""),
                    "display_name": p.get("displayName", ""),
                    "state": p.get("state", ""),
                    "conditions": p.get("conditions", {}),
                    "grant_controls": p.get("grantControls", {}),
                }
                for p in policies
            ]
        except Exception as e:
            logger.debug(f"Could not fetch CA policies: {e}")
            return []

    async def collect_all(self, client: httpx.AsyncClient) -> dict:
        self._report("graph", "Starting Microsoft Graph collection...", 0, 5)

        (
            tenant_info,
            users,
            groups,
            service_principals,
            app_registrations,
            directory_roles,
            ca_policies,
        ) = await asyncio.gather(
            self.get_tenant_info(client),
            self.get_users(client),
            self.get_groups(client),
            self.get_service_principals(client),
            self.get_app_registrations(client),
            self.get_directory_roles(client),
            self.get_conditional_access_policies(client),
            return_exceptions=True,
        )

        def _safe(r, d):
            if isinstance(r, Exception):
                logger.warning(f"Graph collection error: {r}")
                return d
            return r

        resolved_groups = _safe(groups, [])
        memberships: dict = {}
        if resolved_groups:
            try:
                memberships = await self.get_all_group_memberships(client, resolved_groups)
            except Exception as e:
                logger.warning(f"Group membership collection failed: {e}")

        return {
            "tenant_info": _safe(tenant_info, {}),
            "users": _safe(users, []),
            "ca_policies": _safe(ca_policies, []),
            "groups": resolved_groups,
            "group_memberships": memberships,
            "service_principals": _safe(service_principals, []),
            "app_registrations": _safe(app_registrations, []),
            "directory_roles": _safe(directory_roles, []),
        }
