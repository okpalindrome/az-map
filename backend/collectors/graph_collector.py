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

    async def get_users_by_ids(self, client: httpx.AsyncClient, ids: list[str]) -> list[dict]:
        """
        Batch-fetch users by object ID via directoryObjects/getByIds.

        Microsoft Graph uses POST here because the ID list can exceed URL length
        limits.  Each call handles up to 1000 IDs; we chunk larger sets.

        Note: assignedLicenses is NOT returned by getByIds and is excluded from
        the users $select on list queries (only available on individual user GET).
        """
        BATCH = 1000
        raw: list[dict] = []
        total = len(ids)
        fetched = 0
        for i in range(0, total, BATCH):
            chunk = ids[i : i + BATCH]
            data = await self._post_graph_query(
                client,
                f"{GRAPH}/directoryObjects/getByIds",
                {"ids": chunk, "types": ["user"]},
            )
            raw.extend(data.get("value", []))
            fetched += len(chunk)
            self._report("collect", f"Users: {fetched:,}/{total:,} fetched (RBAC-relevant)")
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
            }
            for u in raw
            if "#microsoft.graph.user" in u.get("@odata.type", "")
        ]

    async def get_groups(self, client: httpx.AsyncClient) -> list[dict]:
        """
        Fetch security-enabled groups only.

        $filter on non-default properties requires ConsistencyLevel: eventual and
        $count=true per Microsoft Graph advanced query docs.  Without these headers
        the request returns 400 or falls back to an unfiltered response depending
        on the tenant configuration.

        membershipRule is excluded from $select — it is a dynamic-group property
        not returned in list queries; individual group GET is needed if required.
        """
        self._report("collect", "Groups: collecting security groups...")
        url = f"{GRAPH}/groups"
        params = {
            "$select": "id,displayName,description,groupTypes,securityEnabled,mailEnabled",
            "$top": "999",
            "$filter": "securityEnabled eq true",
            "$count": "true",
        }
        items = await self._paginate_graph(
            client, url, params,
            page_callback=lambda n: self._report("collect", f"Groups: {n:,} collected (security-enabled)"),
            extra_headers={"ConsistencyLevel": "eventual"},
        )
        return [
            {
                "id": g.get("id", ""),
                "display_name": g.get("displayName", ""),
                "description": g.get("description", ""),
                "security_enabled": g.get("securityEnabled", False),
                "mail_enabled": g.get("mailEnabled", False),
                "is_dynamic": "DynamicMembership" in g.get("groupTypes", []),
                "is_m365": "Unified" in g.get("groupTypes", []),
            }
            for g in items
        ]

    async def get_group_members(self, client: httpx.AsyncClient, group_id: str) -> list[dict]:
        """
        Fetch all members of a group (users, service principals, nested groups).

        $select must not include type-specific properties like userPrincipalName —
        the /members endpoint returns a polymorphic directoryObject collection and
        requesting properties that don't exist on all member types causes 400.

        id and displayName are common to all directory object types.
        @odata.type is always returned automatically (it's part of the OData envelope,
        not a selectable property) and is used to distinguish member types.
        """
        url = f"{GRAPH}/groups/{group_id}/members"
        params = {"$select": "id,displayName"}
        try:
            items = await self._paginate_graph(client, url, params)
            return [
                {
                    "id": m.get("id", ""),
                    "display_name": m.get("displayName", ""),
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
        """Fetch members for RBAC-relevant groups only (rate-limited concurrency)."""
        self._report("collect", f"Group memberships: fetching {len(groups)} RBAC groups...")
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
        """
        Fetch all service principals.

        keyCredentials and passwordCredentials are NOT returned in the default SP
        list response — they must be explicitly requested via $select (Graph docs
        confirm this).  There is a 150 req/min throttle for keyCredentials $select,
        but with ~40 pages for a 40K-SP tenant we stay well under that limit.
        """
        self._report("collect", "Service principals: collecting...")
        url = f"{GRAPH}/servicePrincipals"
        params = {
            # appRoles, keyCredentials, passwordCredentials all valid per Graph docs
            "$select": "id,displayName,appId,servicePrincipalType,accountEnabled,appRoles,keyCredentials,passwordCredentials,tags",
            "$top": "999",
        }
        items = await self._paginate_graph(
            client, url, params,
            page_callback=lambda n: self._report("collect", f"Service principals: {n:,} collected"),
        )
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
        """
        Collect Graph data that can run in parallel with RBAC collection.

        Users are NOT fetched here — the orchestrator calls get_users_by_ids()
        after RBAC data is available so we only fetch users that actually appear
        in role assignments.  A 300K-user tenant becomes a few hundred/thousand
        targeted fetches instead of 300+ pages.

        Service principals (~40 pages for a 40K-SP tenant) are fetched in full
        because even SPs without RBAC roles are relevant for credential analysis.
        """
        self._report("collect", "Starting Microsoft Graph collection...", 0, 5)

        (
            tenant_info,
            groups,
            service_principals,
            app_registrations,
            directory_roles,
            ca_policies,
        ) = await asyncio.gather(
            self.get_tenant_info(client),
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

        return {
            "tenant_info": _safe(tenant_info, {}),
            "users": [],            # populated by orchestrator after RBAC via get_users_by_ids
            "ca_policies": _safe(ca_policies, []),
            "groups": _safe(groups, []),
            "group_memberships": {}, # populated by orchestrator after RBAC
            "service_principals": _safe(service_principals, []),
            "app_registrations": _safe(app_registrations, []),
            "directory_roles": _safe(directory_roles, []),
        }
