"""Collects Azure resources: subscriptions, resource groups, and typed resources."""
import asyncio
import logging
from typing import Any, Callable, Optional

import httpx

from ..config import settings
from .base import BaseCollector

logger = logging.getLogger(__name__)

ARM = settings.arm_api_base


class AzureCollector(BaseCollector):
    """Collects Azure resources via ARM REST API."""

    def __init__(self, subscription_id: str, progress_callback: Optional[Callable] = None):
        super().__init__(progress_callback)
        self.subscription_id = subscription_id
        self._sub_base = f"{ARM}/subscriptions/{subscription_id}"

    async def get_subscription_info(self, client: httpx.AsyncClient) -> dict:
        """Fetch subscription metadata."""
        url = f"{ARM}/subscriptions/{self.subscription_id}?api-version=2022-12-01"
        try:
            data = await self._get_arm(client, url)
            return {
                "subscription_id": data.get("subscriptionId", self.subscription_id),
                "display_name": data.get("displayName", "Unknown"),
                "tenant_id": data.get("tenantId", ""),
                "state": data.get("state", ""),
            }
        except Exception as e:
            logger.warning(f"Could not fetch subscription info: {e}")
            return {"subscription_id": self.subscription_id, "display_name": "Unknown"}

    async def get_resource_groups(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/resourcegroups?api-version=2021-04-01"
        self._report("azure", "Collecting resource groups...")
        items = await self._paginate_arm(client, url)
        return [
            {
                "id": rg.get("id", ""),
                "name": rg.get("name", ""),
                "location": rg.get("location", ""),
                "tags": rg.get("tags", {}),
            }
            for rg in items
        ]

    async def get_storage_accounts(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
        self._report("azure", "Collecting storage accounts...")
        items = await self._paginate_arm(client, url)
        return [
            {
                "id": s.get("id", ""),
                "name": s.get("name", ""),
                "location": s.get("location", ""),
                "resource_group": _rg_from_id(s.get("id", "")),
                "sku": s.get("sku", {}).get("name", ""),
                "kind": s.get("kind", ""),
                "allow_blob_public_access": s.get("properties", {}).get("allowBlobPublicAccess", False),
                "https_only": s.get("properties", {}).get("supportsHttpsTrafficOnly", True),
                "network_acls": s.get("properties", {}).get("networkAcls", {}),
                "minimum_tls_version": s.get("properties", {}).get("minimumTlsVersion", ""),
                "tags": s.get("tags", {}),
            }
            for s in items
        ]

    async def get_key_vaults(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        self._report("azure", "Collecting Key Vaults...")
        items = await self._paginate_arm(client, url)
        return [
            {
                "id": kv.get("id", ""),
                "name": kv.get("name", ""),
                "location": kv.get("location", ""),
                "resource_group": _rg_from_id(kv.get("id", "")),
                "sku": kv.get("properties", {}).get("sku", {}).get("name", ""),
                "vault_uri": kv.get("properties", {}).get("vaultUri", ""),
                "tenant_id": kv.get("properties", {}).get("tenantId", ""),
                "enable_rbac_authorization": kv.get("properties", {}).get("enableRbacAuthorization", False),
                "soft_delete_enabled": kv.get("properties", {}).get("enableSoftDelete", True),
                "access_policies": kv.get("properties", {}).get("accessPolicies", []),
                # Network isolation
                "network_acls": kv.get("properties", {}).get("networkAcls", {}),
                "private_endpoint_connections": kv.get("properties", {}).get("privateEndpointConnections", []),
                "public_network_access": kv.get("properties", {}).get("publicNetworkAccess", "Enabled"),
                "tags": kv.get("tags", {}),
            }
            for kv in items
        ]

    async def get_policy_assignments(self, client: httpx.AsyncClient) -> list[dict]:
        """Fetch Azure Policy assignments at subscription scope."""
        url = (
            f"{self._sub_base}/providers/Microsoft.Authorization/policyAssignments"
            "?api-version=2022-06-01"
        )
        self._report("azure", "Collecting Azure Policy assignments...")
        try:
            items = await self._paginate_arm(client, url)
        except Exception as e:
            logger.warning(f"Could not collect policy assignments: {e}")
            return []
        results = []
        for pa in items:
            props = pa.get("properties", {})
            results.append({
                "id": pa.get("id", ""),
                "name": pa.get("name", ""),
                "display_name": props.get("displayName", ""),
                "policy_definition_id": props.get("policyDefinitionId", ""),
                "scope": props.get("scope", ""),
                "enforcement_mode": props.get("enforcementMode", "Default"),
                "parameters": props.get("parameters", {}),
                # "deny" policies are the most security-relevant
                "is_deny": "deny" in props.get("policyDefinitionId", "").lower()
                           or "deny" in props.get("displayName", "").lower(),
            })
        return results

    async def get_function_apps(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.Web/sites?api-version=2023-01-01"
        self._report("azure", "Collecting Function Apps / App Services...")
        items = await self._paginate_arm(client, url)
        results = []
        for site in items:
            kind = site.get("kind", "")
            props = site.get("properties", {})
            identity = site.get("identity", {})
            results.append({
                "id": site.get("id", ""),
                "name": site.get("name", ""),
                "kind": kind,
                "node_type": "function_app" if "functionapp" in kind.lower() else "app_service",
                "location": site.get("location", ""),
                "resource_group": _rg_from_id(site.get("id", "")),
                "state": props.get("state", ""),
                "https_only": props.get("httpsOnly", False),
                "identity_type": identity.get("type", "None"),
                # System-assigned MI principal ID (if any)
                "system_identity_principal_id": identity.get("principalId"),
                # User-assigned MIs: {resource_id: {principalId, clientId}}
                "user_assigned_identities": identity.get("userAssignedIdentities", {}),
                "tags": site.get("tags", {}),
            })
        return results

    async def get_automation_accounts(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01"
        self._report("azure", "Collecting Automation Accounts...")
        try:
            items = await self._paginate_arm(client, url)
        except Exception:
            items = []
        return [
            {
                "id": a.get("id", ""),
                "name": a.get("name", ""),
                "location": a.get("location", ""),
                "resource_group": _rg_from_id(a.get("id", "")),
                "identity": a.get("identity", {}),
                "tags": a.get("tags", {}),
            }
            for a in items
        ]

    async def get_virtual_machines(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
        self._report("azure", "Collecting Virtual Machines...")
        try:
            items = await self._paginate_arm(client, url)
        except Exception:
            items = []
        results = []
        for vm in items:
            identity = vm.get("identity", {})
            results.append({
                "id": vm.get("id", ""),
                "name": vm.get("name", ""),
                "location": vm.get("location", ""),
                "resource_group": _rg_from_id(vm.get("id", "")),
                "os_type": vm.get("properties", {}).get("storageProfile", {}).get("osDisk", {}).get("osType", ""),
                "identity_type": identity.get("type", "None"),
                "system_identity_principal_id": identity.get("principalId"),
                "user_assigned_identities": identity.get("userAssignedIdentities", {}),
                "tags": vm.get("tags", {}),
            })
        return results

    async def get_user_assigned_managed_identities(self, client: httpx.AsyncClient) -> list[dict]:
        url = f"{self._sub_base}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-07-31-preview"
        self._report("azure", "Collecting User-Assigned Managed Identities...")
        try:
            items = await self._paginate_arm(client, url)
        except Exception:
            items = []
        return [
            {
                "id": mi.get("id", ""),
                "name": mi.get("name", ""),
                "location": mi.get("location", ""),
                "resource_group": _rg_from_id(mi.get("id", "")),
                "principal_id": mi.get("properties", {}).get("principalId", ""),
                "client_id": mi.get("properties", {}).get("clientId", ""),
                "tenant_id": mi.get("properties", {}).get("tenantId", ""),
                "tags": mi.get("tags", {}),
            }
            for mi in items
        ]

    async def get_app_auth_settings(
        self, client: httpx.AsyncClient, apps: list[dict]
    ) -> dict[str, dict]:
        """
        Fetch authsettingsV2 for each web/function app.
        Returns {app_id: {enabled, require_https, unauthenticated_client_action, ...}}
        """
        sem = asyncio.Semaphore(5)
        results: dict[str, dict] = {}

        async def _fetch(app: dict):
            resource_id = app["id"]
            url = f"{ARM}{resource_id}/config/authsettingsV2?api-version=2022-09-01"
            async with sem:
                try:
                    data = await self._get_arm(client, url)
                    props = data.get("properties", {})
                    platform = props.get("platform", {})
                    global_validation = props.get("globalValidation", {})
                    results[resource_id] = {
                        "auth_enabled": platform.get("enabled", False),
                        "unauthenticated_action": global_validation.get("unauthenticatedClientAction", "AllowAnonymous"),
                        "require_https": app.get("https_only", False),
                    }
                except Exception:
                    # Auth settings endpoint may return 404 for apps using old auth
                    results[resource_id] = {"auth_enabled": None, "unauthenticated_action": "unknown"}

        await asyncio.gather(*[_fetch(a) for a in apps])
        return results

    async def get_automation_runbooks(
        self, client: httpx.AsyncClient, automation_accounts: list[dict]
    ) -> list[dict]:
        """
        Fetch runbook metadata + content for each automation account.
        Scans content for suspicious patterns (credential exfiltration, download, etc.).
        """
        sem = asyncio.Semaphore(3)
        all_runbooks: list[dict] = []

        _SUSPICIOUS = [
            "invoke-webrequest", "invoke-restmethod", "start-process",
            "downloadstring", "downloadfile", "net.webclient",
            "convertto-securestring", "get-credential", "secretvalue",
            "bypass", "encodedcommand", "-enc ", "iex(", "iex ",
            "curl ", "wget ", "base64",
        ]

        async def _fetch_account(aa: dict):
            rg = aa.get("resource_group", "")
            name = aa.get("name", "")
            if not rg or not name:
                return
            url = (
                f"{ARM}/subscriptions/{self.subscription_id}/resourceGroups/{rg}"
                f"/providers/Microsoft.Automation/automationAccounts/{name}"
                f"/runbooks?api-version=2023-11-01"
            )
            async with sem:
                try:
                    items = await self._paginate_arm(client, url)
                except Exception:
                    return
                for rb in items:
                    rb_name = rb.get("name", "")
                    rb_type = rb.get("properties", {}).get("runbookType", "")
                    content_url = (
                        f"{ARM}/subscriptions/{self.subscription_id}/resourceGroups/{rg}"
                        f"/providers/Microsoft.Automation/automationAccounts/{name}"
                        f"/runbooks/{rb_name}/content?api-version=2023-11-01"
                    )
                    suspicious_matches: list[str] = []
                    try:
                        resp = await client.get(
                            content_url,
                            headers=self._arm_headers(),
                            timeout=15,
                        )
                        if resp.status_code == 200:
                            content_lower = resp.text.lower()
                            suspicious_matches = [
                                p for p in _SUSPICIOUS if p in content_lower
                            ]
                    except Exception:
                        pass

                    all_runbooks.append({
                        "automation_account_id": aa["id"],
                        "automation_account_name": name,
                        "runbook_name": rb_name,
                        "runbook_type": rb_type,
                        "state": rb.get("properties", {}).get("state", ""),
                        "suspicious_patterns": suspicious_matches,
                        "is_suspicious": len(suspicious_matches) > 0,
                    })

        await asyncio.gather(*[_fetch_account(aa) for aa in automation_accounts])
        return all_runbooks

    async def collect_all(self, client: httpx.AsyncClient) -> dict:
        """Run all resource collectors concurrently and return combined result."""
        self._report("azure", "Starting Azure resource collection...", 0, 7)

        (
            sub_info,
            resource_groups,
            storage_accounts,
            key_vaults,
            web_apps,
            automation_accounts,
            virtual_machines,
            managed_identities,
        ) = await asyncio.gather(
            self.get_subscription_info(client),
            self.get_resource_groups(client),
            self.get_storage_accounts(client),
            self.get_key_vaults(client),
            self.get_function_apps(client),
            self.get_automation_accounts(client),
            self.get_virtual_machines(client),
            self.get_user_assigned_managed_identities(client),
            return_exceptions=True,
        )

        def _safe(result, default):
            return default if isinstance(result, Exception) else result

        resolved_web_apps = _safe(web_apps, [])
        resolved_automation = _safe(automation_accounts, [])

        # Second pass: auth settings + runbooks (depends on first pass)
        app_auth, runbooks = await asyncio.gather(
            self.get_app_auth_settings(client, resolved_web_apps),
            self.get_automation_runbooks(client, resolved_automation),
            return_exceptions=True,
        )
        app_auth_map  = _safe(app_auth, {})
        resolved_runbooks = _safe(runbooks, [])

        # Annotate each app with its auth settings
        for app in resolved_web_apps:
            auth = app_auth_map.get(app["id"], {})
            app["auth_enabled"] = auth.get("auth_enabled")
            app["unauthenticated_action"] = auth.get("unauthenticated_action", "unknown")

        # Collect Azure Policy assignments (runs alongside other collections)
        policy_assignments = await self.get_policy_assignments(client)

        return {
            "subscription": _safe(sub_info, {}),
            "resource_groups": _safe(resource_groups, []),
            "storage_accounts": _safe(storage_accounts, []),
            "key_vaults": _safe(key_vaults, []),
            "web_apps": resolved_web_apps,
            "automation_accounts": resolved_automation,
            "runbooks": resolved_runbooks,
            "virtual_machines": _safe(virtual_machines, []),
            "managed_identities": _safe(managed_identities, []),
            "policy_assignments": policy_assignments,
        }


def _rg_from_id(resource_id: str) -> str:
    """Extract resource group name from Azure resource ID."""
    parts = resource_id.lower().split("/")
    try:
        idx = parts.index("resourcegroups")
        return resource_id.split("/")[idx + 1]
    except (ValueError, IndexError):
        return ""
