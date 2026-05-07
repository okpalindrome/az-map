"""
Privilege Escalation Rules Engine.

Each rule is a function that takes context and emits Finding dicts.
Rules model real-world Azure attack paths from Microsoft threat research.
"""
from __future__ import annotations

import logging
from typing import Any, Generator

logger = logging.getLogger(__name__)

# Role name sets
_OWNER_ROLES = {"Owner"}
_UAA_ROLES = {"User Access Administrator", "Role Based Access Control Administrator"}
_CONTRIBUTOR_ROLES = {"Contributor"}
_KV_ADMIN_ROLES = {"Key Vault Administrator"}
_KV_SECRET_ROLES = {"Key Vault Secrets User", "Key Vault Administrator"}
_STORAGE_CONTRIB_ROLES = {"Storage Account Contributor", "Storage Account Key Operator Service Role"}
_AUTOMATION_CONTRIB = {"Automation Contributor", "Contributor", "Owner"}
_WEBSITE_CONTRIB = {"Website Contributor", "Contributor", "Owner"}
_MI_OPERATOR = {"Managed Identity Operator", "Contributor", "Owner"}


def _find_dict(finding_type: str, severity: str, title: str, description: str,
               affected_id: str, affected_name: str, attack_chain: list,
               why_risky: str, remediation: str, tags: list, risk_score: float,
               blast_radius: int = 0) -> dict:
    return {
        "finding_type": finding_type,
        "severity": severity,
        "title": title,
        "description": description,
        "affected_node_id": affected_id,
        "affected_node_name": affected_name,
        "attack_chain": attack_chain,
        "why_risky": why_risky,
        "remediation": remediation,
        "tags": tags,
        "risk_score": risk_score,
        "blast_radius": blast_radius,
    }


class PrivilegeEscalationAnalyzer:
    """
    Runs rule-based detection against collected data.

    Context expected:
      - role_assignments: list of RoleAssignment dicts
      - principal_effective_roles: {principal_id: [role_assignment dicts]}
      - resource_nodes: {resource_id: node dict}
      - service_principals: list of SP dicts
      - function_apps / vms / automation: lists of resource dicts
      - group_memberships: {group_id: [member dicts]}
      - directory_roles: list of Entra role assignment dicts
    """

    def __init__(self, context: dict):
        self.ctx = context
        # index: principal_id → set of role names (subscription-level or below)
        self._principal_roles: dict[str, set[str]] = {}
        for pid, ras in context.get("principal_effective_roles", {}).items():
            self._principal_roles[pid] = {ra.get("role_name", "") for ra in ras}

    def _has_any_role(self, principal_id: str, role_names: set[str]) -> bool:
        return bool(self._principal_roles.get(principal_id, set()) & role_names)

    def _get_principal_name(self, principal_id: str) -> str:
        nodes = self.ctx.get("resource_nodes", {})
        n = nodes.get(principal_id, {})
        return n.get("display_name") or n.get("name") or principal_id

    # ------------------------------------------------------------------
    # Rule 1: Contributor + User Access Administrator → Owner escalation
    # ------------------------------------------------------------------
    def rule_contributor_plus_uaa(self) -> Generator[dict, None, None]:
        for pid, roles in self._principal_roles.items():
            if (roles & _CONTRIBUTOR_ROLES) and (roles & _UAA_ROLES):
                name = self._get_principal_name(pid)
                yield _find_dict(
                    finding_type="privilege_escalation",
                    severity="critical",
                    title=f"Privilege escalation: Contributor + UAA → Owner ({name})",
                    description=(
                        f"{name} holds both Contributor and User Access Administrator "
                        "(or RBAC Administrator) roles. This combination allows assigning "
                        "the Owner role to any controlled identity."
                    ),
                    affected_id=pid,
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": "Principal already has Contributor (full resource access)"},
                        {"step": 2, "action": "Use User Access Administrator to assign Owner to self"},
                        {"step": 3, "action": "Now has full Owner control of subscription"},
                    ],
                    why_risky="Combination grants effective Owner without being explicitly assigned Owner.",
                    remediation=(
                        "Remove User Access Administrator or RBAC Administrator from this identity. "
                        "If role assignment capability is required, scope it to a specific resource group."
                    ),
                    tags=["privilege-escalation", "rbac", "owner"],
                    risk_score=9.5,
                    blast_radius=100,
                )

    # ------------------------------------------------------------------
    # Rule 2: Direct Owner at subscription scope
    # ------------------------------------------------------------------
    def rule_subscription_owner(self) -> Generator[dict, None, None]:
        for ra in self.ctx.get("role_assignments", []):
            if ra.get("role_name") == "Owner" and ra.get("scope_level") == "subscription":
                pid = ra["principal_id"]
                name = self._get_principal_name(pid)
                yield _find_dict(
                    finding_type="high_risk_role",
                    severity="critical",
                    title=f"Owner at subscription scope: {name}",
                    description=f"{name} is assigned Owner at the subscription level.",
                    affected_id=pid,
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": "Identity has Owner at subscription scope"},
                        {"step": 2, "action": "Can read/write/delete any resource in subscription"},
                        {"step": 3, "action": "Can assign any RBAC role to any identity"},
                    ],
                    why_risky="Owner at subscription is the broadest possible Azure privilege.",
                    remediation="Apply least privilege. Replace Owner with specific roles needed. Use PIM for Owner.",
                    tags=["excessive-privilege", "owner", "subscription"],
                    risk_score=9.0,
                    blast_radius=100,
                )

    # ------------------------------------------------------------------
    # Rule 3: Service principal with credentials + high privilege
    # ------------------------------------------------------------------
    def rule_privileged_sp_with_secrets(self) -> Generator[dict, None, None]:
        sps = {sp["id"]: sp for sp in self.ctx.get("service_principals", [])}
        for pid, roles in self._principal_roles.items():
            sp = sps.get(pid)
            if not sp:
                continue
            high_roles = roles & (_OWNER_ROLES | _UAA_ROLES | _CONTRIBUTOR_ROLES)
            if high_roles and (sp.get("has_key_credentials") or sp.get("has_password_credentials")):
                name = sp.get("display_name", pid)
                yield _find_dict(
                    finding_type="over_privileged_sp",
                    severity="high",
                    title=f"Privileged SP with credentials: {name}",
                    description=(
                        f"Service principal '{name}' has {', '.join(high_roles)} role(s) "
                        "AND active credentials (key or password). Credential compromise = full privilege."
                    ),
                    affected_id=pid,
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Attacker extracts credentials for SP '{name}'"},
                        {"step": 2, "action": f"Authenticates as SP (has {', '.join(high_roles)})"},
                        {"step": 3, "action": "Full privilege access to Azure resources"},
                    ],
                    why_risky="Long-lived credentials on high-privilege SPs are a primary attack surface.",
                    remediation=(
                        "Rotate or remove credentials. Use certificate-based auth with short expiry. "
                        "Replace with managed identity where possible. Apply PIM."
                    ),
                    tags=["service-principal", "credentials", "high-privilege"],
                    risk_score=8.5,
                    blast_radius=80,
                )

    # ------------------------------------------------------------------
    # Rule 4: Function App with high-privilege managed identity
    # ------------------------------------------------------------------
    def rule_function_app_privileged_identity(self) -> Generator[dict, None, None]:
        for app in self.ctx.get("function_apps", []):
            app_id = app["id"]
            app_name = app["name"]
            sp_id = app.get("system_identity_principal_id")
            if not sp_id:
                continue
            roles = self._principal_roles.get(sp_id, set())
            high_roles = roles & (_OWNER_ROLES | _UAA_ROLES | _CONTRIBUTOR_ROLES)
            if high_roles:
                yield _find_dict(
                    finding_type="misconfigured_identity",
                    severity="critical",
                    title=f"Function App with high-privilege identity: {app_name}",
                    description=(
                        f"Function App '{app_name}' has a system-assigned managed identity "
                        f"with {', '.join(high_roles)} role(s). Code execution in this app "
                        "immediately yields these privileges."
                    ),
                    affected_id=app_id,
                    affected_name=app_name,
                    attack_chain=[
                        {"step": 1, "action": f"Compromise code/config of Function App '{app_name}'"},
                        {"step": 2, "action": "App's managed identity has high-privilege role"},
                        {"step": 3, "action": f"IMDS endpoint yields token with {', '.join(high_roles)}"},
                        {"step": 4, "action": "Full Azure control plane access"},
                    ],
                    why_risky="Over-privileged app identities allow full privilege from code execution.",
                    remediation="Apply least privilege to function app identity. Scope to specific resources only.",
                    tags=["function-app", "managed-identity", "privilege-escalation"],
                    risk_score=9.0,
                    blast_radius=90,
                )

    # ------------------------------------------------------------------
    # Rule 5: Key Vault access via Contributor (legacy access policies)
    # ------------------------------------------------------------------
    def rule_kv_contributor_secret_access(self) -> Generator[dict, None, None]:
        for kv in self.ctx.get("key_vaults", []):
            if kv.get("enable_rbac_authorization"):
                continue  # RBAC mode — access policies not relevant
            access_policies = kv.get("access_policies", [])
            for policy in access_policies:
                secret_perms = policy.get("permissions", {}).get("secrets", [])
                if "get" in secret_perms or "list" in secret_perms:
                    oid = policy.get("objectId", "")
                    name = self._get_principal_name(oid) or oid
                    yield _find_dict(
                        finding_type="sensitive_resource_access",
                        severity="high",
                        title=f"Key Vault access policy grants secret read: {kv['name']}",
                        description=(
                            f"Identity {name} has secret Get/List permissions on Key Vault "
                            f"'{kv['name']}' via legacy access policies."
                        ),
                        affected_id=kv["id"],
                        affected_name=kv["name"],
                        attack_chain=[
                            {"step": 1, "action": f"Identity '{name}' authenticates to Key Vault"},
                            {"step": 2, "action": "Access policy allows GET/LIST on secrets"},
                            {"step": 3, "action": "Attacker extracts all secrets from vault"},
                        ],
                        why_risky="Key Vault secrets often contain connection strings, API keys, certs.",
                        remediation=(
                            "Migrate to RBAC authorization. Audit who needs secret access. "
                            "Use Key Vault Secrets User (read-only) not Contributor."
                        ),
                        tags=["key-vault", "secret-access", "access-policy"],
                        risk_score=7.5,
                        blast_radius=70,
                    )

    # ------------------------------------------------------------------
    # Rule 6: Storage Account Contributor → key extraction
    # ------------------------------------------------------------------
    def rule_storage_key_access(self) -> Generator[dict, None, None]:
        for pid, roles in self._principal_roles.items():
            if roles & _STORAGE_CONTRIB_ROLES:
                name = self._get_principal_name(pid)
                yield _find_dict(
                    finding_type="sensitive_resource_access",
                    severity="high",
                    title=f"Storage Account key access: {name}",
                    description=(
                        f"{name} has Storage Account Contributor or Key Operator role. "
                        "This allows listing storage account keys, granting full data-plane access."
                    ),
                    affected_id=pid,
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Identity '{name}' lists storage account keys"},
                        {"step": 2, "action": "Full data-plane access to all blobs/tables/queues/files"},
                        {"step": 3, "action": "Can read sensitive data or generate SAS tokens"},
                    ],
                    why_risky="Storage keys provide permanent full data-plane access bypassing RBAC.",
                    remediation=(
                        "Replace Storage Account Contributor with Storage Blob Data Reader/Contributor. "
                        "Disable shared key access. Enforce Azure AD authentication only."
                    ),
                    tags=["storage", "key-access", "data-plane"],
                    risk_score=7.0,
                    blast_radius=60,
                )

    # ------------------------------------------------------------------
    # Rule 7: Global Admin / Privileged Entra roles
    # ------------------------------------------------------------------
    def rule_privileged_entra_roles(self) -> Generator[dict, None, None]:
        privileged_roles = [
            dr for dr in self.ctx.get("directory_roles", [])
            if dr.get("is_privileged")
        ]
        for dr in privileged_roles:
            pid = dr["principal_id"]
            name = dr.get("principal_display_name") or self._get_principal_name(pid)
            yield _find_dict(
                finding_type="high_risk_role",
                severity="critical" if dr["role_name"] == "Global Administrator" else "high",
                title=f"Privileged Entra role: {dr['role_name']} → {name}",
                description=(
                    f"{name} holds the '{dr['role_name']}' Entra ID directory role."
                ),
                affected_id=pid,
                affected_name=name,
                attack_chain=[
                    {"step": 1, "action": f"Identity '{name}' is {dr['role_name']}"},
                    {"step": 2, "action": "Can manage users, groups, apps in the tenant"},
                    {"step": 3, "action": "Can escalate to Global Admin or read all data"},
                ],
                why_risky=f"'{dr['role_name']}' is a Tier-0 Entra identity. Compromise = tenant takeover risk.",
                remediation="Apply PIM (Privileged Identity Management). Use break-glass accounts. Enable MFA.",
                tags=["entra-id", "directory-role", dr["role_name"].lower().replace(" ", "-")],
                risk_score=9.0 if dr["role_name"] == "Global Administrator" else 7.5,
                blast_radius=100,
            )

    # ------------------------------------------------------------------
    # Rule 8: User-Assigned MI used by multiple resources (blast radius)
    # ------------------------------------------------------------------
    def rule_shared_managed_identity(self) -> Generator[dict, None, None]:
        from collections import defaultdict
        mi_users: dict[str, list[str]] = defaultdict(list)
        for app in list(self.ctx.get("function_apps", [])) + list(self.ctx.get("virtual_machines", [])):
            for ua_id in app.get("user_assigned_identities", {}):
                mi_users[ua_id].append(app.get("name", app.get("id", "")))
        for mi_id, users in mi_users.items():
            if len(users) > 2:
                yield _find_dict(
                    finding_type="misconfigured_identity",
                    severity="medium",
                    title=f"User-Assigned MI shared across {len(users)} resources",
                    description=(
                        f"Managed identity is attached to {len(users)} resources: "
                        f"{', '.join(users[:5])}{'...' if len(users) > 5 else ''}. "
                        "Compromise of any one resource grants identity to all."
                    ),
                    affected_id=mi_id,
                    affected_name=mi_id.split("/")[-1],
                    attack_chain=[
                        {"step": 1, "action": f"Compromise any of: {', '.join(users[:3])}"},
                        {"step": 2, "action": "Use IMDS to get managed identity token"},
                        {"step": 3, "action": "Identity is shared — lateral movement to all resources using it"},
                    ],
                    why_risky="Shared identities amplify blast radius of a single resource compromise.",
                    remediation="Use separate managed identities per resource. Follow least-privilege identity design.",
                    tags=["managed-identity", "blast-radius", "lateral-movement"],
                    risk_score=5.5,
                    blast_radius=len(users) * 10,
                )

    # ------------------------------------------------------------------
    # Rule 9: Automation Account with system identity
    # ------------------------------------------------------------------
    def rule_automation_account_identity(self) -> Generator[dict, None, None]:
        for aa in self.ctx.get("automation_accounts", []):
            sp_id = aa.get("identity", {}).get("principalId")
            if not sp_id:
                continue
            roles = self._principal_roles.get(sp_id, set())
            high_roles = roles & (_OWNER_ROLES | _CONTRIBUTOR_ROLES | _UAA_ROLES)
            if high_roles:
                name = aa.get("name", aa["id"])
                yield _find_dict(
                    finding_type="privilege_escalation",
                    severity="high",
                    title=f"Automation Account with privileged identity: {name}",
                    description=(
                        f"Automation Account '{name}' has a managed identity with "
                        f"{', '.join(high_roles)}. Any runbook writer can execute code as this identity."
                    ),
                    affected_id=aa["id"],
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Write a runbook in Automation Account '{name}'"},
                        {"step": 2, "action": "Runbook executes as managed identity"},
                        {"step": 3, "action": f"Managed identity has {', '.join(high_roles)} → full access"},
                    ],
                    why_risky="Automation accounts with high-privilege identities are a common lateral movement path.",
                    remediation="Apply least privilege to automation identity. Restrict runbook write access.",
                    tags=["automation", "managed-identity", "privilege-escalation"],
                    risk_score=8.0,
                    blast_radius=75,
                )

    # ------------------------------------------------------------------
    # Rule 10: Persistence — SP with expiring soon / long-lived credentials
    # ------------------------------------------------------------------
    def rule_persistence_sp_credentials(self) -> Generator[dict, None, None]:
        for sp in self.ctx.get("service_principals", []):
            cred_count = sp.get("key_credential_count", 0) + sp.get("password_credential_count", 0)
            if cred_count > 3:
                name = sp.get("display_name", sp["id"])
                yield _find_dict(
                    finding_type="persistence_risk",
                    severity="medium",
                    title=f"SP with many credentials (possible persistence): {name}",
                    description=(
                        f"Service principal '{name}' has {cred_count} credentials. "
                        "Multiple credentials may indicate credential stuffing or persistence by an attacker."
                    ),
                    affected_id=sp["id"],
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Attacker adds credential to '{name}' SP"},
                        {"step": 2, "action": "Even if original credential rotated, attacker retains access"},
                    ],
                    why_risky="Multiple credentials on a single SP is an attacker persistence indicator.",
                    remediation="Audit all credentials. Remove unused ones. Monitor for unexpected credential additions.",
                    tags=["service-principal", "persistence", "credentials"],
                    risk_score=6.0,
                    blast_radius=50,
                )

    # ------------------------------------------------------------------
    # Rule 11: Nested group privilege accumulation
    # ------------------------------------------------------------------
    def rule_nested_group_escalation(self) -> Generator[dict, None, None]:
        """Detect groups that have dangerous roles AND contain other groups (nested membership)."""
        group_memberships = self.ctx.get("group_memberships_raw", {})  # {group_id: [member dicts]}
        for gid, roles in self._principal_roles.items():
            high_roles = roles & (_OWNER_ROLES | _UAA_ROLES | _CONTRIBUTOR_ROLES)
            if not high_roles:
                continue
            # Check if this group contains sub-groups
            members = group_memberships.get(gid, [])
            sub_groups = [m for m in members if m.get("type", "").lower() in ("group", "microsoftgraph.group")]
            if not sub_groups:
                continue
            name = self._get_principal_name(gid)
            sub_names = ", ".join(m.get("display_name") or m.get("id", "") for m in sub_groups[:3])
            yield _find_dict(
                finding_type="excessive_privilege",
                severity="high",
                title=f"Nested group inherits privileged role: {name}",
                description=(
                    f"Group '{name}' has {', '.join(high_roles)} and contains nested groups: {sub_names}. "
                    "Members of nested groups inherit the privileged role transitively."
                ),
                affected_id=gid,
                affected_name=name,
                attack_chain=[
                    {"step": 1, "action": f"User is member of a nested sub-group of '{name}'"},
                    {"step": 2, "action": f"'{name}' has {', '.join(high_roles)} role"},
                    {"step": 3, "action": "User inherits privileged role without being directly assigned"},
                ],
                why_risky="Nested group membership silently widens the blast radius of privileged role assignments.",
                remediation=(
                    "Flatten group nesting for security groups with Azure RBAC assignments. "
                    "Audit transitive membership regularly."
                ),
                tags=["group", "nested-groups", "privilege-escalation"],
                risk_score=7.0,
                blast_radius=60,
            )

    # ------------------------------------------------------------------
    # Rule 12: Reader + Key Vault Secrets User → silent data exfiltration
    # ------------------------------------------------------------------
    def rule_reader_plus_kv_secrets(self) -> Generator[dict, None, None]:
        """Reader at subscription + KV Secrets User = full tenant-wide secret read."""
        _READER = {"Reader"}
        _KV_SECRET = {"Key Vault Secrets User", "Key Vault Administrator"}
        for pid, roles in self._principal_roles.items():
            if (roles & _READER) and (roles & _KV_SECRET):
                name = self._get_principal_name(pid)
                yield _find_dict(
                    finding_type="sensitive_resource_access",
                    severity="high",
                    title=f"Silent data exfiltration path (Reader + KV Secrets): {name}",
                    description=(
                        f"{name} has both Reader (can enumerate all resources) and "
                        "Key Vault Secrets User (can read any secret). "
                        "This combination enables full silent credential exfiltration."
                    ),
                    affected_id=pid,
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Identity '{name}' uses Reader to list all Key Vaults in subscription"},
                        {"step": 2, "action": "Uses Key Vault Secrets User to GET every secret across all vaults"},
                        {"step": 3, "action": "Exfiltrates connection strings, certificates, API keys — no alerts triggered"},
                    ],
                    why_risky=(
                        "Reader + KV Secrets User allows silent read-only data theft of all secrets. "
                        "Often overlooked because neither role appears dangerous in isolation."
                    ),
                    remediation=(
                        "Scope Key Vault Secrets User to specific vaults only. "
                        "Never combine subscription-level Reader with KV secret access. "
                        "Enable KV diagnostic logging and alert on bulk secret reads."
                    ),
                    tags=["key-vault", "data-exfiltration", "reader", "lateral-movement"],
                    risk_score=8.0,
                    blast_radius=85,
                )

    # ------------------------------------------------------------------
    # Rule 13: App registration requesting high Graph API permissions
    # ------------------------------------------------------------------
    def rule_app_high_graph_permissions(self) -> Generator[dict, None, None]:
        """App registrations with dangerous Graph API delegated or app permissions."""
        _DANGEROUS_GRAPH_PERMS = {
            "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
            "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
            "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application.ReadWrite.OwnedBy
            "62a82d76-70ea-41e2-9197-370581804d09",  # Group.ReadWrite.All
            "dbaae8cf-10b5-4b86-a4a1-f871c94c6695",  # GroupMember.ReadWrite.All
            "741f803b-c850-494e-b5df-cde7c675a1ca",  # User.ReadWrite.All
            "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read.All (broad)
        }
        _DANGEROUS_NAMES = {
            "RoleManagement.ReadWrite.Directory",
            "AppRoleAssignment.ReadWrite.All",
            "Application.ReadWrite.All",
            "Group.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "User.ReadWrite.All",
        }
        for app in self.ctx.get("app_registrations", []):
            requested = app.get("requested_permissions", [])
            dangerous = []
            for resource_req in requested:
                for scope in resource_req.get("resourceAccess", []):
                    sid = scope.get("id", "")
                    stype = scope.get("type", "")  # Role = app permission, Scope = delegated
                    if sid in _DANGEROUS_GRAPH_PERMS and stype == "Role":
                        dangerous.append(sid)
            if dangerous:
                name = app.get("display_name", app.get("id", ""))
                yield _find_dict(
                    finding_type="over_privileged_sp",
                    severity="high",
                    title=f"App requests dangerous Graph app permissions: {name}",
                    description=(
                        f"App registration '{name}' requests {len(dangerous)} high-privilege "
                        "Microsoft Graph application permission(s). If consented, it can operate "
                        "across the entire tenant without user context."
                    ),
                    affected_id=app.get("id", ""),
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Admin consents to app '{name}' Graph permissions"},
                        {"step": 2, "action": "App (or attacker who compromises it) can read/write users, groups, roles"},
                        {"step": 3, "action": "Full tenant enumeration or privilege escalation via role assignment"},
                    ],
                    why_risky="Graph app permissions operate at tenant-wide scope with no user delegation boundary.",
                    remediation=(
                        "Review and reduce requested permissions. Use delegated permissions where possible. "
                        "Implement admin consent workflow. Audit all consented app permissions quarterly."
                    ),
                    tags=["app-registration", "graph-permissions", "tenant-wide"],
                    risk_score=8.0,
                    blast_radius=90,
                )

    # ------------------------------------------------------------------
    # Rule 14: Managed Identity lateral movement to Key Vault / Storage
    # ------------------------------------------------------------------
    def rule_mi_lateral_movement(self) -> Generator[dict, None, None]:
        """Resources with MIs that have KV or Storage access = pivot path."""
        _KV_ACCESS = {"Key Vault Secrets User", "Key Vault Administrator",
                      "Key Vault Crypto Service Encryption User"}
        _STORAGE_ACCESS = {"Storage Blob Data Contributor", "Storage Blob Data Reader",
                           "Storage Account Contributor", "Storage Account Key Operator Service Role"}
        _SENSITIVE = _KV_ACCESS | _STORAGE_ACCESS

        for app in list(self.ctx.get("function_apps", [])) + list(self.ctx.get("virtual_machines", [])):
            sp_id = app.get("system_identity_principal_id")
            if not sp_id:
                continue
            roles = self._principal_roles.get(sp_id, set())
            sensitive = roles & _SENSITIVE
            if not sensitive:
                continue
            resource_name = app.get("name", app.get("id", ""))
            node_type = "function_app" if "function" in app.get("node_type", app.get("kind", "")).lower() else "vm"
            yield _find_dict(
                finding_type="lateral_movement",
                severity="high",
                title=f"MI lateral movement: {resource_name} → {', '.join(list(sensitive)[:2])}",
                description=(
                    f"{node_type.replace('_',' ').title()} '{resource_name}' has a managed identity "
                    f"with {', '.join(sensitive)} access. Compromising this resource enables pivoting "
                    "to sensitive data."
                ),
                affected_id=app.get("id", ""),
                affected_name=resource_name,
                attack_chain=[
                    {"step": 1, "action": f"Compromise {node_type} '{resource_name}' via code exec, misconfiguration, or vuln"},
                    {"step": 2, "action": "Use IMDS (169.254.169.254) to get managed identity access token"},
                    {"step": 3, "action": f"Token grants {', '.join(sensitive)} — extract secrets/data"},
                ],
                why_risky="Identity-bearing compute is a lateral movement stepping stone to sensitive data stores.",
                remediation=(
                    "Scope managed identity permissions to specific vaults/containers, not entire subscriptions. "
                    "Use Key Vault Secrets User (read specific) not Contributor."
                ),
                tags=["managed-identity", "lateral-movement", "key-vault", "storage"],
                risk_score=7.5,
                blast_radius=65,
            )

    # ------------------------------------------------------------------
    # Rule 15: Internet-exposed app with no authentication
    # ------------------------------------------------------------------
    def rule_internet_exposed_no_auth(self) -> Generator[dict, None, None]:
        """Function apps / app services that allow anonymous public access."""
        for app in self.ctx.get("function_apps", []):
            state = app.get("state", "")
            if state and state.lower() != "running":
                continue
            auth_enabled = app.get("auth_enabled")
            unauth_action = app.get("unauthenticated_action", "")
            https_only = app.get("https_only", True)

            issues = []
            if auth_enabled is False:
                issues.append("no authentication configured")
            if unauth_action in ("AllowAnonymous", "allow_anonymous"):
                issues.append("anonymous access allowed")
            if not https_only:
                issues.append("HTTP (non-HTTPS) traffic allowed")

            if not issues:
                continue

            name = app.get("name", app.get("id", ""))
            has_identity = bool(app.get("system_identity_principal_id") or app.get("user_assigned_identities"))
            severity = "high" if has_identity else "medium"
            risk_score = 7.0 if has_identity else 5.0

            yield _find_dict(
                finding_type="misconfigured_identity",
                severity=severity,
                title=f"Internet-exposed app without authentication: {name}",
                description=(
                    f"App '{name}' is publicly accessible with: {', '.join(issues)}."
                    + (" It also has a managed identity — unauthenticated callers can trigger"
                       " code that runs with Azure privileges." if has_identity else "")
                ),
                affected_id=app.get("id", ""),
                affected_name=name,
                attack_chain=[
                    {"step": 1, "action": f"External attacker accesses '{name}' without credentials"},
                    {"step": 2, "action": "Triggers app logic or finds injection point"},
                    {"step": 3, "action": "App runs as managed identity — attacker pivots to Azure resources"}
                    if has_identity else
                    {"step": 3, "action": "Data exposure or SSRF to internal Azure services"},
                ],
                why_risky="Public apps without auth are directly reachable by any internet actor.",
                remediation=(
                    "Enable Easy Auth (Azure AD) or a custom auth layer. "
                    "Set httpsOnly=true. If public access isn't needed, restrict via private endpoint or IP allowlist."
                ),
                tags=["internet-exposed", "no-auth", "public-access"],
                risk_score=risk_score,
                blast_radius=50 if has_identity else 30,
            )

    # ------------------------------------------------------------------
    # Rule 16: No Conditional Access policies → all users lack MFA enforcement
    # ------------------------------------------------------------------
    def rule_ca_policy_gaps(self) -> Generator[dict, None, None]:
        """Detect missing or weak Conditional Access coverage."""
        ca_policies = self.ctx.get("ca_policies", [])
        privileged_dir_roles = [
            dr for dr in self.ctx.get("directory_roles", [])
            if dr.get("is_privileged")
        ]
        if not privileged_dir_roles:
            return  # No privileged identities to protect — skip

        if not ca_policies:
            yield _find_dict(
                finding_type="misconfigured_identity",
                severity="critical",
                title="No Conditional Access policies configured",
                description=(
                    "The tenant has no Conditional Access policies. All users authenticate "
                    "without any MFA, location, or device compliance enforcement."
                ),
                affected_id="tenant",
                affected_name="Tenant",
                attack_chain=[
                    {"step": 1, "action": "Attacker phishes or brute-forces any user's password"},
                    {"step": 2, "action": "No MFA challenge — authentication succeeds immediately"},
                    {"step": 3, "action": "Full account access, including admin accounts"},
                ],
                why_risky="Without CA policies, stolen passwords grant immediate unrestricted access.",
                remediation=(
                    "Create baseline CA policies: require MFA for all users, "
                    "block legacy auth protocols, require compliant devices for admins."
                ),
                tags=["conditional-access", "mfa", "no-policy"],
                risk_score=9.5,
                blast_radius=100,
            )
            return

        # Check if any enabled CA policy targets privileged roles / all users with MFA
        mfa_enabled_policies = [
            p for p in ca_policies
            if p.get("state") == "enabled"
            and "mfa" in str(p.get("grant_controls", {})).lower()
        ]
        if not mfa_enabled_policies:
            yield _find_dict(
                finding_type="misconfigured_identity",
                severity="high",
                title="Conditional Access policies exist but MFA is not enforced",
                description=(
                    f"Found {len(ca_policies)} CA policies but none enforce MFA as a grant control. "
                    "Privileged accounts may authenticate with password only."
                ),
                affected_id="tenant",
                affected_name="Tenant",
                attack_chain=[
                    {"step": 1, "action": "CA policies exist but do not require MFA"},
                    {"step": 2, "action": "Stolen password → direct access to privileged accounts"},
                ],
                why_risky="MFA is the single most effective control against credential-based attacks.",
                remediation="Add MFA grant requirement to existing CA policies. Target all users or at minimum admin roles.",
                tags=["conditional-access", "mfa", "weak-policy"],
                risk_score=7.5,
                blast_radius=80,
            )

    # ------------------------------------------------------------------
    # Rule 17: Automation runbook with suspicious patterns
    # ------------------------------------------------------------------
    def rule_suspicious_runbooks(self) -> Generator[dict, None, None]:
        """Flag automation runbooks with suspicious code patterns."""
        for rb in self.ctx.get("runbooks", []):
            if not rb.get("is_suspicious"):
                continue
            patterns = rb.get("suspicious_patterns", [])
            aa_name = rb.get("automation_account_name", "")
            rb_name = rb.get("runbook_name", "")
            aa_id   = rb.get("automation_account_id", "")
            yield _find_dict(
                finding_type="persistence_risk",
                severity="high",
                title=f"Suspicious runbook: {aa_name}/{rb_name}",
                description=(
                    f"Runbook '{rb_name}' in Automation Account '{aa_name}' contains "
                    f"suspicious patterns: {', '.join(patterns[:5])}. "
                    "This may indicate credential harvesting, C2 communication, or data exfiltration."
                ),
                affected_id=aa_id,
                affected_name=f"{aa_name}/{rb_name}",
                attack_chain=[
                    {"step": 1, "action": f"Attacker gains write access to Automation Account '{aa_name}'"},
                    {"step": 2, "action": f"Modifies or creates runbook '{rb_name}' with malicious code"},
                    {"step": 3, "action": "Runbook executes as managed identity → exfiltrates credentials or escalates"},
                ],
                why_risky="Malicious runbooks execute with the automation account's managed identity privileges.",
                remediation=(
                    "Review runbook '{rb_name}' content immediately. "
                    "Enable change tracking on automation accounts. "
                    "Restrict runbook write access to break-glass identities only."
                ),
                tags=["automation", "runbook", "suspicious-code", "persistence"],
                risk_score=8.5,
                blast_radius=70,
            )

    # ------------------------------------------------------------------
    # Rule 18: Privileged Role Administrator → Global Administrator escalation
    # ------------------------------------------------------------------
    def rule_pra_to_global_admin(self) -> Generator[dict, None, None]:
        """Privileged Role Admin can activate/assign Global Admin to themselves."""
        pra_holders = [
            dr for dr in self.ctx.get("directory_roles", [])
            if dr.get("role_name") == "Privileged Role Administrator"
        ]
        global_admins = {
            dr["principal_id"] for dr in self.ctx.get("directory_roles", [])
            if dr.get("role_name") == "Global Administrator"
        }
        for dr in pra_holders:
            pid = dr["principal_id"]
            if pid in global_admins:
                continue  # Already Global Admin — covered by rule_privileged_entra_roles
            name = dr.get("principal_display_name") or self._get_principal_name(pid)
            yield _find_dict(
                finding_type="privilege_escalation",
                severity="critical",
                title=f"Privileged Role Admin can escalate to Global Admin: {name}",
                description=(
                    f"'{name}' holds Privileged Role Administrator in Entra ID. "
                    "This role allows assigning or activating any Entra directory role, "
                    "including Global Administrator."
                ),
                affected_id=pid,
                affected_name=name,
                attack_chain=[
                    {"step": 1, "action": f"'{name}' is Privileged Role Administrator"},
                    {"step": 2, "action": "Opens Azure Portal → Entra ID → Roles → Global Administrator"},
                    {"step": 3, "action": "Assigns Global Administrator to self or controlled identity"},
                    {"step": 4, "action": "Full tenant ownership — can read all data, manage all users/apps"},
                ],
                why_risky=(
                    "Privileged Role Admin is a Tier-0 identity. One step from Global Admin. "
                    "Often overlooked because it's not Global Admin itself."
                ),
                remediation=(
                    "Apply PIM (Privileged Identity Management) with approval workflow for this role. "
                    "Require MFA and justification for activation. Monitor all role assignment actions."
                ),
                tags=["entra-id", "privilege-escalation", "global-admin", "pra"],
                risk_score=9.5,
                blast_radius=100,
            )

    # ------------------------------------------------------------------
    # Rule 19: Storage / Key Vault without network isolation
    # ------------------------------------------------------------------
    def rule_no_network_isolation(self) -> Generator[dict, None, None]:
        """Storage accounts and Key Vaults open to all networks."""
        # Storage accounts
        for sa in self.ctx.get("storage_accounts", []):
            network_acls = sa.get("network_acls", {})
            default_action = network_acls.get("defaultAction", "Allow")
            allow_public = sa.get("allow_blob_public_access", False)

            if default_action == "Allow":
                severity = "high" if allow_public else "medium"
                name = sa.get("name", sa.get("id", ""))
                yield _find_dict(
                    finding_type="sensitive_resource_access",
                    severity=severity,
                    title=f"Storage account open to all networks: {name}",
                    description=(
                        f"Storage account '{name}' has no network ACL restrictions "
                        f"(defaultAction=Allow)"
                        + (", AND public blob access is enabled." if allow_public else ".")
                    ),
                    affected_id=sa.get("id", ""),
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": "Storage account reachable from any IP globally"},
                        {"step": 2, "action": "Attacker with storage keys or SAS token can access all data"},
                        {"step": 3, "action": "No network perimeter to prevent exfiltration"},
                    ],
                    why_risky=(
                        "Open network ACLs mean the only protection is credentials. "
                        "No IP/VNet restriction layer to stop credential-based exfiltration."
                    ),
                    remediation=(
                        "Set defaultAction=Deny and add explicit IP/VNet allowlists. "
                        "Consider private endpoints for production storage. "
                        "Disable public blob access unless explicitly required."
                    ),
                    tags=["storage", "network-exposure", "no-isolation"],
                    risk_score=6.5 if severity == "medium" else 7.5,
                    blast_radius=50,
                )

        # Key Vaults
        for kv in self.ctx.get("key_vaults", []):
            network_acls = kv.get("network_acls", {})
            default_action = network_acls.get("defaultAction", "Allow")
            public_access = kv.get("public_network_access", "Enabled")
            private_endpoints = kv.get("private_endpoint_connections", [])

            if default_action == "Allow" and public_access != "Disabled" and not private_endpoints:
                name = kv.get("name", kv.get("id", ""))
                yield _find_dict(
                    finding_type="sensitive_resource_access",
                    severity="high",
                    title=f"Key Vault open to all networks: {name}",
                    description=(
                        f"Key Vault '{name}' has no network ACL restrictions and no private endpoint. "
                        "Any authenticated identity (including compromised ones) can reach it from any IP."
                    ),
                    affected_id=kv.get("id", ""),
                    affected_name=name,
                    attack_chain=[
                        {"step": 1, "action": f"Attacker obtains credentials for identity with KV access"},
                        {"step": 2, "action": f"Makes requests to '{name}' vault from any location"},
                        {"step": 3, "action": "Extracts secrets, keys, or certificates with no network barrier"},
                    ],
                    why_risky=(
                        "Key Vaults store the most sensitive credentials. "
                        "Open network access maximises the window of exploitation from compromised identities."
                    ),
                    remediation=(
                        "Add network ACL with Deny default and specific IP/VNet allowlists. "
                        "Use private endpoints for production Key Vaults. "
                        "Enable diagnostic logging and alert on anomalous access patterns."
                    ),
                    tags=["key-vault", "network-exposure", "no-isolation"],
                    risk_score=7.5,
                    blast_radius=70,
                )

    # ------------------------------------------------------------------
    # Rule 20: No Azure Policy guarding privileged role assignment
    # ------------------------------------------------------------------
    def rule_no_deny_policy(self) -> Generator[dict, None, None]:
        """No Azure Policy preventing dangerous role assignments."""
        policy_assignments = self.ctx.get("policy_assignments", [])

        # Only flag if there are no policy assignments at all — informational
        if not policy_assignments:
            yield _find_dict(
                finding_type="excessive_privilege",
                severity="medium",
                title="No Azure Policy assignments configured",
                description=(
                    "The subscription has no Azure Policy assignments. "
                    "There is no guardrail preventing future assignment of Owner to arbitrary identities, "
                    "or enforcing tagging, resource types, or location restrictions."
                ),
                affected_id="subscription",
                affected_name="Subscription",
                attack_chain=[
                    {"step": 1, "action": "No policy prevents assigning Owner role subscription-wide"},
                    {"step": 2, "action": "Any identity with User Access Administrator can grant Owner freely"},
                    {"step": 3, "action": "No automated compliance check on resource configurations"},
                ],
                why_risky="Azure Policy is a defence-in-depth layer. Without it, misconfigurations go unchecked.",
                remediation=(
                    "Assign the built-in 'Not allowed resource types' or 'Require a tag' policies as a start. "
                    "Consider 'Allowed locations' and deny policies for Owner assignment at tenant root."
                ),
                tags=["azure-policy", "no-guardrails", "governance"],
                risk_score=5.0,
                blast_radius=40,
            )
            return

        # Check if any deny policy guards privileged role assignments
        deny_role_policies = [
            p for p in policy_assignments
            if p.get("is_deny") and any(
                kw in p.get("policy_definition_id", "").lower()
                for kw in ("roledefinition", "authorization", "owner")
            )
        ]
        if not deny_role_policies and len(policy_assignments) > 0:
            yield _find_dict(
                finding_type="excessive_privilege",
                severity="low",
                title="No deny policy guarding Owner/UAA role assignment",
                description=(
                    f"Found {len(policy_assignments)} Azure Policy assignment(s) but none "
                    "deny dangerous role assignments (Owner, User Access Administrator). "
                    "Policy exists but doesn't guard privileged RBAC."
                ),
                affected_id="subscription",
                affected_name="Subscription",
                attack_chain=[
                    {"step": 1, "action": "Policies exist but don't restrict Owner assignment"},
                    {"step": 2, "action": "Privileged role can be assigned without policy guardrail"},
                ],
                why_risky="Deny policies provide an immutable guardrail that cannot be bypassed even by admins.",
                remediation=(
                    "Assign the built-in policy 'Do not allow creation of Owner role assignment at subscription scope' "
                    "or create a custom deny policy."
                ),
                tags=["azure-policy", "governance", "rbac"],
                risk_score=4.0,
                blast_radius=30,
            )

    def run_all(self) -> list[dict]:
        """Run all rules and return deduplicated findings."""
        findings = []
        rules = [
            self.rule_contributor_plus_uaa,
            self.rule_subscription_owner,
            self.rule_privileged_sp_with_secrets,
            self.rule_function_app_privileged_identity,
            self.rule_kv_contributor_secret_access,
            self.rule_storage_key_access,
            self.rule_privileged_entra_roles,
            self.rule_shared_managed_identity,
            self.rule_automation_account_identity,
            self.rule_persistence_sp_credentials,
            self.rule_nested_group_escalation,
            self.rule_reader_plus_kv_secrets,
            self.rule_app_high_graph_permissions,
            self.rule_mi_lateral_movement,
            self.rule_internet_exposed_no_auth,
            self.rule_ca_policy_gaps,
            self.rule_suspicious_runbooks,
            self.rule_pra_to_global_admin,
            self.rule_no_network_isolation,
            self.rule_no_deny_policy,
        ]
        seen: set = set()
        for rule in rules:
            try:
                for f in rule():
                    key = (f["finding_type"], f.get("affected_node_id", ""), f["title"][:80])
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
            except Exception as e:
                logger.warning(f"Rule {rule.__name__} failed: {e}")
        return findings
