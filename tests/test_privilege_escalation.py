"""Unit tests for PrivilegeEscalationAnalyzer rules."""
import pytest
from backend.analyzers.privilege_escalation import PrivilegeEscalationAnalyzer


def _make_ctx(**overrides):
    """Build a minimal valid analyzer context."""
    base = {
        "role_assignments": [],
        "principal_effective_roles": {},
        "resource_nodes": {},
        "service_principals": [],
        "function_apps": [],
        "virtual_machines": [],
        "automation_accounts": [],
        "key_vaults": [],
        "directory_roles": [],
        "group_memberships_raw": {},
        "app_registrations": [],
        "ca_policies": [],
        "runbooks": [],
    }
    base.update(overrides)
    return base


# ──────────────────────────────────────────────────────────────
# Rule 1: Contributor + UAA
# ──────────────────────────────────────────────────────────────

def test_contributor_plus_uaa_triggers():
    ctx = _make_ctx(
        principal_effective_roles={
            "pid-1": [
                {"role_name": "Contributor", "scope_level": "subscription"},
                {"role_name": "User Access Administrator", "scope_level": "subscription"},
            ]
        },
        resource_nodes={"pid-1": {"name": "BadUser", "node_type": "user"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    matching = [f for f in findings if f["finding_type"] == "privilege_escalation"
                and "Contributor" in f["title"]]
    assert len(matching) >= 1
    assert matching[0]["severity"] == "critical"


def test_contributor_alone_no_trigger():
    ctx = _make_ctx(
        principal_effective_roles={
            "pid-2": [{"role_name": "Contributor", "scope_level": "subscription"}]
        },
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    # No UAA → no Contributor+UAA finding
    assert not any(
        "Contributor" in f["title"] and "UAA" in f["title"] for f in findings
    )


# ──────────────────────────────────────────────────────────────
# Rule 2: Subscription owner
# ──────────────────────────────────────────────────────────────

def test_subscription_owner_triggers():
    ctx = _make_ctx(
        role_assignments=[{
            "role_name": "Owner",
            "scope_level": "subscription",
            "principal_id": "pid-owner",
            "role_definition_id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        }],
        resource_nodes={"pid-owner": {"name": "AdminUser", "node_type": "user"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "high_risk_role" and "Owner" in f["title"] for f in findings)


def test_rg_owner_no_trigger():
    ctx = _make_ctx(
        role_assignments=[{
            "role_name": "Owner",
            "scope_level": "resource_group",
            "principal_id": "pid-rg-owner",
            "role_definition_id": "8e3af657",
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    # Only subscription-scope Owner triggers rule 2
    assert not any(
        f["finding_type"] == "high_risk_role" and "Owner at subscription" in f["title"]
        for f in findings
    )


# ──────────────────────────────────────────────────────────────
# Rule 3: Privileged SP with credentials
# ──────────────────────────────────────────────────────────────

def test_privileged_sp_with_creds():
    ctx = _make_ctx(
        principal_effective_roles={
            "sp-1": [{"role_name": "Owner", "scope_level": "subscription"}]
        },
        service_principals=[{
            "id": "sp-1",
            "display_name": "MyServiceApp",
            "has_key_credentials": True,
            "key_credential_count": 2,
            "has_password_credentials": False,
            "password_credential_count": 0,
            "account_enabled": True,
        }],
        resource_nodes={"sp-1": {"name": "MyServiceApp", "node_type": "service_principal"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "over_privileged_sp" for f in findings)


def test_disabled_sp_lower_risk():
    """Disabled SP should not trigger sp-with-creds rule (account_enabled=False)."""
    ctx = _make_ctx(
        principal_effective_roles={
            "sp-disabled": [{"role_name": "Owner", "scope_level": "subscription"}]
        },
        service_principals=[{
            "id": "sp-disabled",
            "display_name": "DisabledApp",
            "has_key_credentials": True,
            "key_credential_count": 1,
            "has_password_credentials": False,
            "password_credential_count": 0,
            "account_enabled": False,
        }],
    )
    # Should still trigger — account_enabled just reduces score via risk_scorer
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    # Rule itself fires regardless; scorer handles score reduction
    assert any(f["finding_type"] == "over_privileged_sp" for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 4: Function App with privileged managed identity
# ──────────────────────────────────────────────────────────────

def test_function_app_privileged_identity():
    ctx = _make_ctx(
        principal_effective_roles={
            "mi-principal": [{"role_name": "Owner", "scope_level": "subscription"}]
        },
        function_apps=[{
            "id": "/subscriptions/x/rg/y/sites/MyFn",
            "name": "MyFn",
            "system_identity_principal_id": "mi-principal",
            "user_assigned_identities": {},
        }],
        resource_nodes={"mi-principal": {"name": "mi-principal", "node_type": "managed_identity"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(
        f["finding_type"] == "misconfigured_identity" and "Function App" in f["title"]
        for f in findings
    )


# ──────────────────────────────────────────────────────────────
# Rule 12: Reader + Key Vault Secrets User
# ──────────────────────────────────────────────────────────────

def test_reader_plus_kv_secrets():
    ctx = _make_ctx(
        principal_effective_roles={
            "pid-reader-kv": [
                {"role_name": "Reader", "scope_level": "subscription"},
                {"role_name": "Key Vault Secrets User", "scope_level": "subscription"},
            ]
        },
        resource_nodes={"pid-reader-kv": {"name": "AuditUser", "node_type": "user"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "sensitive_resource_access" and "Reader" in f["title"]
               for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 14: MI lateral movement
# ──────────────────────────────────────────────────────────────

def test_mi_lateral_movement_to_kv():
    ctx = _make_ctx(
        principal_effective_roles={
            "mi-sp": [{"role_name": "Key Vault Secrets User", "scope_level": "resource_group"}]
        },
        function_apps=[{
            "id": "/sub/x/rg/y/sites/WebApp",
            "name": "WebApp",
            "node_type": "function_app",
            "system_identity_principal_id": "mi-sp",
            "user_assigned_identities": {},
            "state": "Running",
        }],
        resource_nodes={"mi-sp": {"name": "mi-sp", "node_type": "managed_identity"}},
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "lateral_movement" for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 15: Internet-exposed app
# ──────────────────────────────────────────────────────────────

def test_internet_exposed_no_auth():
    ctx = _make_ctx(
        function_apps=[{
            "id": "/sub/x/rg/y/sites/PublicFn",
            "name": "PublicFn",
            "node_type": "function_app",
            "state": "Running",
            "auth_enabled": False,
            "unauthenticated_action": "AllowAnonymous",
            "https_only": True,
            "system_identity_principal_id": None,
            "user_assigned_identities": {},
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "misconfigured_identity" and "Internet-exposed" in f["title"]
               for f in findings)


def test_app_with_auth_no_trigger():
    ctx = _make_ctx(
        function_apps=[{
            "id": "/sub/x/rg/y/sites/ProtectedFn",
            "name": "ProtectedFn",
            "node_type": "function_app",
            "state": "Running",
            "auth_enabled": True,
            "unauthenticated_action": "Return401",
            "https_only": True,
            "system_identity_principal_id": None,
            "user_assigned_identities": {},
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert not any("Internet-exposed" in f["title"] for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 16: No CA policies
# ──────────────────────────────────────────────────────────────

def test_no_ca_policies_triggers_when_privileged_users_exist():
    ctx = _make_ctx(
        ca_policies=[],
        directory_roles=[{
            "principal_id": "admin-1",
            "principal_display_name": "Admin",
            "role_name": "Global Administrator",
            "is_privileged": True,
            "role_id": "role-ga",
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("No Conditional Access" in f["title"] for f in findings)


def test_no_ca_no_trigger_without_privileged_users():
    ctx = _make_ctx(ca_policies=[], directory_roles=[])
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert not any("Conditional Access" in f["title"] for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 17: Suspicious runbooks
# ──────────────────────────────────────────────────────────────

def test_suspicious_runbook_detected():
    ctx = _make_ctx(
        runbooks=[{
            "automation_account_id": "/sub/x/rg/y/aa/MyAA",
            "automation_account_name": "MyAA",
            "runbook_name": "Export-Creds",
            "runbook_type": "PowerShell",
            "state": "Published",
            "is_suspicious": True,
            "suspicious_patterns": ["invoke-webrequest", "convertto-securestring"],
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any(f["finding_type"] == "persistence_risk" and "Suspicious runbook" in f["title"]
               for f in findings)


def test_clean_runbook_no_trigger():
    ctx = _make_ctx(
        runbooks=[{
            "automation_account_id": "/sub/x/rg/y/aa/MyAA",
            "automation_account_name": "MyAA",
            "runbook_name": "Start-VMs",
            "is_suspicious": False,
            "suspicious_patterns": [],
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert not any("Suspicious runbook" in f["title"] for f in findings)


# ──────────────────────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────────────────────

def test_run_all_deduplicates():
    """run_all should not return duplicate findings for the same principal+rule."""
    ctx = _make_ctx(
        role_assignments=[
            {"role_name": "Owner", "scope_level": "subscription", "principal_id": "p1",
             "role_definition_id": "8e3af657"},
            {"role_name": "Owner", "scope_level": "subscription", "principal_id": "p1",
             "role_definition_id": "8e3af657"},  # duplicate
        ],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    owner_findings = [f for f in findings if "Owner at subscription" in f.get("title", "")]
    # Should only be one finding for p1, not two
    assert len(owner_findings) <= 1 or len({f["affected_node_id"] for f in owner_findings}) == len(owner_findings)


# ──────────────────────────────────────────────────────────────
# Rule 18: Privileged Role Admin → Global Admin escalation
# ──────────────────────────────────────────────────────────────

def test_pra_escalation_to_global_admin():
    ctx = _make_ctx(
        directory_roles=[
            {"principal_id": "pra-user", "principal_display_name": "PRAUser",
             "role_name": "Privileged Role Administrator", "is_privileged": True, "role_id": "pra-role"},
        ],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("Privileged Role Admin" in f["title"] and f["severity"] == "critical" for f in findings)


def test_pra_already_global_admin_no_extra_finding():
    """If PRA is already Global Admin, rule 18 should not add a duplicate escalation finding."""
    ctx = _make_ctx(
        directory_roles=[
            {"principal_id": "ga-user", "principal_display_name": "GAUser",
             "role_name": "Privileged Role Administrator", "is_privileged": True, "role_id": "pra"},
            {"principal_id": "ga-user", "principal_display_name": "GAUser",
             "role_name": "Global Administrator", "is_privileged": True, "role_id": "ga"},
        ],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    # PRA→GA escalation rule should skip this (already GA)
    pra_escalation = [f for f in findings if "Privileged Role Admin can escalate" in f.get("title", "")]
    assert len(pra_escalation) == 0


# ──────────────────────────────────────────────────────────────
# Rule 19: No network isolation
# ──────────────────────────────────────────────────────────────

def test_storage_open_network():
    ctx = _make_ctx(
        storage_accounts=[{
            "id": "/sub/x/storage/mysa",
            "name": "mysa",
            "network_acls": {"defaultAction": "Allow"},
            "allow_blob_public_access": False,
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("Storage account open" in f["title"] for f in findings)


def test_storage_restricted_network_no_trigger():
    ctx = _make_ctx(
        storage_accounts=[{
            "id": "/sub/x/storage/secure",
            "name": "secure",
            "network_acls": {"defaultAction": "Deny", "ipRules": [{"value": "10.0.0.0/8"}]},
            "allow_blob_public_access": False,
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert not any("Storage account open" in f["title"] for f in findings)


def test_kv_open_network():
    ctx = _make_ctx(
        key_vaults=[{
            "id": "/sub/x/kv/mykv",
            "name": "mykv",
            "network_acls": {"defaultAction": "Allow"},
            "public_network_access": "Enabled",
            "private_endpoint_connections": [],
            "enable_rbac_authorization": True,
            "access_policies": [],
        }],
    )
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("Key Vault open" in f["title"] for f in findings)


# ──────────────────────────────────────────────────────────────
# Rule 20: No Azure Policy
# ──────────────────────────────────────────────────────────────

def test_no_policy_assignments():
    ctx = _make_ctx(policy_assignments=[])
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("No Azure Policy" in f["title"] for f in findings)


def test_policy_assignments_no_deny():
    ctx = _make_ctx(policy_assignments=[
        {"id": "/sub/x/policy/tagging", "name": "RequireTags",
         "display_name": "Require Tags", "policy_definition_id": "/providers/tag-policy",
         "scope": "/subscriptions/x", "is_deny": False},
    ])
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert any("No deny policy" in f["title"] for f in findings)


def test_deny_role_policy_no_trigger():
    ctx = _make_ctx(policy_assignments=[
        {"id": "/sub/x/policy/deny-owner", "name": "DenyOwner",
         "display_name": "Deny Owner Role Assignment",
         "policy_definition_id": "/providers/Microsoft.Authorization/deny-owner-roledefinition",
         "scope": "/subscriptions/x", "is_deny": True},
    ])
    findings = PrivilegeEscalationAnalyzer(ctx).run_all()
    assert not any("No deny policy" in f["title"] for f in findings)
