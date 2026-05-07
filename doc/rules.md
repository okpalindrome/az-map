# Detection Rules

az-map runs 20 detection rules after each scan. Rules are implemented in
`backend/analyzers/privilege_escalation.py` and can be extended without changing
any other code.

Each finding includes:
- **Severity** (Critical / High / Medium / Low)
- **Risk score** (0–10)
- **Blast radius** (0–100, relative impact)
- **Why risky** — plain-language explanation
- **Attack chain** — numbered steps
- **Remediation** — concrete action

---

## Rule Index

| # | Rule Name | Severity | Risk Score |
|---|---|---|---|
| 1 | [Contributor + User Access Administrator](#1-contributor--user-access-administrator) | Critical | 9.5 |
| 2 | [Owner at subscription scope](#2-owner-at-subscription-scope) | Critical | 9.0 |
| 3 | [Privileged SP with credentials](#3-privileged-sp-with-credentials) | High | 8.5 |
| 4 | [Function App with high-privilege managed identity](#4-function-app-with-high-privilege-managed-identity) | Critical | 9.0 |
| 5 | [Key Vault legacy access policy grants secret read](#5-key-vault-legacy-access-policy-grants-secret-read) | High | 7.5 |
| 6 | [Storage Account Contributor → key extraction](#6-storage-account-contributor--key-extraction) | High | 7.0 |
| 7 | [Privileged Entra directory role](#7-privileged-entra-directory-role) | Critical/High | 7.5–9.0 |
| 8 | [Shared user-assigned managed identity](#8-shared-user-assigned-managed-identity) | Medium | 5.5 |
| 9 | [Automation Account with privileged identity](#9-automation-account-with-privileged-identity) | High | 8.0 |
| 10 | [Service Principal with many credentials](#10-service-principal-with-many-credentials) | Medium | 6.0 |
| 11 | [Nested group privilege accumulation](#11-nested-group-privilege-accumulation) | High | 7.0 |
| 12 | [Reader + Key Vault Secrets User](#12-reader--key-vault-secrets-user) | High | 8.0 |
| 13 | [App registration with dangerous Graph permissions](#13-app-registration-with-dangerous-graph-permissions) | High | 8.0 |
| 14 | [Managed Identity lateral movement](#14-managed-identity-lateral-movement) | High | 7.5 |
| 15 | [Internet-exposed app without authentication](#15-internet-exposed-app-without-authentication) | High/Medium | 5.0–7.0 |
| 16 | [No Conditional Access policies](#16-no-conditional-access-policies) | Critical/High | 7.5–9.5 |
| 17 | [Suspicious automation runbook](#17-suspicious-automation-runbook) | High | 8.5 |
| 18 | [Privileged Role Admin → Global Admin escalation](#18-privileged-role-admin--global-admin-escalation) | Critical | 9.5 |
| 19 | [Storage / Key Vault without network isolation](#19-storage--key-vault-without-network-isolation) | High/Medium | 6.5–7.5 |
| 20 | [No Azure Policy guarding role assignment](#20-no-azure-policy-guarding-role-assignment) | Medium/Low | 4.0–5.0 |

---

## Rule Details

### 1. Contributor + User Access Administrator

**Severity:** Critical | **Risk Score:** 9.5 | **Blast Radius:** 100

**What it detects:** An identity that holds both `Contributor` (full resource write access) and `User Access Administrator` (can assign any RBAC role). This combination is functionally equivalent to Owner.

**Attack chain:**
1. Identity already has Contributor — full resource read/write/delete
2. Uses User Access Administrator to assign Owner role to itself
3. Now has explicit Owner with no additional API calls

**Why it's dangerous:** Neither role alone is Owner, but the combination bypasses the Owner-assignment guardrail. Often missed in RBAC reviews that focus on direct Owner assignments.

**Remediation:** Remove User Access Administrator from this identity. If role assignment is needed, scope it to a specific resource group only.

---

### 2. Owner at subscription scope

**Severity:** Critical | **Risk Score:** 9.0 | **Blast Radius:** 100

**What it detects:** Any identity with the `Owner` role assigned at the subscription level (not scoped to a resource group or resource).

**Attack chain:**
1. Identity has Owner at subscription scope
2. Can read/write/delete any resource in the subscription
3. Can assign any RBAC role to any identity, including Owner to new identities
4. Can modify RBAC policies, network rules, security settings

**Remediation:** Replace with least-privilege roles scoped to the specific resource groups that need access. Use PIM (Privileged Identity Management) for Owner. Require approval and time-bound activation.

---

### 3. Privileged SP with credentials

**Severity:** High | **Risk Score:** 8.5 | **Blast Radius:** 80

**What it detects:** A service principal with `Owner`, `Contributor`, or `User Access Administrator` that also has active key credentials or password credentials.

**Why it's dangerous:** Long-lived SP credentials (especially password/client secrets) are a primary attack surface. If the credential leaks (from code, CI/CD, environment variables), an attacker immediately has high-privilege Azure access.

**Attack chain:**
1. Attacker finds credential in source code, CI logs, or environment variable
2. Authenticates as the SP (`az login --service-principal`)
3. Has Owner/Contributor — full subscription access

**Remediation:** Rotate or remove credentials. Switch to certificate auth with short expiry. Replace with managed identity where possible. Apply PIM for SP activations.

---

### 4. Function App with high-privilege managed identity

**Severity:** Critical | **Risk Score:** 9.0 | **Blast Radius:** 90

**What it detects:** A Function App or App Service with a system-assigned managed identity that has `Owner`, `Contributor`, or `User Access Administrator` on the subscription or a broad scope.

**Why it's dangerous:** Any code execution vulnerability in the app (SSRF, code injection, dependency confusion) immediately yields the managed identity token via IMDS (`169.254.169.254`). The attacker never needs credentials.

**Attack chain:**
1. Attacker exploits code execution in the Function App (SSRF, injection, etc.)
2. Makes a request to `http://169.254.169.254/metadata/identity/oauth2/token`
3. Gets a Bearer token with the managed identity's permissions
4. Uses the token to call Azure ARM API with Owner/Contributor privileges

**Remediation:** Apply least privilege — scope the managed identity to only the specific resources it needs (specific storage container, specific Key Vault secret). Never assign subscription-level Owner to a compute identity.

---

### 5. Key Vault legacy access policy grants secret read

**Severity:** High | **Risk Score:** 7.5 | **Blast Radius:** 70

**What it detects:** Key Vaults using legacy access policies (not RBAC) where any identity has `Get` or `List` permission on secrets.

**Why it's dangerous:** Legacy access policies are broader than RBAC — they grant access at the vault level, not per-secret. Any compromise of the listed identity means all secrets in the vault are exposed.

**Attack chain:**
1. Identity listed in access policy authenticates to Key Vault
2. Access policy allows GET/LIST on secrets
3. All secrets extracted with a single loop

**Remediation:** Migrate to RBAC authorization (`enableRbacAuthorization=true`). Use `Key Vault Secrets User` role for read-only access to specific secrets. Enable Key Vault diagnostic logging.

---

### 6. Storage Account Contributor → key extraction

**Severity:** High | **Risk Score:** 7.0 | **Blast Radius:** 60

**What it detects:** Identities with `Storage Account Contributor` or `Storage Account Key Operator Service Role`, which allow listing storage account keys.

**Why it's dangerous:** Storage account keys provide permanent, unrestricted data-plane access — they bypass all RBAC controls. An attacker with a storage key can read/write/delete all blobs, tables, queues, and file shares.

**Attack chain:**
1. Identity calls `az storage account keys list`
2. Gets two 512-bit master keys with full data-plane access
3. Uses key to generate SAS tokens with any permissions, any expiry

**Remediation:** Replace Storage Account Contributor with `Storage Blob Data Contributor` (data-plane only, no key access). Disable shared key access with `allowSharedKeyAccess=false`. Enforce Azure AD authentication only.

---

### 7. Privileged Entra directory role

**Severity:** Critical (Global Admin) / High (others) | **Risk Score:** 7.5–9.0

**What it detects:** Identities assigned to any of these Entra ID directory roles:
Global Administrator, Privileged Role Administrator, Application Administrator,
Cloud Application Administrator, Authentication Administrator,
Privileged Authentication Administrator, User Administrator,
Exchange Administrator, SharePoint Administrator, Hybrid Identity Administrator,
Security Administrator, Intune Administrator, Conditional Access Administrator,
Password Administrator, Helpdesk Administrator.

**Why it's dangerous:** Entra directory roles operate at the tenant level, above any Azure subscription RBAC. A compromised Global Admin can read all data, reset any password, and modify any app in the entire Microsoft 365 / Entra tenant.

**Remediation:** Apply PIM for all privileged directory roles. Require MFA + approval for activation. Use separate break-glass accounts. Monitor sign-ins for privileged role holders. Reduce the number of permanent (non-PIM) role assignments to zero where possible.

---

### 8. Shared user-assigned managed identity

**Severity:** Medium | **Risk Score:** 5.5

**What it detects:** A user-assigned managed identity attached to more than 2 resources (Function Apps, VMs, etc.).

**Why it's dangerous:** Each resource sharing the identity is a potential entry point. Compromising any one resource gives the attacker the identity token, which can then be used from any of the other resources as well.

**Remediation:** Use separate managed identities per resource. Apply the principle of identity isolation — one identity per workload.

---

### 9. Automation Account with privileged identity

**Severity:** High | **Risk Score:** 8.0 | **Blast Radius:** 75

**What it detects:** An Automation Account whose system-assigned managed identity has `Owner`, `Contributor`, or `User Access Administrator`.

**Why it's dangerous:** Anyone with `Automation Contributor` access to the account can write a runbook that executes as the managed identity. The runbook can call Azure APIs with full privilege without ever leaving the tenant.

**Attack chain:**
1. Attacker gains `Automation Contributor` on the account
2. Writes a runbook that calls `Connect-AzAccount -Identity` then enumerates/modifies resources
3. Executes the runbook — runs as the privileged managed identity

**Remediation:** Apply least privilege to the automation identity. Restrict runbook write access. Enable change tracking and alerting on runbook modifications.

---

### 10. Service Principal with many credentials

**Severity:** Medium | **Risk Score:** 6.0

**What it detects:** A service principal with more than 3 active credentials (key or password).

**Why it's dangerous:** An attacker with write access to an SP can add a new credential for persistent access. Even after a password reset or key rotation, the attacker's added credential remains valid. Multiple credentials on one SP can indicate this pattern.

**Remediation:** Audit all credentials. Remove unused ones. Monitor for unexpected credential additions via Azure Activity Logs. Consider certificate credentials with short expiry instead of passwords.

---

### 11. Nested group privilege accumulation

**Severity:** High | **Risk Score:** 7.0 | **Blast Radius:** 60

**What it detects:** Security groups with dangerous RBAC roles that also contain nested sub-groups. Members of the nested groups inherit the privileged role transitively.

**Why it's dangerous:** Nested group membership silently widens the blast radius. A user added to an inner group may not realise they now have subscription-level Owner via a parent group's RBAC assignment.

**Remediation:** Flatten security groups used for RBAC assignments. Audit transitive membership regularly using `az ad group member list --query ...`. Use flat, named groups for each RBAC scope.

---

### 12. Reader + Key Vault Secrets User

**Severity:** High | **Risk Score:** 8.0 | **Blast Radius:** 85

**What it detects:** An identity with both `Reader` (subscription-wide enumeration) and `Key Vault Secrets User` (can read secrets from any vault).

**Why it's dangerous:** Reader lets the identity discover all Key Vaults in the subscription. Key Vault Secrets User lets it read secrets from each. Combined, this is a silent full-credential-exfiltration path — no alerts, no writes.

**Attack chain:**
1. Identity uses Reader to `az keyvault list --subscription ...`
2. For each vault, calls `az keyvault secret list` then `az keyvault secret show`
3. Extracts all connection strings, API keys, certificates — with no suspicious activity

**Remediation:** Scope `Key Vault Secrets User` to specific vaults, not subscription. Use separate identities for enumeration and secret access. Enable Key Vault diagnostic logging and alert on bulk GET operations.

---

### 13. App registration with dangerous Graph permissions

**Severity:** High | **Risk Score:** 8.0 | **Blast Radius:** 90

**What it detects:** App registrations that have requested high-privilege Microsoft Graph **application permissions** (not delegated). Specifically: `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.ReadWrite.All`.

**Why it's dangerous:** Application permissions operate tenant-wide with no user context required. An app with `RoleManagement.ReadWrite.Directory` can assign Global Administrator to any identity. These permissions are active 24/7, not just when a user is logged in.

**Remediation:** Replace application permissions with delegated permissions where possible. Implement admin consent workflow. Audit all consented app permissions quarterly. Remove or scope permissions to the minimum required.

---

### 14. Managed Identity lateral movement

**Severity:** High | **Risk Score:** 7.5 | **Blast Radius:** 65

**What it detects:** Resources (Function Apps, VMs) with managed identities that have `Key Vault Secrets User`, `Key Vault Administrator`, `Storage Blob Data Contributor`, `Storage Account Contributor`, or similar data-access roles.

**Why it's dangerous:** Compromising the resource (code execution, misconfiguration) gives the attacker the managed identity token, which can then pivot to read all secrets or blob data.

**Remediation:** Scope managed identity roles to the specific vault/container the resource needs. Avoid subscription-scope data roles on compute identities.

---

### 15. Internet-exposed app without authentication

**Severity:** High (with MI) / Medium (without) | **Risk Score:** 5.0–7.0

**What it detects:** Function Apps or App Services that:
- Have Easy Auth disabled (`platform.enabled = false`)
- Allow anonymous access (`globalValidation.unauthenticatedClientAction = AllowAnonymous`)
- Or allow HTTP traffic (`httpsOnly = false`)

Severity is elevated to High if the app also has a managed identity.

**Remediation:** Enable Easy Auth (Azure AD authentication). Set `httpsOnly = true`. If public access is not needed, restrict via private endpoint or IP allowlist.

---

### 16. No Conditional Access policies

**Severity:** Critical (no policies) / High (policies without MFA) | **Risk Score:** 7.5–9.5

**What it detects (Critical):** The tenant has zero Conditional Access policies configured. All users authenticate with no MFA, location, or device compliance enforcement.

**What it detects (High):** CA policies exist but none enforce MFA as a grant control.

**Why it's dangerous:** Without MFA, a stolen password grants immediate unrestricted account access. This is the root cause of the majority of credential-based breaches.

**Remediation (Critical):** Create baseline CA policies immediately:
- Require MFA for all users
- Block legacy authentication protocols
- Require compliant devices for admin roles

**Remediation (High):** Add MFA grant requirement to existing CA policies.

---

### 17. Suspicious automation runbook

**Severity:** High | **Risk Score:** 8.5 | **Blast Radius:** 70

**What it detects:** Automation Account runbooks whose code contains patterns associated with credential harvesting, C2 communication, or data exfiltration:
`Invoke-WebRequest`, `Invoke-RestMethod`, `DownloadString`, `DownloadFile`,
`Net.WebClient`, `ConvertTo-SecureString`, `Get-Credential`, `SecretValue`,
`-EncodedCommand`, `Invoke-Expression`, `iex(`, `curl`, `wget`, `base64`.

**Why it's dangerous:** Automation runbooks execute with the account's managed identity privileges. Malicious code inserted into a runbook runs silently on a schedule with full Azure API access.

**Remediation:** Review the flagged runbook content immediately. Enable change tracking and alerting on runbook modifications. Restrict runbook write access to break-glass identities. Enable Automation Account diagnostic logging.

---

### 18. Privileged Role Admin → Global Admin escalation

**Severity:** Critical | **Risk Score:** 9.5 | **Blast Radius:** 100

**What it detects:** Identities with the `Privileged Role Administrator` Entra directory role who are not already Global Administrators.

**Why it's dangerous:** Privileged Role Admin can activate, assign, and manage any Entra directory role — including Global Administrator. This is a one-step escalation to full tenant ownership that is often overlooked because the identity is "not a Global Admin."

**Attack chain:**
1. Identity is Privileged Role Administrator
2. Opens Azure Portal → Entra ID → Roles and Administrators → Global Administrator
3. Assigns Global Administrator to itself or a controlled identity
4. Full tenant ownership — can read all data, manage all users, apps, and settings

**Remediation:** Apply PIM with approval workflow and MFA for Privileged Role Administrator activation. Monitor all role assignment actions. Restrict this role to break-glass accounts.

---

### 19. Storage / Key Vault without network isolation

**Severity:** High (KV / public storage) / Medium (private storage) | **Risk Score:** 6.5–7.5

**What it detects:**
- **Storage accounts** with `networkAcls.defaultAction = Allow` (accepts traffic from all IPs)
- **Key Vaults** with `networkAcls.defaultAction = Allow` and no private endpoint connections

**Why it's dangerous:** Open network access means the only protection is credential security. No IP/VNet restriction layer limits exposure from compromised credentials.

**Remediation:**
- Set `defaultAction = Deny` with explicit IP/VNet allowlists
- Use private endpoints for production storage and Key Vaults
- Disable public network access where not needed (`publicNetworkAccess = Disabled`)

---

### 20. No Azure Policy guarding role assignment

**Severity:** Medium (no policies) / Low (policies without deny) | **Risk Score:** 4.0–5.0

**What it detects:**
- **Medium:** The subscription has no Azure Policy assignments at all
- **Low:** Policy assignments exist but none deny dangerous role assignments (Owner, UAA)

**Why it's dangerous:** Azure Policy provides immutable guardrails that operate below IAM. Without deny policies, any identity with User Access Administrator can freely assign Owner to arbitrary identities, even if you have monitoring in place.

**Remediation:** Assign the built-in policy *"Do not allow creation of Owner role assignment at subscription scope"* or create a custom deny effect policy. Consider deploying the Azure Security Benchmark policy initiative.

---

## Adding New Rules

1. Open `backend/analyzers/privilege_escalation.py`
2. Add a generator method: `def rule_<name>(self) -> Generator[dict, None, None]`
3. Yield `_find_dict(...)` calls for each finding
4. Add the method to the `rules` list in `run_all()`
5. If the rule needs new context data (e.g. a new resource type), add the key to the `context` dict in `backend/analyzers/runner.py`
6. Add a unit test in `tests/test_privilege_escalation.py`
