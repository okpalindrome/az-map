# az-map Documentation

**az-map** is a lightweight, self-contained Azure security analysis tool.
It scans an Azure subscription via `az login` credentials and produces an interactive
graph of every identity, resource, and privilege relationship — then runs 20 detection
rules to find escalation paths, excessive permissions, and misconfigurations.

---

## Table of Contents

| Document | Description |
|---|---|
| [Setup Guide](setup.md) | Prerequisites, installation (Windows + Linux), Azure permissions, configuration, troubleshooting |
| [Features](features.md) | Graph view, Table view, Dashboard, Attack Path panel, Diff mode, Export, Tenant config |
| [Detection Rules](rules.md) | All 20 rules with attack chains, risk scores, and remediation guidance |
| [Attack Path Analysis](attack-paths.md) | How path modeling works, path types, interpreting results, limitations |
| [Architecture](architecture.md) | Tech stack, module map, data flow, database schema |
| [Security Design](security.md) | Read-only guarantee, auth, input validation, rate limiting, threat model |
| [REST API](api.md) | All endpoints with parameters, request/response examples |

---

## Quick Start

```bash
# 1. Install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Log in to Azure
az login

# 3. Run
python run.py
# → open http://localhost:8000

# 4. Paste your subscription ID and click Scan
```

---

## What gets scanned

| Source | Data collected |
|---|---|
| Azure ARM | Subscriptions, resource groups, storage accounts, Key Vaults, Function Apps, VMs, Automation Accounts, managed identities, Azure Policy assignments |
| Azure RBAC | All role definitions, all role assignments (subscription + resource group + resource scope) |
| Microsoft Graph | Users, groups, group memberships (transitive), service principals, app registrations, Entra directory roles, Conditional Access policies |

All data collection is **read-only** — az-map uses only HTTP GET requests.

---

## 20 Detection Rules (summary)

| Severity | Rules |
|---|---|
| Critical | Owner at subscription · Contributor+UAA escalation · Function App with privileged MI · PRA→Global Admin · No CA policies |
| High | Privileged SP with credentials · KV access policy · Storage key operator · Privileged Entra roles · Automation with privileged identity · Nested groups · Reader+KV secrets · Dangerous Graph permissions · MI lateral movement · Suspicious runbook · Internet-exposed app · KV/Storage no network isolation |
| Medium | Shared MI · SP with many credentials · No Azure Policy |
| Low | Policy exists but no deny for Owner |

See [rules.md](rules.md) for full descriptions, attack chains, and remediation.
