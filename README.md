> ⚠️ Experimental — use in non-production environments only.

# az-map — Azure Security Analysis Tool

A lightweight, self-contained Azure privilege mapping and attack-path analysis tool. Inspired by BloodHound/AzureHound, but built from scratch without any BloodHound dependencies — works safely through corporate proxies and endpoint security tools (Zscaler, Defender, etc.).

---

## What it does

az-map scans an Azure subscription via Azure CLI credentials and produces an interactive graph of every identity, resource, and privilege relationship. It runs 20 security detection rules to find:

- Privilege escalation paths (Owner escalation, Privileged Role Admin → Global Admin)
- Excessive permissions (Contributor + UAA combos, subscription-wide Owner)
- Managed identity lateral movement (MI on compute → Key Vault / Storage)
- Misconfigured identities (internet-exposed apps with no auth, shared MIs)
- Sensitive resource exposure (KV without network ACLs, storage with public access)
- Entra ID risks (no CA policies, Global Admin accounts, suspicious Automation runbooks)
- Persistence indicators (SPs with many credentials, suspicious runbook code)

Results are visualised in an Obsidian-style force-directed graph with a clean white theme.

---

## Architecture

```
az-map/
├── run.py                   ← single entry point: python run.py
├── requirements.txt         ← runtime dependencies
├── requirements-dev.txt     ← dev/test dependencies (pytest)
├── backend/
│   ├── collectors/          ← Azure ARM + Microsoft Graph API data collection
│   ├── analyzers/           ← 20 detection rules + diff engine + attack-path finder
│   ├── graph/               ← NetworkX graph builder + Cytoscape.js serialiser
│   └── api/                 ← FastAPI REST API (scan, graph, findings, export, tenant)
├── frontend/
│   ├── index.html           ← single-page app (no build step)
│   └── js/                  ← Vanilla JS: graph.js, table.js, dashboard.js, app.js
└── tests/                   ← 79 pytest tests (unit + integration + API)
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend runtime** | Python 3.11 | Server + collectors |
| **Web framework** | FastAPI + uvicorn | REST API, SSE scan streaming |
| **Database** | SQLite (`~/.az-map/azmap.db`) | Persistent scan storage — no server required |
| **ORM** | SQLAlchemy | DB models: Scan, Node, Edge, Finding |
| **Graph engine** | NetworkX (DiGraph) | In-memory attack path analysis |
| **Azure auth** | azure-identity `AzureCliCredential` | Reads token from active `az login` session |
| **Azure APIs** | azure-mgmt-* (subscription, authorization, resource, storage, keyvault, web, compute, msi) | ARM control-plane data collection |
| **MS Graph** | raw httpx (no msgraph-sdk) | Users, groups, SPs, CA policies, Entra roles |
| **Frontend** | Vanilla JS (no framework, no build step) | Zero-dependency SPA |
| **Graph visualisation** | Cytoscape.js (vendored, no CDN needed) | Force-directed interactive graph |
| **Theme** | Obsidian-inspired white | Clean, high-contrast |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | 3.10 may work but is untested |
| Azure CLI | Latest | `az login` must succeed before scanning |
| OS | Windows 10/11, macOS, Linux | See platform notes below |

**Azure permissions needed for the scanning identity:**

| Scope | Permission |
|---|---|
| Subscription | `Reader` |
| Subscription | `Microsoft.Authorization/roleAssignments/read` |
| Microsoft Graph | `User.Read.All`, `Group.Read.All`, `Application.Read.All` |
| Microsoft Graph | `RoleManagement.Read.Directory` (for Entra roles) |
| Microsoft Graph | `Policy.Read.All` (for Conditional Access policies) |

> The scan account needs read-only access. No write permissions required.

---

## Installation

### Windows

```powershell
# 1. Clone
git clone https://github.com/your-org/az-map.git
cd az-map

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install runtime dependencies
pip install -r requirements.txt

# 4. Log in to Azure
az login
```

### macOS / Linux

```bash
# 1. Clone
git clone https://github.com/your-org/az-map.git
cd az-map

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install runtime dependencies
pip install -r requirements.txt

# 4. Log in to Azure
az login
# For a specific tenant:
az login --tenant <tenant-id>
```

---

## Quick Start

```bash
# Start the server (works on Windows, macOS, Linux)
python run.py
# → Server running at http://localhost:8000
```

1. Open **http://localhost:8000** in your browser
2. Select your **Subscription** from the dropdown (auto-populated from `az login` session), or paste the Subscription ID
3. Click **Scan** — real-time progress streams to the UI
4. Explore the interactive graph, attack paths, findings table, and dashboard

---

## Features

### Graph View
- Force-directed layout (Cytoscape.js / cose algorithm), vendored — works offline
- Nodes coloured and shaped by type (user, group, SP, MI, KV, storage, VM, etc.)
- Red/orange/gold borders: critical risk / risky / owned nodes
- Click any node → detail panel with risk score, relationships, and attack paths from that node
- **Owned nodes**: mark any identity or resource as "Owned/Pwned" from the detail panel; shown with gold border in graph and listed in the sidebar
- Filter sidebar: by resource type, risk level, or free-text search; sidebar is fully scrollable

### Attack Path Panel
- Click **⚡ Paths** in the toolbar
- Enter a from/to node name or ID, or click **→ Global Admin** for all escalation paths
- Click **♦ From Owned Nodes** to find all paths from nodes you've marked as owned
- Click any result to highlight the path in the graph and open a step-by-step relationship chain (node → edge type → node → …)
- Clicking the target resource opens its full detail in the right panel

### Table View
- **Findings** tab: all security findings with severity, risk score, type, affected resource; click type tag → inline attack chain + remediation; click resource → graph navigation
- **Inventory** tab: full resource list with risk scores and reasons, paginated
- **Roles** tab: role definitions with privilege levels and total role assignments

### Dashboard View
- Shows: subscription name, tenant ID, scan date/time, snapshot label
- Severity donut chart (plain SVG — no extra libraries)
- Findings by type and resources by type bar charts
- Top risk findings (clickable → graph navigation)

### Diff / Compare
- Click **⇄ Diff** to compare two scans of the same subscription
- Shows: new resources, removed resources, risk-changed identities, new/resolved findings
- Diff overlay highlights changes directly on the graph (green = new, orange = risk increased)

### Import / Export
| Action | Description |
|---|---|
| **Export JSON** | Full structured export: all nodes, edges, findings, role assignments (filename: `{subscription-name}.json`) |
| **Export CSV** | Three-section file: Findings / Inventory / Role Assignments — all fields including subscription name |
| **Import JSON** | Re-import a previously exported JSON file; appears in scan history and diff selector |

### Owned Nodes
- The currently logged-in `az` user is automatically detected and marked as **Owned** when a scan loads
- Click **Mark as Owned** in any node's detail panel to flag it as compromised
- The **♦ Owned** sidebar section lists all owned nodes — click to jump to that node's detail
- Use **♦ From Owned Nodes** in the Attack Path panel to find all reachable targets

### Snapshot Labels
- Click the **✎** button on any scan in the sidebar to add a human-readable label (e.g. `baseline-2026-Q1`)
- Labels appear in the diff selector and JSON export filename

### Multi-Tenant Config
- Click **+** in the Tenants section to save subscription groups for quick switching
- Edit/delete saved tenant configurations

---

## Detection Rules (20 total)

| # | Rule | Severity |
|---|---|---|
| 1 | Contributor + User Access Administrator → Owner escalation | Critical |
| 2 | Owner assigned at subscription scope | Critical |
| 3 | Privileged service principal with active credentials | High |
| 4 | Function App with high-privilege managed identity | Critical |
| 5 | Key Vault legacy access policy grants secret read | High |
| 6 | Storage Account Contributor → key extraction path | High |
| 7 | Privileged Entra directory role (Global Admin, etc.) | Critical/High |
| 8 | User-assigned MI shared across multiple resources | Medium |
| 9 | Automation Account with high-privilege managed identity | High |
| 10 | Service Principal with many credentials (persistence) | Medium |
| 11 | Nested group privilege accumulation | High |
| 12 | Reader + Key Vault Secrets User → silent data exfiltration | High |
| 13 | App registration with dangerous Graph API permissions | High |
| 14 | Managed Identity lateral movement to KV/Storage | High |
| 15 | Internet-exposed app without authentication | High/Medium |
| 16 | No Conditional Access policies (or CA without MFA) | Critical/High |
| 17 | Automation runbook with suspicious code patterns | High |
| 18 | Privileged Role Administrator → Global Admin escalation | Critical |
| 19 | Storage Account / Key Vault without network isolation | High/Medium |
| 20 | No Azure Policy guarding privileged role assignment | Medium/Low |

---

## Configuration

az-map uses environment variables with the `AZMAP_` prefix.

**Windows (PowerShell):**
```powershell
$env:AZMAP_DB_PATH      = "$HOME\.az-map\azmap.db"
$env:AZMAP_API_TIMEOUT  = "30"
$env:AZMAP_MAX_CONCURRENCY = "10"
```

**Windows (cmd.exe):**
```cmd
set AZMAP_DB_PATH=%USERPROFILE%\.az-map\azmap.db
set AZMAP_API_TIMEOUT=30
```

**macOS / Linux:**
```bash
export AZMAP_DB_PATH="$HOME/.az-map/azmap.db"
export AZMAP_API_TIMEOUT=30
export AZMAP_MAX_CONCURRENCY=10
```

The database is created automatically at `~/.az-map/azmap.db` (or `%USERPROFILE%\.az-map\azmap.db` on Windows) on first run.

---

## Incremental Re-scan

To re-run analysis with updated rules without hitting the Azure APIs again:

In the UI: check **"Reuse cached collection"** before clicking Scan.

Or via the API:
```bash
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"subscription_id": "<sub-id>", "reuse_collection": true}'
```

---

## REST API

Full OpenAPI spec: **http://localhost:8000/docs**

Key endpoints:
```
POST   /api/scan/start                    Start a new scan
GET    /api/scan/subscriptions            List subscriptions from az login session
GET    /api/scan/current-user             Get currently logged-in az CLI user
POST   /api/scan/import                   Import a previously exported JSON
GET    /api/scan/{id}                     Get scan status
GET    /api/scan/stream/{id}              SSE real-time progress stream
GET    /api/graph/{id}/elements           Graph nodes + edges (filterable)
GET    /api/graph/{id}/node/{node_id}     Node detail + relationships
GET    /api/graph/{id}/paths              Attack path finder
GET    /api/graph/{id}/paths-from-owned   Paths from all owned nodes
GET    /api/graph/{id}/owned              List owned node IDs
POST   /api/graph/{id}/owned              Mark/unmark a node as owned
GET    /api/graph/{id}/stats              Scan statistics + metadata
GET    /api/findings/{id}                 List findings (filterable)
GET    /api/findings/{id}/summary         Severity/type breakdown
GET    /api/export/{id}/json              Full JSON export
GET    /api/export/{id}/csv              Multi-section CSV (findings + inventory + roles)
GET    /api/snapshot/diff?scan_a=&scan_b= Diff two scans
POST   /api/tenant/                       Create tenant config
GET    /api/tenant/                       List tenant configs
```

---

## Development

### Install dev dependencies

```bash
# Runtime + test dependencies
pip install -r requirements.txt -r requirements-dev.txt
```

### Run tests

```bash
python -m pytest tests/ -v
```

### Run with auto-reload

```bash
uvicorn backend.main:app --reload --port 8000
```

### Test coverage

```
tests/test_privilege_escalation.py   — 28 rule unit tests (all 20 rules covered)
tests/test_diff.py                   — 8 diff engine tests
tests/test_integration.py            — 8 DB + graph builder smoke tests
tests/test_api.py                    — 38 FastAPI endpoint tests
                                       79 total, 0 failures
```

### Adding a new detection rule

1. Open `backend/analyzers/privilege_escalation.py`
2. Add a method `rule_<name>(self) -> Generator[dict, None, None]`
3. Use `_find_dict(...)` to yield findings
4. Add the method to the `rules` list in `run_all()`
5. If it needs new context data, add the key to the `context` dict in `runner.py`
6. Add a unit test in `tests/test_privilege_escalation.py`

---

## Platform Notes

### Windows
- Python 3.11 from [python.org](https://www.python.org/downloads/) — **check "Add Python to PATH"** during install
- Azure CLI from [Microsoft's installer](https://aka.ms/installazurecliwindows) — installs as `az.cmd`; az-map detects this automatically
- Run `python run.py` (not `python3`) in Command Prompt or PowerShell; asyncio subprocess support requires Python 3.8+ (included in our 3.11 requirement)
- After `az login`, open a **new** terminal window before running az-map so the session is picked up correctly

### macOS
- Use `python3` if your system has both Python 2 and Python 3
- Azure CLI via Homebrew: `brew install azure-cli`, or the [pkg installer](https://aka.ms/installazureclimacos)
- Apple Silicon (M1/M2/M3): az-map works natively; Homebrew installs to `/opt/homebrew/bin/az` which is automatically detected

### Linux
- Use your distro's package manager for Python 3.11 or use pyenv
- Azure CLI install: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash` (Debian/Ubuntu)

---

## Limitations

- Scans one subscription at a time (multi-tenant config stores bookmarks; switch manually)
- Microsoft Graph permissions depend on the tenant's consent settings
- Runbook code scanning requires `Microsoft.Automation/automationAccounts/runbooks/content/read`
- Large tenants (>10K users/groups) may be slow — incremental scan mode helps

---

## License

MIT
