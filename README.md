# ⚠️ Experimental 

# az-map — Azure Security Analysis Tool 


A lightweight, self-contained Azure privilege mapping and attack-path analysis tool. Inspired by BloodHound/AzureHound, but built from scratch without any BloodHound dependencies — so it works safely through corporate proxies and endpoint security tools.

---

## What it does

az-map scans an Azure subscription via Azure CLI credentials and produces an interactive graph of every identity, resource, and privilege relationship. It then runs 20 security detection rules to find:

- Privilege escalation paths (Owner escalation, Privileged Role Admin → Global Admin)
- Excessive permissions (Contributor+UAA combos, subscription-wide Owner)
- Managed identity lateral movement (MI on compute → access to Key Vault / Storage)
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
| **Database** | SQLite (`~/.az-map/azmap.db`) | Persistent scan storage (no server required) |
| **ORM** | SQLAlchemy | DB models: Scan, Node, Edge, Finding |
| **Graph engine** | NetworkX (DiGraph) | In-memory attack path analysis |
| **Azure auth** | azure-identity `AzureCliCredential` | Reads token from active `az login` session |
| **Azure APIs** | azure-mgmt-* (subscription, authorization, resource, storage, keyvault, web, compute, msi) | ARM control-plane data collection |
| **MS Graph** | raw httpx (no msgraph-sdk) | Users, groups, SPs, CA policies, Entra roles |
| **Frontend** | Vanilla JS (no framework, no build step) | Zero-dependency SPA |
| **Graph visualisation** | Cytoscape.js (vendored locally) | Force-directed interactive graph |
| **Theme** | Obsidian-inspired white | Clean, high-contrast, printable |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | 3.10 may work but untested |
| Azure CLI | Latest | `az login` must succeed before scanning |
| Internet access | — | CDN load for Cytoscape.js (one JS file) |

**Azure permissions needed for the scanning identity:**

| Scope | Permission |
|---|---|
| Subscription | `Reader` |
| Subscription | `Microsoft.Authorization/roleAssignments/read` |
| Microsoft Graph | `User.Read.All`, `Group.Read.All`, `Application.Read.All` |
| Microsoft Graph | `RoleManagement.Read.Directory` (for Entra roles) |
| Microsoft Graph | `Policy.Read.All` (for Conditional Access policies) |

> The scan account needs read-only access. It does not need write permissions.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/your-org/az-map.git
cd az-map

# 2. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # macOS/Linux
.venv\Scripts\activate             # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Log in to Azure
az login
# For a specific tenant:
az login --tenant <tenant-id>
```

---

## Quick Start

```bash
# Start the server
python run.py
# → Server running at http://localhost:8000
```

1. Open **http://localhost:8000** in your browser
2. Paste your **Subscription ID** into the top bar
3. Click **Scan** — real-time progress streams via SSE
4. Explore the interactive graph, findings table, and dashboard

---

## Features

### Graph View
- Force-directed layout (Cytoscape.js / cose algorithm)
- Nodes coloured and shaped by type (user, group, SP, MI, KV, storage, etc.)
- Red/orange borders on risky/critical nodes
- Click any node → detail panel with risk score, reasons, and relationships
- Filter sidebar: filter by resource type, risk level, or free-text search
- Toggle edge labels, zoom/fit controls

### Table View
- **Findings** tab: all security findings sortable by risk score, severity, blast radius
  - Click the finding type tag → inline explainability (why risky + attack chain + remediation)
  - Click the affected resource name → jump to node in graph
- **Inventory** tab: full resource list with risk scores
- **Roles** tab: all role definitions with privilege levels

### Dashboard View
- Severity donut chart (plain SVG — no extra libraries)
- Findings by type bar chart
- Resources by type bar chart
- Top-5 risk findings (clickable → graph navigation)

### Attack Path Panel
- Click **⚡ Paths** in the toolbar
- Enter from/to node IDs or names
- Or click **→ Global Admin** for all paths to Global Admin
- Paths are highlighted in the graph; click any result to animate to it

### Diff / Compare
- Click **⇄ Diff** to compare two scans
- Shows: new resources, removed resources, risk-changed identities, new/resolved findings
- Diff overlay highlights changes directly on the graph (green=new, orange=risk-up)

### Export
| Format | Description |
|---|---|
| **JSON** | Full structured export: findings, inventory, role assignments |
| **CSV** | Findings table for Excel/Sheets |
| **HTML Report** | Self-contained report with executive summary, all findings, inventory |
| **Paths** | Attack path JSON: all escalation + lateral movement paths |

### Snapshot Labels
- Right-click the ✎ button on any scan in the history sidebar to add a label (e.g. "baseline-2026-Q1")
- Labels appear in diff selectors and export filenames

### Multi-Tenant Config
- Click **+** in the Tenants section of the sidebar to save subscription groups
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

az-map uses environment variables with the `AZMAP_` prefix:

```bash
export AZMAP_DB_PATH="~/.az-map/azmap.db"        # SQLite database location
export AZMAP_SNAPSHOTS_DIR="~/.az-map/snapshots"  # Snapshot storage
export AZMAP_API_TIMEOUT=30                        # HTTP timeout (seconds)
export AZMAP_MAX_CONCURRENCY=10                    # Max concurrent API calls
```

The database is created automatically at `~/.az-map/azmap.db` on first run.

---

## Incremental Re-scan

To re-run analysis with updated rules without hitting the Azure APIs again:

```bash
# In the UI: check "Reuse cached collection" before clicking Scan
# Or via API:
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"subscription_id": "<sub-id>", "reuse_collection": true}'
```

This copies all collected data from the most recent completed scan for the same subscription and re-runs only the analyzers.

---

## REST API

The full OpenAPI spec is at **http://localhost:8000/docs**.

Key endpoints:

```
POST   /api/scan/start                   Start a scan
GET    /api/scan/{id}                    Get scan status
GET    /api/scan/stream/{id}             SSE progress stream
GET    /api/graph/{id}/elements          Graph nodes + edges (filterable)
GET    /api/graph/{id}/node/{node_id}    Node detail + relationships
GET    /api/graph/{id}/paths             Attack path finder
GET    /api/graph/{id}/stats             Scan statistics
GET    /api/findings/{id}                List findings (filterable)
GET    /api/findings/{id}/summary        Severity/type breakdown
GET    /api/export/{id}/json             JSON export
GET    /api/export/{id}/csv              CSV export
GET    /api/export/{id}/html             HTML report
GET    /api/export/{id}/paths            Attack paths JSON
GET    /api/snapshot/diff?scan_a=&scan_b= Diff two scans
POST   /api/tenant/                      Create tenant config
GET    /api/tenant/                      List tenant configs
```

---

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run with auto-reload (development)
uvicorn backend.main:app --reload --port 8000

# Check Python syntax
python -c "import ast, pathlib; [ast.parse(f.read_text()) for f in pathlib.Path('backend').rglob('*.py')]"
```

### Test coverage

```
tests/test_privilege_escalation.py   — 28 rule unit tests (all 20 rules covered)
tests/test_diff.py                   — 8 diff engine tests
tests/test_integration.py            — 8 DB + graph builder smoke tests
tests/test_api.py                    — 38 FastAPI endpoint tests
```

### Adding a new detection rule

1. Open `backend/analyzers/privilege_escalation.py`
2. Add a method `rule_<name>(self) -> Generator[dict, None, None]`
3. Use `_find_dict(...)` to yield findings
4. Add the method to the `rules` list in `run_all()`
5. If it needs new context data, add the key to the `context` dict in `runner.py`
6. Add a unit test in `tests/test_privilege_escalation.py`

---

## Limitations

- Scans one subscription at a time (multi-tenant config stores bookmarks; switch manually)
- Microsoft Graph permissions depend on the tenant's consent settings
- Runbook code scanning requires `Microsoft.Automation/automationAccounts/runbooks/content/read`
- Large tenants (>10K users/groups) may be slow — incremental scan mode helps

---

## License

MIT
