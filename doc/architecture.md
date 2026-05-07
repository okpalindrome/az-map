# Architecture

## Overview

az-map is a single-process Python application with a lightweight FastAPI backend serving a vanilla-JS single-page frontend. No external services, no Docker, no database server — just a Python process and a SQLite file.

```
┌──────────────────────────────────────────────────────────┐
│                    Browser (localhost:8000)               │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐              │
│  │  Graph   │  │  Table   │  │ Dashboard │  Cytoscape.js │
│  │  View    │  │  View    │  │   View    │  (vendored)   │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘              │
│       └─────────────┴───────────────┘                    │
│                   api.js (fetch)                         │
└──────────────────────────┬───────────────────────────────┘
                           │ HTTP (localhost)
┌──────────────────────────▼───────────────────────────────┐
│                    FastAPI (uvicorn)                      │
│  /api/scan   /api/graph   /api/findings   /api/export    │
│  /api/snapshot   /api/tenant   /health   /docs           │
│                                                          │
│  ┌─────────────┐   ┌─────────────┐   ┌───────────────┐  │
│  │  Collectors  │   │  Analyzers  │   │ Graph Builder │  │
│  │  (httpx)     │   │  (rules)    │   │ (NetworkX)    │  │
│  └──────┬───────┘   └──────┬──────┘   └───────┬───────┘  │
│         │                  │                  │          │
│  ┌──────▼──────────────────▼──────────────────▼───────┐  │
│  │                  SQLite (SQLAlchemy)                │  │
│  │          ~/.az-map/azmap.db                        │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────┘
                           │ HTTPS (Azure APIs)
          ┌────────────────┴─────────────────┐
          │                                  │
   Azure ARM API                    Microsoft Graph API
   management.azure.com             graph.microsoft.com
   (READ-ONLY: GET only)            (READ-ONLY: GET only)
```

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Web framework | FastAPI 0.115 | Async, OpenAPI auto-docs, dependency injection |
| ASGI server | uvicorn | Standard FastAPI server |
| Database | SQLite + SQLAlchemy 2.0 | Zero-infrastructure, portable |
| Graph analysis | NetworkX 3.4 | Path finding, centrality, ancestor queries |
| Azure auth | azure-identity (AzureCliCredential) | Delegates to `az login`, no credential storage |
| HTTP client | httpx (async) | Async GET requests to ARM and Graph APIs |
| Frontend | Vanilla JS (no framework) | No build step, works in any browser |
| Graph visualisation | Cytoscape.js 3.29 (vendored) | Force-directed graph, no CDN dependency |

---

## Module Map

```
backend/
├── config.py               Settings — AZMAP_* env vars via pydantic-settings
├── database.py             SQLAlchemy engine, session factory, init_db()
├── main.py                 FastAPI app, router registration, lifespan, static files
│
├── models/
│   └── db_models.py        ORM: Scan, Node, Edge, RoleDefinition, RoleAssignment,
│                           Finding, TenantConfig
│
├── collectors/
│   ├── base.py             TokenCache, BaseCollector (GET-only, retry logic)
│   ├── azure_collector.py  ARM API: RGs, storage, KV, apps, VMs, automation, MIs
│   │                       + get_policy_assignments() + get_app_auth_settings()
│   │                       + get_automation_runbooks()
│   ├── rbac_collector.py   ARM API: role definitions + all role assignments
│   ├── graph_collector.py  Graph API: users, groups, SPs, apps, Entra roles, CA policies
│   └── scan_orchestrator.py  Async pipeline: collect → persist → analyze
│                             Incremental mode: reuse_collection=True copies prior scan
│
├── analyzers/
│   ├── effective_permissions.py  Transitive group membership resolution
│   ├── privilege_escalation.py   20 detection rules (PrivilegeEscalationAnalyzer)
│   ├── risk_scorer.py            RBAC + Entra role → risk_score per node
│   ├── attack_paths.py           NetworkX: path-to-owner, lateral movement
│   ├── diff.py                   Scan comparison (new/removed/risk-changed)
│   └── runner.py                 run_all_analyzers() — called by orchestrator
│
├── graph/
│   └── builder.py          build_graph() → nx.DiGraph
│                           graph_to_cytoscape() → filtered Cytoscape.js elements
│
└── api/
    ├── scan.py             POST /start, GET /stream/{id} (SSE), list, get, delete
    ├── graph_api.py        GET /elements, /node/{id}, /paths, /stats
    ├── findings.py         GET /findings/{scan_id}, /summary, /finding/{id}
    ├── export.py           GET /json, /csv, /html, /paths
    ├── snapshot.py         GET /list/{sub_id}, /diff, POST /label/{scan_id}
    └── tenant.py           CRUD: GET /, POST /, GET /{id}, PUT /{id}, DELETE /{id}
```

---

## Data Flow

### Scan pipeline

```
1. POST /api/scan/start {subscription_id}
       │
       ▼
   Create Scan record (status=running)
       │
       ▼ (BackgroundTask)
   ScanOrchestrator.run()
       │
       ├─ [parallel] AzureCollector.collect_all()
       │    ├── get_subscription_info()
       │    ├── get_resource_groups()
       │    ├── get_storage_accounts()
       │    ├── get_key_vaults()
       │    ├── get_function_apps() + get_app_auth_settings()
       │    ├── get_automation_accounts() + get_automation_runbooks()
       │    ├── get_virtual_machines()
       │    ├── get_user_assigned_managed_identities()
       │    └── get_policy_assignments()
       │
       ├─ [parallel] RBACCollector.collect_all()
       │    ├── get_role_definitions()
       │    └── get_role_assignments()
       │
       ├─ [parallel] GraphCollector.collect_all()
       │    ├── get_users()
       │    ├── get_groups() + get_all_group_memberships()
       │    ├── get_service_principals()
       │    ├── get_app_registrations()
       │    ├── get_directory_roles()
       │    └── get_conditional_access_policies()
       │
       ├─ _persist_all()         ← writes Nodes, Edges, RoleDefinitions, RoleAssignments
       │
       └─ run_all_analyzers()
            ├── EffectivePermissionEngine  (transitive group resolution)
            ├── RiskScorer                 (score + risk_level per node)
            └── PrivilegeEscalationAnalyzer (20 rules → Finding records)
```

### Read path (browser → API)

```
GraphView.load(scanId, filters)
    │
    ▼
GET /api/graph/{id}/elements?node_types=...&risk_levels=...&search=...
    │
    ▼
graph_to_cytoscape()  ← queries Node + Edge tables with SQLAlchemy filters
    │
    ▼
{elements: {nodes: [...], edges: [...]}}  → Cytoscape.js renders graph
```

---

## Database Schema

All data is stored in `~/.az-map/azmap.db`. Each scan is self-contained — deleting a scan record cascade-deletes all its nodes, edges, and findings.

```
scans          ─┬─< nodes          (every identity and resource)
                ├─< edges          (directed relationships)
                ├─< role_definitions
                ├─< role_assignments
                └─< findings       (security findings)

tenant_configs  (standalone — not tied to scans)
```

**Node types:** `user`, `group`, `service_principal`, `managed_identity`,
`subscription`, `resource_group`, `storage_account`, `key_vault`,
`function_app`, `app_service`, `automation_account`, `vm`, `role_definition`

**Edge types:** `has_role`, `member_of`, `contains`, `assigned_to`,
`has_system_identity`, `can_escalate_to`, `has_entra_role`

---

## Security Design

See [security.md](security.md) for the full security analysis.

Key points:
- **Read-only**: all Azure API calls use HTTP GET only. No Azure resources are modified.
- **Token isolation**: access tokens live in memory only; never written to disk or logs.
- **Input validation**: all user-supplied strings are validated (UUID format, control-char strip, length cap).
- **Rate limiting**: automatic retry with `Retry-After` header respect on HTTP 429.
- **No SSRF risk**: API base URLs are hardcoded constants; no user input reaches URL construction.
- **SQL injection**: SQLAlchemy ORM with parameterised queries throughout.
