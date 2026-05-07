# Features

## Starting a Scan

1. Paste your Azure **Subscription ID** (UUID format) into the toolbar.
2. Click **Scan** — the button shows real-time progress via Server-Sent Events.
3. Progress phases: `init → collect → persist → analyze → done`
4. The scan history sidebar updates automatically on completion.

### Incremental Re-scan

To re-run only the analysis rules without hitting Azure APIs again:

- **UI:** check the **"Reuse cached collection"** option (if shown) before clicking Scan  
- **API:** `POST /api/scan/start` with `"reuse_collection": true`

This copies all collected data from the most recent completed scan for the same subscription and re-runs only the 20 detection rules. Useful when you update the tool and want to apply new rules to existing data.

---

## Graph View

The main view. An Obsidian-style force-directed graph of every identity and resource in the subscription.

### Node types and colors

| Node type | Color | Shape |
|---|---|---|
| User | Blue | Circle |
| Group | Cyan | Hexagon |
| Service Principal | Orange | Diamond |
| Managed Identity | Violet | Rounded diamond |
| Subscription | Dark blue | Star |
| Resource Group | Light blue | Rounded rectangle |
| Storage Account | Green | Rectangle |
| Key Vault | Red | Pentagon |
| Function App | Amber | Rounded triangle |
| VM | Slate | Circle |
| Automation Account | Purple | Circle |
| Role Definition | Gray | Triangle |

### Risk borders

Nodes with security findings get a colored border:
- **Red border** → Critical risk
- **Orange border** → Risky
- No border → Safe

### Interactions

| Action | Result |
|---|---|
| Click node | Opens detail panel (risk score, reasons, all relationships) |
| Click edge | Shows tooltip with edge type and scope |
| Hover node | Tooltip with full name and risk level |
| Click background | Clears selection and highlight |
| Scroll / pinch | Zoom in/out |
| Drag | Pan |
| Click **⊡** | Fit graph to screen |
| Click **⟳** | Re-run force layout |
| Click **+** / **−** | Zoom controls |

### Neighborhood highlight

Clicking a node fades all unrelated elements and highlights the immediate neighborhood (direct connections). Click the background to clear.

### Edge labels

Toggle **"Show edge labels"** in the sidebar to display relationship types on edges (e.g. "has_role: Owner", "member of").

---

## Sidebar Filters

### Resource type filter

Check/uncheck resource types to show/hide them from the graph. Changes apply immediately with a debounced API call.

### Risk level filter

Show only nodes at a given risk level: Critical, Risky, or Safe.

### Search

Free-text search across node names and IDs. Matches are filtered in the graph. Results update 400 ms after typing stops.

---

## Table View

Switch to **Table** in the toolbar for a data-grid view of the same scan.

### Findings tab

All security findings from the 20 detection rules. Sortable by risk score, severity, blast radius, or title.

- **Click a row** — expands inline showing description, attack chain, and remediation
- **Click the finding type tag** (e.g. `privilege escalation`) — expands an **explainability panel** with:
  - Why this is risky (plain language)
  - Numbered attack chain steps
  - Remediation guidance
- **Click the affected resource name** — switches to Graph view and highlights that node

### Inventory tab

All collected resources sorted by risk score. Click any row to navigate to the node in the graph.

### Roles tab

All Azure RBAC role definitions collected from the subscription, with privilege level indicators.

---

## Dashboard View

Switch to **Dashboard** in the toolbar for summary charts.

- **Severity donut chart** — Critical / High / Medium / Low / Info breakdown
- **Findings by type** — horizontal bar chart of finding categories
- **Resources by type** — node type breakdown
- **Top-5 Risk Findings** — click any card to navigate to the affected node in the graph

---

## Attack Path Panel

Click **⚡ Paths** in the toolbar to open the floating path finder panel.

### Usage

1. **From** field: enter a node name or ID (e.g. `my-function-app`, a user's display name, or a GUID)
2. **To** field: enter a target node (optional — leave blank to find all Owner-path escalations)
3. Click **Find Paths** — results appear below
4. **Click any result row** — the path is highlighted in the graph (fades everything else)

### → Global Admin shortcut

Click **→ Global Admin** to find all identities that can reach a Global Administrator Entra role in the fewest hops.

### Path result format

```
3h  Alice Johnson → has_role → Contributor → can_escalate → Owner
```

`3h` = 3 hops. Click to animate the graph to that path.

---

## Diff / Compare Mode

Click **⇄ Diff** in the toolbar to compare two scans side by side.

1. Select the **baseline** (older) scan from the left dropdown
2. Select the **current** (newer) scan from the right dropdown
3. Click **Compare**

### Output

- **New resources** — resources that appeared since the baseline (green)
- **Removed resources** — resources no longer present (red)
- **Risk increases** — nodes whose risk score went up by ≥ 0.5 (orange)
- **Risk decreases** — nodes whose risk score improved (blue)
- **New findings** — security findings not present in the baseline
- **Resolved findings** — findings that no longer fire

### Graph overlay

After comparing, the graph view is updated with a color overlay:
- Green border = new resource
- Red border + fade = removed resource
- Orange border = risk increased
- Blue border = risk decreased

---

## Export

| Button | Format | Contents |
|---|---|---|
| **JSON** | `azmap_<id>.json` | Full structured export: scan metadata, all findings (with attack chains), full inventory, all role assignments |
| **CSV** | `azmap_findings_<id>.csv` | Findings table: severity, risk score, blast radius, type, title, affected resource, why risky, remediation, tags |
| **Report** | `azmap_report_<id>.html` | Self-contained HTML report: executive summary table, severity badges, findings-by-type table, all findings with attack chains and remediation, resource inventory |
| **Paths** | `azmap_paths_<id>.json` | All detected privilege escalation paths + lateral movement paths (NetworkX shortest paths) |

---

## Tenant Configuration

The **Tenants** section in the sidebar stores named groups of subscription IDs. Useful for MSP workflows or multi-subscription environments.

- Click **+** to add a new tenant config
- Enter display name, Azure Tenant ID (optional), subscription IDs (one per line), and notes
- Click a tenant to filter the scan history to that tenant's subscriptions
- The ✎ button on any tenant edits it; ✕ deletes it

Tenant configs are stored in the local SQLite database and persist between sessions.

---

## Snapshot Labels

Every completed scan can have a human-readable label. Labels appear in the scan history sidebar, the diff compare dropdowns, and export filenames.

To set a label: click the **✎** button next to a scan in the history sidebar.

Example labels: `baseline-2026-Q1`, `post-remediation`, `before-infra-change`

---

## Scan History

The sidebar shows the last 50 scans, most recent first. Click any scan to load it into all views (graph, table, dashboard).

Scans can be deleted via the API: `DELETE /api/scan/{scan_id}` — this cascade-deletes all associated nodes, findings, and role data.
