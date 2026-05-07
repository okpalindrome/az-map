# REST API Reference

The full interactive API spec (Swagger UI) is available at **http://localhost:8000/docs** while the server is running.

All endpoints return JSON. All error responses use the format `{"detail": "message"}`.

---

## Authentication

No API authentication is required — az-map is a local tool and binds to `localhost` only. Do not expose it on a public network interface.

---

## Scan

### Start a scan

```
POST /api/scan/start
```

**Request body:**
```json
{
  "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "snapshot_label": "baseline-2026",
  "reuse_collection": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `subscription_id` | UUID string | Yes | Azure subscription to scan |
| `snapshot_label` | string | No | Human-readable label (max 128 chars) |
| `reuse_collection` | boolean | No | If true, skip API collection and reuse last scan's data |

**Response:** `ScanResponse` (see below)

**Errors:**
- `422` — subscription_id is not a valid UUID

---

### Get scan status

```
GET /api/scan/{scan_id}
```

**Response: ScanResponse**
```json
{
  "scan_id": "...",
  "subscription_id": "...",
  "subscription_name": "My Subscription",
  "tenant_id": "...",
  "status": "completed",
  "started_at": "2026-05-07T10:00:00",
  "completed_at": "2026-05-07T10:02:34",
  "progress": {"phase": "done", "message": "Scan complete", "current": 5, "total": 5},
  "error": null,
  "snapshot_label": "baseline-2026"
}
```

Status values: `running` | `completed` | `failed`

---

### Stream scan progress (Server-Sent Events)

```
GET /api/scan/stream/{scan_id}
```

Returns an SSE stream. Each event is a JSON object:
```
data: {"phase": "collect", "message": "Collecting users...", "current": 1, "total": 5}
data: {"phase": "done", "message": "Scan complete", "current": 5, "total": 5}
```

The stream closes when `phase` is `done` or `error`.

---

### List scans

```
GET /api/scan/
```

Returns the 50 most recent scans, sorted by start date descending.

---

### Delete a scan

```
DELETE /api/scan/{scan_id}
```

Cascade-deletes all nodes, edges, findings, and role data for the scan.

**Response:** `{"deleted": "<scan_id>"}`

---

## Graph

### Get graph elements (Cytoscape.js format)

```
GET /api/graph/{scan_id}/elements
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `node_types` | string | Comma-separated node types to include (e.g. `user,group,key_vault`) |
| `risk_levels` | string | Comma-separated risk levels: `safe`, `risky`, `critical` |
| `search` | string | Free-text search against node name and ID (max 200 chars) |

**Response:**
```json
{
  "elements": {
    "nodes": [
      {
        "data": {
          "id": "user-alice-guid",
          "label": "Alice Johnson",
          "fullLabel": "Alice Johnson",
          "nodeType": "user",
          "riskLevel": "critical",
          "riskScore": 9.0,
          "riskReasons": ["Owner at subscription scope"],
          "color": "#2563EB",
          "shape": "ellipse",
          "borderColor": "#DC2626",
          "borderWidth": 3
        }
      }
    ],
    "edges": [
      {
        "data": {
          "id": "edge-guid",
          "source": "user-alice-guid",
          "target": "role-owner-guid",
          "edgeType": "has_role",
          "label": "Owner",
          "properties": {"scope": "/subscriptions/...", "role_name": "Owner"}
        }
      }
    ]
  },
  "stats": {
    "total_nodes": 142,
    "total_edges": 89,
    "critical_nodes": 3,
    "risky_nodes": 11
  }
}
```

---

### Get node detail

```
GET /api/graph/{scan_id}/node/{node_id}
```

`node_id` can be a GUID or an Azure resource ID (URL-encoded).

**Response:**
```json
{
  "node_id": "...",
  "node_type": "user",
  "name": "Alice Johnson",
  "display_name": "Alice Johnson",
  "risk_score": 9.0,
  "risk_level": "critical",
  "risk_reasons": ["Owner at subscription scope"],
  "properties": {"upn": "alice@contoso.com", "account_enabled": true},
  "relationships": [
    {
      "direction": "outbound",
      "edge_type": "has_role",
      "other_node_id": "role-owner-guid",
      "other_node_name": "Owner",
      "other_node_type": "role_definition",
      "properties": {"scope": "/subscriptions/...", "role_name": "Owner"}
    }
  ]
}
```

---

### Find attack paths

```
GET /api/graph/{scan_id}/paths
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `from_node` | string | Source node ID or name |
| `to_node` | string | Target node ID or name (optional) |
| `max_depth` | integer | Maximum path length in hops (1–8, default 5) |

If neither `from_node` nor `to_node` is given, returns all escalation paths to Owner-equivalent roles.

If only `from_node` is given, returns all reachable sensitive resources (lateral movement).

---

### Graph statistics

```
GET /api/graph/{scan_id}/stats
```

**Response:**
```json
{
  "scan_id": "...",
  "subscription_id": "...",
  "subscription_name": "My Subscription",
  "status": "completed",
  "node_counts": {"user": 45, "group": 12, "service_principal": 23, "key_vault": 3},
  "risk_counts": {"safe": 71, "risky": 8, "critical": 3},
  "finding_counts": {"critical": 2, "high": 5, "medium": 3, "low": 1},
  "total_role_assignments": 187
}
```

---

## Findings

### List findings

```
GET /api/findings/{scan_id}
```

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `severity` | (all) | Comma-separated: `critical,high,medium,low,info` |
| `finding_type` | (all) | Comma-separated finding types |
| `search` | (none) | Free-text search in title and description (max 200 chars) |
| `sort_by` | `risk_score` | `risk_score` \| `severity` \| `blast_radius` \| `title` |
| `limit` | 200 | 1–1000 |
| `offset` | 0 | Pagination offset |

**Response:**
```json
{
  "total": 12,
  "offset": 0,
  "limit": 200,
  "findings": [
    {
      "id": "...",
      "finding_type": "privilege_escalation",
      "severity": "critical",
      "title": "Privilege escalation: Contributor + UAA → Owner (Alice)",
      "description": "...",
      "affected_node_id": "user-alice-guid",
      "affected_node_name": "Alice Johnson",
      "attack_chain": [
        {"step": 1, "action": "Principal already has Contributor"},
        {"step": 2, "action": "Use UAA to assign Owner to self"},
        {"step": 3, "action": "Now has full Owner control"}
      ],
      "why_risky": "Combination grants effective Owner without being explicitly assigned Owner.",
      "remediation": "Remove User Access Administrator...",
      "tags": ["privilege-escalation", "rbac", "owner"],
      "risk_score": 9.5,
      "blast_radius": 100
    }
  ]
}
```

---

### Findings summary

```
GET /api/findings/{scan_id}/summary
```

Returns severity breakdown, type breakdown, and top-5 findings by risk score.

---

### Get single finding

```
GET /api/findings/{scan_id}/finding/{finding_id}
```

---

## Export

### JSON export

```
GET /api/export/{scan_id}/json
```

Returns a structured JSON file with scan metadata, all findings, full inventory, and role assignments. `Content-Disposition: attachment`.

### CSV export

```
GET /api/export/{scan_id}/csv
```

Returns a CSV file with one row per finding. Columns: severity, risk_score, blast_radius, finding_type, title, affected_node, why_risky, remediation, tags.

### HTML report

```
GET /api/export/{scan_id}/html
```

Returns a self-contained HTML report with executive summary, severity badges, findings by type, all findings with attack chains and remediation, and resource inventory.

### Attack paths JSON

```
GET /api/export/{scan_id}/paths
```

Returns all detected privilege escalation paths and lateral movement paths as structured JSON.

---

## Snapshot

### List snapshots for a subscription

```
GET /api/snapshot/list/{subscription_id}
```

Returns completed scans for a subscription, most recent first.

### Diff two scans

```
GET /api/snapshot/diff?scan_a={scan_id}&scan_b={scan_id}
```

`scan_a` = baseline (older), `scan_b` = current (newer).

**Response:**
```json
{
  "scan_a": {"id": "...", "label": "baseline-2026", "date": "2026-01-01T..."},
  "scan_b": {"id": "...", "label": null, "date": "2026-05-07T..."},
  "summary": {
    "new_nodes": 3,
    "removed_nodes": 1,
    "risk_increased": 2,
    "risk_decreased": 0,
    "new_findings": 4,
    "resolved_findings": 1,
    "new_critical": 1,
    "new_high": 3
  },
  "new_nodes": [...],
  "removed_nodes": [...],
  "risk_changed": [...],
  "new_findings": [...],
  "resolved_findings": [...]
}
```

### Set snapshot label

```
POST /api/snapshot/label/{scan_id}
```

**Request body:** `{"label": "baseline-2026"}`  
**Response:** `{"scan_id": "...", "label": "baseline-2026"}`

---

## Tenant Configuration

### List tenants

```
GET /api/tenant/
```

### Create tenant

```
POST /api/tenant/
```

**Request body:**
```json
{
  "display_name": "Contoso Production",
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "subscription_ids": ["sub-uuid-1", "sub-uuid-2"],
  "notes": "Primary production tenant"
}
```

All fields are validated: UUIDs checked, control chars stripped, length capped.

### Get tenant

```
GET /api/tenant/{id}
```

### Update tenant

```
PUT /api/tenant/{id}
```

Partial update — only fields present in the request body are modified.

### Delete tenant

```
DELETE /api/tenant/{id}
```

Returns HTTP 204 No Content.

---

## Health

```
GET /health
```

**Response:** `{"status": "ok"}`

Used to verify the server is running. Returns 200 always if the process is alive.
