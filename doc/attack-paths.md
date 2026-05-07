# Attack Path Analysis

## What is Attack Path Modeling?

Attack path modeling answers the question: **given that an attacker compromises identity X, what can they reach?**

In Azure, privileges are rarely direct. An attacker rarely finds a single identity with Owner assigned directly to them. Instead, they chain:
- Group memberships that grant RBAC roles
- Managed identity assignments on compute resources
- App registrations with Graph permissions
- Automation runbooks executing as privileged identities

az-map builds a directed graph of every identity, role, and resource in the subscription, then uses graph algorithms to find these chains automatically.

---

## How az-map Builds Paths

### Step 1 — Graph construction

Every collected entity becomes a **Node**. Every relationship becomes a directed **Edge**:

```
Alice ──[member_of]──▶ Security-Admins ──[has_role]──▶ Owner (subscription)
                                                            ↑
MyFunctionApp ──[has_system_identity]──▶ FunctionApp-MI ──[has_role]──▶ Contributor
```

Edge types:
| Edge | Meaning |
|---|---|
| `has_role` | Principal has RBAC role at scope |
| `member_of` | User/SP is member of group |
| `assigned_to` | Managed identity assigned to resource |
| `has_system_identity` | Resource has system-assigned MI |
| `has_entra_role` | Principal has Entra directory role |
| `contains` | Structural (sub → RG → resource) |
| `can_escalate_to` | Derived privilege escalation edge |

### Step 2 — NetworkX path finding

az-map uses Python's NetworkX library to:

- `nx.all_simple_paths(G, source, target)` — find all non-repeating paths between two nodes
- `nx.shortest_path(G, source, target)` — find the shortest escalation chain
- `nx.ancestors(G, target)` — find everything that can reach a high-value target

### Step 3 — Target identification

"High-value targets" are nodes of type `role_definition` with names matching `owner`, `user access admin`, or `rbac admin`. Global Admin escalation paths use Entra role nodes as targets.

---

## Path Types

### Privilege Escalation Paths

Paths from any identity to Owner-equivalent privilege. These are the most dangerous — they represent full subscription takeover.

**Example chain:**
```
JohnDoe (user)
  → member_of → Cloud-Infra-Team (group)
  → has_role → Contributor (at subscription)
  + has_role → User Access Administrator (at subscription)
  → [can assign] → Owner
```

**How to find in az-map:**
- Click **⚡ Paths** → click **→ Global Admin** / leave "To" blank → Find Paths
- Or: navigate to `GET /api/graph/{scan_id}/paths` with no parameters

### Lateral Movement Paths

Paths from a compromised identity to sensitive resources (Key Vaults, Storage Accounts, Automation Accounts). These represent data exfiltration or persistence paths.

**Example chain:**
```
compromised-vm (VM)
  → has_system_identity → vm-managed-identity (MI)
  → has_role → Key Vault Secrets User (at KV scope)
  → can read → production-secrets (Key Vault)
```

**How to find in az-map:**
- Click **⚡ Paths** → enter a node name in "From" → leave "To" blank → Find Paths
- API: `GET /api/graph/{id}/paths?from_node=<node_id>`

### Point-to-Point Paths

Find all paths between two specific nodes.

**How to find:**
- Click **⚡ Paths** → enter both "From" and "To" → Find Paths
- API: `GET /api/graph/{id}/paths?from_node=<id>&to_node=<id>&max_depth=5`

---

## Interpreting Results

### Path result format

```
2h  alice@contoso.com → Contributor → Owner
```

- `2h` — 2 hops (2 edges traversed)
- The path is the sequence of nodes and edges
- Click the result row to highlight the path in the graph

### Shorter paths = higher priority

A 2-hop path is more dangerous than a 5-hop path. The attacker needs fewer steps and fewer things to go wrong.

### Graph highlighting

When you select a path:
- Path nodes stay visible
- Everything else fades
- Path edges turn bold with labels

Click the graph background to clear the highlight.

---

## Export: Attack Paths JSON

Click **Paths** in the toolbar export section (or `GET /api/export/{scan_id}/paths`) to download all detected paths as structured JSON.

```json
{
  "az_map_version": "1.0",
  "scan_id": "...",
  "escalation_paths": [
    {
      "source": "user-alice-guid",
      "source_name": "Alice Johnson",
      "target": "role-def-owner-guid",
      "length": 2,
      "path": ["user-alice-guid", "group-infra-guid", "role-def-owner-guid"]
    }
  ],
  "lateral_movement_paths": [
    {
      "target": "kv-prod-secrets-id",
      "target_name": "prod-kv",
      "target_type": "key_vault",
      "hops": 2,
      "path": [...]
    }
  ],
  "summary": {
    "total_escalation_paths": 14,
    "total_lateral_paths": 8
  }
}
```

---

## Limitations

### What az-map CAN detect

- Azure RBAC-based privilege chains (Owner, Contributor, UAA via direct assignment or group)
- Managed identity → resource → data-plane access
- Entra directory role → tenant-wide privilege
- Group membership transitivity (nested groups resolved)
- App registration → tenant-wide Graph permission

### What az-map CANNOT detect (yet)

- **Conditional Azure Policy allow/deny** — custom policy effects that override RBAC
- **Azure AD PIM eligible assignments** — these are not activated and don't appear in role assignments
- **Legacy admin portals** — Classic Azure Administrator roles
- **Azure B2C tenants** — different identity model
- **Service connection credential theft paths** — e.g. GitHub Actions secrets → SP credentials
- **Kubernetes RBAC** — AKS cluster-internal privilege is out of scope

### Path depth cap

The default `max_depth` is 5 hops. Deep chains (>5 hops) are rare in practice and expensive to compute. Override with `?max_depth=8` in the API if needed.
