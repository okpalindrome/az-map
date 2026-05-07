# Security Design

## Read-Only Guarantee

**az-map never modifies, creates, or deletes any Azure resource.**

All HTTP calls to Azure APIs use the GET method exclusively. This is enforced at the
`BaseCollector` class level — only `_get`, `_paginate_arm`, `_paginate_graph`,
`_get_arm`, and `_get_graph` are exposed. These are all GET wrappers.
No `POST`, `PUT`, `PATCH`, or `DELETE` methods exist on collector classes.

To verify:
```bash
grep -rn "client\.post\|client\.put\|client\.delete\|client\.patch" backend/collectors/
# → (no output — zero write calls)
```

---

## Authentication & Credentials

### How authentication works

az-map uses `AzureCliCredential` from the `azure-identity` library. This delegates
entirely to the Azure CLI token cache — az-map itself never handles, prompts for,
or stores Azure passwords or client secrets.

**Windows:** tokens stored in `%USERPROFILE%\.azure\` by the Azure CLI  
**Linux/macOS:** tokens stored in `~/.azure/` by the Azure CLI

### Token handling

- Tokens are held **in memory only** (Python `dict` inside `TokenCache`)
- Tokens are **never written to disk** by az-map (only by `az login`)
- Tokens are **never emitted in logs** — auth headers are constructed inline and not passed to logger calls
- Tokens are refreshed 60 seconds before expiry to avoid mid-scan failures
- Tokens are refreshed on every HTTP retry attempt in case they expired during a long scan

### Token scope

- ARM scope: `https://management.azure.com/.default` — read-only if the user's RBAC only grants Reader
- Graph scope: `https://graph.microsoft.com/.default` — limited to the user's Graph consented permissions

The `.default` scope means the token contains exactly the permissions the signed-in account has — az-map cannot exceed the caller's actual permissions.

---

## Input Validation

All user-supplied input entering the API layer is validated before use.

### subscription_id

Validated as a strict UUID (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
Rejects paths with slashes, IP addresses, or other invalid formats.

```python
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
```

### String fields (snapshot labels, tenant names, notes)

- Control characters (`\x00–\x1f`, `\x7f`) stripped
- Length caps enforced: 128 chars (labels, names), 1024 chars (notes)
- Empty strings rejected where a value is required

### List fields (subscription_ids in tenant config)

Each item validated as UUID individually. Malformed entries raise a validation error.

### Search / filter query parameters

- `search` — `max_length=200` enforced at FastAPI Query level
- `node_types` / `risk_levels` — split by comma, values used only as SQLAlchemy filter values (parameterised)
- `severity` / `finding_type` — same pattern

### Path / URL parameters

- `scan_id`, `node_id`, `tenant_id_` — passed directly to SQLAlchemy parameterised queries (no SQL injection risk)
- `node_id` is URL-decoded by FastAPI before reaching the route handler

---

## SQL Injection

az-map uses SQLAlchemy ORM with parameterised queries throughout. No raw SQL strings
are constructed from user input.

The `LIKE` pattern for search:
```python
s = f"%{search.lower()}%"
func.lower(Node.name).like(s)
```

SQLAlchemy passes `s` as a bind parameter, not interpolated into the SQL string. The `%` and `_` wildcards in the search string behave as LIKE wildcards (broad match), which is the intended behaviour — not a security issue.

---

## Log Injection

All user-controlled or external-API-sourced strings are sanitised before reaching log output:

```python
def _sanitize_for_log(text: str) -> str:
    return str(text).replace("\n", " ").replace("\r", " ")[:200]
```

This prevents a malicious API response from injecting fake log lines.

---

## SSRF (Server-Side Request Forgery)

az-map is not vulnerable to SSRF because:
- All HTTP base URLs are **hardcoded constants** (`management.azure.com`, `graph.microsoft.com`)
- No user input reaches URL construction
- The only caller-controlled part of a URL is `{subscription_id}` which is UUID-validated

---

## Rate Limiting & Retry

az-map implements automatic retry with exponential back-off:

| Response | Behaviour |
|---|---|
| `429 Too Many Requests` | Read `Retry-After` header; wait that many seconds (capped at 60); retry |
| `500 / 502 / 503 / 504` | Exponential back-off: 1s → 4s → 16s; give up after 3 attempts |
| Network timeout | Same exponential back-off |

This prevents scan failures due to transient Azure API throttling, which is common for subscriptions with large numbers of resources.

Azure ARM rate limits: ~12,000 GET requests/hour/subscription  
Microsoft Graph rate limits: ~1,000 requests/10 minutes (varies by endpoint)

With a default concurrency of 10 and retry logic, az-map stays well within these limits for typical subscriptions.

---

## Data Storage

All scan data is stored locally in `~/.az-map/azmap.db` (SQLite).

- **No data leaves the machine** beyond the Azure API calls
- No telemetry, no analytics, no cloud sync
- The database file contains collected Azure resource metadata and security findings
- Treat the database file with the same sensitivity as your Azure portal access — it contains resource names, principal IDs, and privilege information

To delete all scan data:
```bash
rm ~/.az-map/azmap.db
```

---

## Network Traffic

az-map makes outbound HTTPS requests to:
- `https://management.azure.com` — Azure Resource Manager API
- `https://graph.microsoft.com` — Microsoft Graph API
- `https://login.microsoftonline.com` — Azure AD token endpoint (via azure-identity)

No other outbound connections are made. Cytoscape.js is vendored locally — no CDN calls.

---

## Windows vs. Linux Security Notes

### Windows

- Run az-map in a user-level terminal (not Administrator/SYSTEM)
- The Azure CLI token cache at `%USERPROFILE%\.azure\msal_token_cache.bin` is protected by DPAPI (Windows data protection) — only the logged-in user can read it
- Run `az login` before starting az-map in each new terminal session
- The database at `%USERPROFILE%\.az-map\azmap.db` has no special permissions — consider encrypting the folder if this is a shared machine

### Linux

- Run as a non-root user
- `~/.azure/` token cache is `600` (user-only) by default
- `~/.az-map/azmap.db` is created `640` — consider `chmod 600` if on a shared system:
  ```bash
  chmod 600 ~/.az-map/azmap.db
  ```

---

## Threat Model Summary

| Threat | Mitigated? | Notes |
|---|---|---|
| Accidental Azure resource modification | ✅ Yes | GET-only; write calls impossible |
| Credential theft from logs | ✅ Yes | Tokens never logged |
| Credential theft from disk | ✅ Yes | Tokens held in memory only |
| SQL injection | ✅ Yes | ORM with parameterised queries |
| Log injection | ✅ Yes | `_sanitize_for_log()` on all external strings |
| SSRF | ✅ Yes | Hardcoded API base URLs |
| XSS in HTML export | ✅ Yes | `_esc()` applied to all dynamic content |
| Input validation bypass | ✅ Yes | UUID regex, control-char strip, length caps |
| Rate limit exhaustion / scan failure | ✅ Yes | Retry with Retry-After respect |
| Data exfiltration by az-map | ✅ N/A | Local-only, no telemetry |
| Privilege escalation via az-map | ✅ N/A | Read-only; cannot assign roles |
| Stale browser cache (wrong HTML) | ✅ Yes | `Cache-Control: no-store` on index.html |
