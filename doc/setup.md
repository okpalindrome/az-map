# Setup Guide

## System Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.11 | 3.10 may work but untested |
| Azure CLI | Latest | Required for `az login` authentication |
| OS | Windows 10+ / Ubuntu 20.04+ / macOS 12+ | Cross-platform |
| RAM | 512 MB | More for large tenants (>5 K users) |
| Disk | 200 MB | Python packages + SQLite database |
| Network | Internet (initial scan) | Offline after data collected |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/az-map.git
cd az-map
```

### 2. Create a virtual environment

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (cmd.exe)**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Log in to Azure

```bash
az login
```

For a specific tenant:
```bash
az login --tenant <tenant-id>
```

For non-interactive environments (CI, headless servers):
```bash
az login --use-device-code
```

> **Windows note:** After `az login` in one terminal, open a new terminal before running `python run.py`. The new terminal inherits the token from the Azure CLI token cache at `%USERPROFILE%\.azure\`.

### 5. Start the server

```bash
python run.py
```

Open **http://localhost:8000** in your browser.

---

## Required Azure Permissions

The account used for `az login` must have:

| Scope | Permission | Why |
|---|---|---|
| Subscription | `Reader` | Enumerate all resources |
| Subscription | `Microsoft.Authorization/*/read` | Read RBAC assignments and definitions |
| Subscription | `Microsoft.Web/sites/config/read` | Read App Service auth settings |
| Subscription | `Microsoft.Automation/automationAccounts/runbooks/read` | List runbooks |
| Subscription | `Microsoft.Automation/automationAccounts/runbooks/content/read` | Read runbook code |
| Microsoft Graph | `User.Read.All` | Enumerate users |
| Microsoft Graph | `Group.Read.All` | Enumerate groups and memberships |
| Microsoft Graph | `Application.Read.All` | Enumerate service principals and apps |
| Microsoft Graph | `RoleManagement.Read.Directory` | Read Entra directory role assignments |
| Microsoft Graph | `Policy.Read.All` | Read Conditional Access policies |

**All permissions are read-only.** az-map never writes to, modifies, or deletes any Azure resources.

> **Minimum working setup:** Subscription Reader + User.Read.All + Group.Read.All + Application.Read.All. The other permissions improve detection accuracy but are not mandatory.

---

## Configuration

az-map is configured via environment variables with the `AZMAP_` prefix. All settings have safe defaults.

| Variable | Default | Description |
|---|---|---|
| `AZMAP_DB_PATH` | `~/.az-map/azmap.db` | SQLite database file location |
| `AZMAP_SNAPSHOTS_DIR` | `~/.az-map/snapshots` | Directory for snapshot exports |
| `AZMAP_API_TIMEOUT` | `30` | HTTP timeout in seconds per request |
| `AZMAP_MAX_CONCURRENCY` | `10` | Max concurrent API calls |

**Example:**
```bash
export AZMAP_DB_PATH="/data/azmap/scans.db"
export AZMAP_API_TIMEOUT=60   # slow tenant
python run.py
```

**Windows PowerShell:**
```powershell
$env:AZMAP_DB_PATH = "C:\data\azmap\scans.db"
python run.py
```

The database and snapshot directories are created automatically on first run.

---

## Running Tests

```bash
pip install pytest httpx
python -m pytest tests/ -v
```

Expected output: **79 passed, 1 warning** (Pydantic v2 deprecation notice — harmless).

---

## Updating

```bash
git pull
pip install -r requirements.txt   # pick up new dependencies
python run.py
```

The database schema uses SQLAlchemy with `create_all`, so new tables are created automatically on startup. Existing scan data is preserved.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Azure CLI credentials not available` | Not logged in | Run `az login` |
| `No module named 'fastapi'` | Virtual env not activated | Run `source .venv/bin/activate` |
| `Port 8000 already in use` | Another process on 8000 | `AZMAP_PORT=8001 python run.py` or kill the process |
| `403 Forbidden` from Azure API | Missing permissions | Check permissions table above |
| `429 Too Many Requests` | Rate-limited | az-map retries automatically; large tenants may be slow |
| `cytoscape is not defined` | Stale browser cache | Hard refresh: Ctrl+Shift+R / Cmd+Shift+R |
| Scan shows no users/groups | Missing Graph permissions | Grant `User.Read.All` and `Group.Read.All` consent |
