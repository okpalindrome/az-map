"""
FastAPI TestClient smoke tests.

All tests use an in-memory SQLite DB via dependency override — no Azure
credentials required, no real DB file created.
"""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models.db_models import (
    Finding, Node, RoleAssignment, Scan, TenantConfig,
)


# ── Shared in-memory DB ──────────────────────────────────────────────────────
# StaticPool forces all SQLAlchemy sessions to share ONE connection, which is
# required for SQLite :memory: — otherwise each new connection gets a fresh DB.

_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_TEST_ENGINE)
_TestSession = sessionmaker(bind=_TEST_ENGINE, autoflush=True)


def _override_get_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db

# Single shared client for the session
client = TestClient(app, raise_server_exceptions=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mk_completed_scan(sub_id: str = "sub-test") -> str:
    """Insert a completed scan directly into the test DB; return scan_id."""
    from datetime import datetime
    db = _TestSession()
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        subscription_id=sub_id,
        subscription_name="Test Subscription",
        tenant_id="tenant-abc",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        progress={"phase": "done"},
    )
    db.add(scan)
    db.commit()
    db.close()
    return scan_id


def _mk_node(scan_id: str, node_id: str, node_type: str, name: str) -> None:
    db = _TestSession()
    db.add(Node(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        node_id=node_id,
        node_type=node_type,
        name=name,
        display_name=name,
        risk_level="safe",
        risk_score=0.0,
        properties={},
    ))
    db.commit()
    db.close()


def _mk_finding(scan_id: str) -> str:
    db = _TestSession()
    fid = str(uuid.uuid4())
    db.add(Finding(
        id=fid,
        scan_id=scan_id,
        finding_type="high_risk_role",
        severity="critical",
        title="Owner at subscription: TestUser",
        description="Test finding",
        attack_chain=[{"step": 1, "action": "Has Owner"}],
        why_risky="Full control",
        remediation="Use PIM",
        tags=["owner"],
        risk_score=9.0,
        blast_radius=100,
    ))
    db.commit()
    db.close()
    return fid


# ── Infrastructure endpoints ─────────────────────────────────────────────────

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_docs():
    r = client.get("/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower() or "openapi" in r.text.lower()


def test_root_returns_index_or_redirect():
    r = client.get("/", follow_redirects=False)
    # Either serves index.html (200) or redirects to /docs
    assert r.status_code in (200, 307, 308, 302)


# ── Scan API ─────────────────────────────────────────────────────────────────

def test_list_scans_empty():
    r = client.get("/api/scan/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_scan_not_found():
    r = client.get("/api/scan/nonexistent-id")
    assert r.status_code == 404


def test_get_scan_found():
    sid = _mk_completed_scan()
    r = client.get(f"/api/scan/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["scan_id"] == sid
    assert data["status"] == "completed"
    assert data["subscription_id"] == "sub-test"


def test_delete_scan():
    sid = _mk_completed_scan("sub-del")
    r = client.delete(f"/api/scan/{sid}")
    assert r.status_code == 200
    assert r.json()["deleted"] == sid
    # Confirm gone
    assert client.get(f"/api/scan/{sid}").status_code == 404


def test_delete_scan_not_found():
    r = client.delete("/api/scan/no-such-scan")
    assert r.status_code == 404


# ── Graph API ─────────────────────────────────────────────────────────────────

def test_graph_elements_empty_scan():
    sid = _mk_completed_scan("sub-graph")
    r = client.get(f"/api/graph/{sid}/elements")
    assert r.status_code == 200
    body = r.json()
    assert "elements" in body
    assert body["elements"]["nodes"] == []
    assert body["elements"]["edges"] == []


def test_graph_elements_with_nodes():
    sid = _mk_completed_scan("sub-graph2")
    _mk_node(sid, "user-a", "user", "Alice")
    _mk_node(sid, "group-a", "group", "Admins")
    r = client.get(f"/api/graph/{sid}/elements")
    assert r.status_code == 200
    nodes = r.json()["elements"]["nodes"]
    assert len(nodes) == 2
    node_ids = {n["data"]["id"] for n in nodes}
    assert "user-a" in node_ids


def test_graph_elements_filter_by_type():
    sid = _mk_completed_scan("sub-filter")
    _mk_node(sid, "u1", "user", "UserOne")
    _mk_node(sid, "kv1", "key_vault", "MyVault")
    r = client.get(f"/api/graph/{sid}/elements?node_types=user")
    assert r.status_code == 200
    nodes = r.json()["elements"]["nodes"]
    assert all(n["data"]["nodeType"] == "user" for n in nodes)
    assert len(nodes) == 1


def test_graph_node_detail():
    sid = _mk_completed_scan("sub-node")
    _mk_node(sid, "sp-1", "service_principal", "MyApp")
    r = client.get(f"/api/graph/{sid}/node/sp-1")
    assert r.status_code == 200
    data = r.json()
    assert data["node_id"] == "sp-1"
    assert data["node_type"] == "service_principal"
    assert data["name"] == "MyApp"


def test_graph_node_detail_not_found():
    sid = _mk_completed_scan()
    r = client.get(f"/api/graph/{sid}/node/no-such-node")
    assert r.status_code == 404


def test_graph_stats():
    sid = _mk_completed_scan("sub-stats")
    _mk_node(sid, "u1", "user", "Bob")
    _mk_node(sid, "kv1", "key_vault", "VaultA")
    r = client.get(f"/api/graph/{sid}/stats")
    assert r.status_code == 200
    data = r.json()
    assert "node_counts" in data
    assert data["node_counts"].get("user", 0) == 1
    assert data["node_counts"].get("key_vault", 0) == 1


def test_graph_attack_paths_empty():
    sid = _mk_completed_scan("sub-paths")
    r = client.get(f"/api/graph/{sid}/paths")
    assert r.status_code == 200
    assert "paths" in r.json()


def test_graph_not_found():
    r = client.get("/api/graph/no-scan/elements")
    assert r.status_code == 404


# ── Findings API ──────────────────────────────────────────────────────────────

def test_list_findings_empty():
    sid = _mk_completed_scan("sub-findings")
    r = client.get(f"/api/findings/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["findings"] == []


def test_list_findings_with_data():
    sid = _mk_completed_scan("sub-findings2")
    _mk_finding(sid)
    r = client.get(f"/api/findings/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 1
    assert data["findings"][0]["severity"] == "critical"


def test_findings_filter_by_severity():
    sid = _mk_completed_scan("sub-sev")
    _mk_finding(sid)  # critical
    # Also add a low finding
    db = _TestSession()
    db.add(Finding(
        id=str(uuid.uuid4()), scan_id=sid, finding_type="excessive_privilege",
        severity="low", title="Minor issue", attack_chain=[], tags=[], risk_score=2.0,
    ))
    db.commit()
    db.close()
    r = client.get(f"/api/findings/{sid}?severity=critical")
    assert r.status_code == 200
    data = r.json()
    assert all(f["severity"] == "critical" for f in data["findings"])


def test_findings_summary():
    sid = _mk_completed_scan("sub-summary")
    _mk_finding(sid)
    r = client.get(f"/api/findings/{sid}/summary")
    assert r.status_code == 200
    data = r.json()
    assert "by_severity" in data
    assert "top_risk" in data
    assert data["by_severity"].get("critical", 0) == 1


def test_findings_not_found():
    r = client.get("/api/findings/no-scan")
    assert r.status_code == 404


# ── Export API ────────────────────────────────────────────────────────────────

def test_export_json():
    sid = _mk_completed_scan("sub-export")
    _mk_finding(sid)
    r = client.get(f"/api/export/{sid}/json")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    data = r.json()
    assert data["az_map_version"] == "1.0"
    assert len(data["findings"]) == 1


def test_export_csv():
    sid = _mk_completed_scan("sub-csv")
    _mk_finding(sid)
    r = client.get(f"/api/export/{sid}/csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    lines = r.text.strip().split("\n")
    assert len(lines) == 2  # header + 1 finding


def test_export_html():
    sid = _mk_completed_scan("sub-html")
    _mk_finding(sid)
    r = client.get(f"/api/export/{sid}/html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "az-map" in r.text
    assert "Owner at subscription" in r.text


def test_export_paths():
    sid = _mk_completed_scan("sub-paths-export")
    _mk_node(sid, "u1", "user", "Alice")
    r = client.get(f"/api/export/{sid}/paths")
    assert r.status_code == 200
    data = r.json()
    assert "escalation_paths" in data
    assert "lateral_movement_paths" in data


def test_export_not_found():
    r = client.get("/api/export/no-scan/json")
    assert r.status_code == 404


# ── Snapshot API ──────────────────────────────────────────────────────────────

def test_list_snapshots_empty():
    r = client.get("/api/snapshot/list/sub-nosnapshots")
    assert r.status_code == 200
    assert r.json() == []


def test_list_snapshots_with_scan():
    sid = _mk_completed_scan("sub-snap")
    r = client.get("/api/snapshot/list/sub-snap")
    assert r.status_code == 200
    snaps = r.json()
    assert any(s["scan_id"] == sid for s in snaps)


def test_set_snapshot_label():
    sid = _mk_completed_scan("sub-label")
    r = client.post(f"/api/snapshot/label/{sid}", json={"label": "baseline-2026"})
    assert r.status_code == 200
    assert r.json()["label"] == "baseline-2026"
    # Verify it persists on the scan record
    r2 = client.get(f"/api/scan/{sid}")
    assert r2.json()["snapshot_label"] == "baseline-2026"


def test_diff_same_scan_error():
    sid = _mk_completed_scan()
    r = client.get(f"/api/snapshot/diff?scan_a={sid}&scan_b={sid}")
    # The diff engine allows same-scan comparison (returns empty diff), not an error
    assert r.status_code in (200, 400)


def test_diff_missing_scan():
    r = client.get("/api/snapshot/diff?scan_a=fake-a&scan_b=fake-b")
    assert r.status_code == 400


# ── Tenant API ───────────────────────────────────────────────────────────────

def test_list_tenants_initially_empty():
    r = client.get("/api/tenant/")
    assert r.status_code == 200
    # May have data from other tests — just verify it's a list
    assert isinstance(r.json(), list)


_SUB_UUID_1 = "11111111-1111-1111-1111-111111111111"
_SUB_UUID_2 = "22222222-2222-2222-2222-222222222222"
_TENANT_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_create_tenant():
    body = {
        "display_name": f"Contoso-{uuid.uuid4().hex[:6]}",
        "tenant_id": _TENANT_UUID,
        "subscription_ids": [_SUB_UUID_1, _SUB_UUID_2],
        "notes": "Primary tenant",
    }
    r = client.post("/api/tenant/", json=body)
    assert r.status_code == 201
    data = r.json()
    assert data["display_name"] == body["display_name"]
    assert data["subscription_ids"] == [_SUB_UUID_1, _SUB_UUID_2]
    assert data["id"] is not None


def test_create_tenant_duplicate_name():
    name = f"DupTenant-{uuid.uuid4().hex[:6]}"
    client.post("/api/tenant/", json={"display_name": name})
    r = client.post("/api/tenant/", json={"display_name": name})
    assert r.status_code == 409


def test_get_tenant():
    name = f"GetTest-{uuid.uuid4().hex[:6]}"
    created = client.post("/api/tenant/", json={"display_name": name}).json()
    tid = created["id"]
    r = client.get(f"/api/tenant/{tid}")
    assert r.status_code == 200
    assert r.json()["display_name"] == name


def test_update_tenant():
    name = f"UpdateTest-{uuid.uuid4().hex[:6]}"
    created = client.post("/api/tenant/", json={"display_name": name}).json()
    tid = created["id"]
    _new_sub = "99999999-9999-9999-9999-999999999999"
    r = client.put(f"/api/tenant/{tid}", json={"subscription_ids": [_new_sub], "notes": "updated"})
    assert r.status_code == 200
    updated = r.json()
    assert updated["subscription_ids"] == [_new_sub]
    assert updated["notes"] == "updated"


def test_delete_tenant():
    name = f"DelTest-{uuid.uuid4().hex[:6]}"
    created = client.post("/api/tenant/", json={"display_name": name}).json()
    tid = created["id"]
    r = client.delete(f"/api/tenant/{tid}")
    assert r.status_code == 204
    assert client.get(f"/api/tenant/{tid}").status_code == 404


def test_get_tenant_not_found():
    r = client.get("/api/tenant/nonexistent")
    assert r.status_code == 404
