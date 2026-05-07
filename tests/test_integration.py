"""
Integration smoke tests.

These tests do NOT start the HTTP server — they test the full
backend stack (DB init, model creation, graph building, analyzer
pipeline) using in-memory SQLite and synthetic data.
"""
import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models.db_models import (
    Edge, Finding, Node, RoleAssignment, RoleDefinition, Scan, TenantConfig,
)


@pytest.fixture(scope="module")
def engine():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(e)
    yield e
    Base.metadata.drop_all(e)


@pytest.fixture(scope="function")
def db(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.rollback()
    s.close()


# ──────────────────────────────────────────────────────────────
# DB / model smoke tests
# ──────────────────────────────────────────────────────────────

def test_db_init(db):
    """All tables exist and are queryable."""
    assert db.query(Scan).count() == 0
    assert db.query(Node).count() == 0
    assert db.query(Finding).count() == 0
    assert db.query(TenantConfig).count() == 0


def test_create_scan(db):
    sid = str(uuid.uuid4())
    scan = Scan(
        id=sid,
        subscription_id="sub-test",
        subscription_name="Test",
        status="running",
        progress={"phase": "init"},
    )
    db.add(scan)
    db.commit()
    retrieved = db.query(Scan).filter(Scan.id == sid).first()
    assert retrieved is not None
    assert retrieved.subscription_id == "sub-test"
    assert retrieved.progress["phase"] == "init"


def test_create_node_and_edge(db):
    scan = Scan(id=str(uuid.uuid4()), subscription_id="sub-x", status="completed")
    db.add(scan)
    db.commit()

    n1 = Node(id=str(uuid.uuid4()), scan_id=scan.id,
              node_id="user-1", node_type="user", name="Alice", display_name="Alice")
    n2 = Node(id=str(uuid.uuid4()), scan_id=scan.id,
              node_id="group-1", node_type="group", name="Admins", display_name="Admins")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        id=str(uuid.uuid4()),
        scan_id=scan.id,
        source_node_id="user-1",
        target_node_id="group-1",
        edge_type="member_of",
        properties={"member_type": "user"},
    )
    db.add(edge)
    db.commit()

    assert db.query(Node).filter(Node.scan_id == scan.id).count() == 2
    assert db.query(Edge).filter(Edge.scan_id == scan.id).count() == 1


def test_create_finding_with_attack_chain(db):
    scan = Scan(id=str(uuid.uuid4()), subscription_id="sub-y", status="completed")
    db.add(scan)
    db.commit()

    f = Finding(
        id=str(uuid.uuid4()),
        scan_id=scan.id,
        finding_type="privilege_escalation",
        severity="critical",
        title="Owner at subscription: TestUser",
        description="Test finding",
        attack_chain=[
            {"step": 1, "action": "Identity has Owner"},
            {"step": 2, "action": "Can assign roles"},
        ],
        why_risky="Owner = full control",
        remediation="Apply PIM",
        tags=["owner", "subscription"],
        risk_score=9.0,
        blast_radius=100,
    )
    db.add(f)
    db.commit()

    retrieved = db.query(Finding).filter(Finding.scan_id == scan.id).first()
    assert retrieved.severity == "critical"
    assert len(retrieved.attack_chain) == 2
    assert retrieved.tags == ["owner", "subscription"]


def test_tenant_config_crud(db):
    t = TenantConfig(
        id=str(uuid.uuid4()),
        display_name="Contoso",
        tenant_id="tenant-contoso",
        subscription_ids=["sub-001", "sub-002"],
        notes="Main tenant",
    )
    db.add(t)
    db.commit()

    got = db.query(TenantConfig).filter(TenantConfig.display_name == "Contoso").first()
    assert got is not None
    assert got.subscription_ids == ["sub-001", "sub-002"]

    # Update
    got.subscription_ids = ["sub-001"]
    db.commit()
    updated = db.query(TenantConfig).filter(TenantConfig.id == t.id).first()
    assert updated.subscription_ids == ["sub-001"]

    # Delete
    db.delete(updated)
    db.commit()
    assert db.query(TenantConfig).filter(TenantConfig.display_name == "Contoso").first() is None


# ──────────────────────────────────────────────────────────────
# Graph builder smoke test
# ──────────────────────────────────────────────────────────────

def test_build_graph_from_db(db):
    from backend.graph.builder import build_graph, graph_to_cytoscape

    scan = Scan(id=str(uuid.uuid4()), subscription_id="sub-g", status="completed")
    db.add(scan)
    db.commit()

    nodes_data = [
        ("user-a", "user",  "Alice"),
        ("group-a", "group", "Admins"),
        ("rd-owner", "role_definition", "Owner"),
    ]
    for nid, ntype, name in nodes_data:
        db.add(Node(
            id=str(uuid.uuid4()), scan_id=scan.id,
            node_id=nid, node_type=ntype, name=name, display_name=name,
            risk_level="safe", risk_score=0.0,
        ))
    db.add(Edge(
        id=str(uuid.uuid4()), scan_id=scan.id,
        source_node_id="user-a", target_node_id="group-a",
        edge_type="member_of", properties={},
    ))
    db.add(Edge(
        id=str(uuid.uuid4()), scan_id=scan.id,
        source_node_id="user-a", target_node_id="rd-owner",
        edge_type="has_role", properties={"role_name": "Owner", "scope": "/subscriptions/x"},
    ))
    db.commit()

    G = build_graph(scan.id, db)
    assert G.number_of_nodes() == 3
    assert G.number_of_edges() == 2
    assert G.has_edge("user-a", "rd-owner")

    cyto = graph_to_cytoscape(scan.id, db)
    assert len(cyto["elements"]["nodes"]) == 3
    assert len(cyto["elements"]["edges"]) == 2
    assert cyto["stats"]["total_nodes"] == 3


# ──────────────────────────────────────────────────────────────
# Effective permissions engine
# ──────────────────────────────────────────────────────────────

def test_effective_permissions_group_inheritance():
    from backend.analyzers.effective_permissions import EffectivePermissionEngine

    role_assignments = [
        {"principal_id": "group-admins", "role_name": "Owner",
         "role_definition_id": "8e3af657", "scope": "/subscriptions/x",
         "scope_level": "subscription", "principal_type": "Group"},
    ]
    group_memberships = {
        "group-admins": [{"id": "user-alice", "type": "user"}]
    }

    engine = EffectivePermissionEngine(role_assignments, group_memberships)
    alice_perms = engine.compute("user-alice")

    assert len(alice_perms) == 1
    assert alice_perms[0]["role_name"] == "Owner"
    assert alice_perms[0]["inherited_from"] == "group-admins"


def test_effective_permissions_direct_only():
    from backend.analyzers.effective_permissions import EffectivePermissionEngine

    role_assignments = [
        {"principal_id": "user-bob", "role_name": "Contributor",
         "role_definition_id": "b24988ac", "scope": "/subscriptions/x",
         "scope_level": "subscription", "principal_type": "User"},
    ]
    engine = EffectivePermissionEngine(role_assignments, {})
    bob_perms = engine.compute("user-bob")

    assert len(bob_perms) == 1
    assert bob_perms[0]["inherited_from"] is None


def test_effective_permissions_nested_groups():
    """User → GroupA → GroupB → role: transitive resolution."""
    from backend.analyzers.effective_permissions import EffectivePermissionEngine

    role_assignments = [
        {"principal_id": "group-b", "role_name": "Reader",
         "role_definition_id": "acdd72a7", "scope": "/subscriptions/x",
         "scope_level": "subscription", "principal_type": "Group"},
    ]
    group_memberships = {
        "group-b": [{"id": "group-a", "type": "group"}],
        "group-a": [{"id": "user-charlie", "type": "user"}],
    }

    engine = EffectivePermissionEngine(role_assignments, group_memberships)
    charlie_perms = engine.compute("user-charlie")

    assert len(charlie_perms) == 1
    assert charlie_perms[0]["role_name"] == "Reader"
