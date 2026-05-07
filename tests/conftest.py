"""Shared pytest fixtures for az-map tests."""
import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models.db_models import (
    Edge, Finding, Node, RoleAssignment, RoleDefinition, Scan, TenantConfig,
)


@pytest.fixture(scope="function")
def db_session():
    """In-memory SQLite session, rolled back after each test."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


def make_scan(db, subscription_id="sub-1234", status="completed") -> Scan:
    """Create and persist a minimal Scan record."""
    s = Scan(
        id=str(uuid.uuid4()),
        subscription_id=subscription_id,
        subscription_name="Test Subscription",
        tenant_id="tenant-abc",
        status=status,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow() if status == "completed" else None,
        progress={},
    )
    db.add(s)
    db.commit()
    return s


def make_node(db, scan_id: str, node_id: str, node_type: str, name: str,
              risk_level: str = "safe", risk_score: float = 0.0,
              properties: dict = None) -> Node:
    n = Node(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        node_id=node_id,
        node_type=node_type,
        name=name,
        display_name=name,
        risk_level=risk_level,
        risk_score=risk_score,
        properties=properties or {},
    )
    db.add(n)
    db.commit()
    return n


def make_finding(db, scan_id: str, finding_type: str, severity: str,
                 title: str, risk_score: float = 5.0,
                 affected_node_id: str = None) -> Finding:
    f = Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        risk_score=risk_score,
        affected_node_id=affected_node_id,
        attack_chain=[],
        tags=[],
    )
    db.add(f)
    db.commit()
    return f
