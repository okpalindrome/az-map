"""Unit tests for scan diff engine."""
import pytest
from backend.analyzers.diff import compute_diff
from tests.conftest import make_finding, make_node, make_scan


def test_diff_new_nodes(db_session):
    """Nodes in B but not A appear as new_nodes."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_node(db_session, scan_a.id, "node-shared", "user", "SharedUser")
    make_node(db_session, scan_b.id, "node-shared", "user", "SharedUser")
    make_node(db_session, scan_b.id, "node-new", "service_principal", "NewSP")

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert len(diff.new_nodes) == 1
    assert diff.new_nodes[0].node_id == "node-new"
    assert len(diff.removed_nodes) == 0


def test_diff_removed_nodes(db_session):
    """Nodes in A but not B appear as removed_nodes."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_node(db_session, scan_a.id, "node-old", "user", "OldUser")
    make_node(db_session, scan_a.id, "node-keep", "group", "KeepGroup")
    make_node(db_session, scan_b.id, "node-keep", "group", "KeepGroup")

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert len(diff.removed_nodes) == 1
    assert diff.removed_nodes[0].node_id == "node-old"
    assert len(diff.new_nodes) == 0


def test_diff_risk_changed(db_session):
    """Node with changed risk level appears in risk_changed_nodes."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_node(db_session, scan_a.id, "node-x", "user", "User", risk_level="safe",   risk_score=1.0)
    make_node(db_session, scan_b.id, "node-x", "user", "User", risk_level="critical", risk_score=9.0)

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert len(diff.risk_changed_nodes) == 1
    rc = diff.risk_changed_nodes[0]
    assert rc.risk_level_before == "safe"
    assert rc.risk_level_after == "critical"
    assert rc.delta == pytest.approx(8.0)


def test_diff_no_changes(db_session):
    """Identical scans produce an empty diff."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_node(db_session, scan_a.id, "n1", "user", "Alice", risk_level="safe", risk_score=0.0)
    make_node(db_session, scan_b.id, "n1", "user", "Alice", risk_level="safe", risk_score=0.0)

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert diff.new_nodes == []
    assert diff.removed_nodes == []
    assert diff.risk_changed_nodes == []


def test_diff_new_findings(db_session):
    """Findings in B but not A appear as new_findings."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_finding(db_session, scan_a.id, "high_risk_role", "high", "Owner at sub: Alice")
    make_finding(db_session, scan_b.id, "high_risk_role", "high", "Owner at sub: Alice")
    make_finding(db_session, scan_b.id, "privilege_escalation", "critical", "New escalation: Bob")

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert len(diff.new_findings) == 1
    assert "Bob" in diff.new_findings[0].title


def test_diff_resolved_findings(db_session):
    """Findings in A but not B appear as resolved_findings."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_finding(db_session, scan_a.id, "high_risk_role", "critical", "Owner: Charlie")
    make_finding(db_session, scan_a.id, "excessive_privilege", "high", "Over-privileged: Dave")
    make_finding(db_session, scan_b.id, "excessive_privilege", "high", "Over-privileged: Dave")

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    assert len(diff.resolved_findings) == 1
    assert "Charlie" in diff.resolved_findings[0].title


def test_diff_summary(db_session):
    """Summary dict contains correct counts."""
    scan_a = make_scan(db_session)
    scan_b = make_scan(db_session)

    make_node(db_session, scan_b.id, "brand-new", "storage_account", "NewStorage")
    make_finding(db_session, scan_b.id, "privilege_escalation", "critical", "New Critical: X")

    diff = compute_diff(scan_a.id, scan_b.id, db_session)
    s = diff.summary
    assert s["new_nodes"] == 1
    assert s["removed_nodes"] == 0
    assert s["new_findings"] == 1
    assert s["new_critical"] == 1


def test_diff_invalid_scan_raises(db_session):
    """Non-existent scan IDs raise ValueError."""
    with pytest.raises(ValueError, match="not found"):
        compute_diff("nonexistent-a", "nonexistent-b", db_session)
