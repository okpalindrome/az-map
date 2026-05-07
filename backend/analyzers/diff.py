"""
Scan Diff Engine.

Compares two completed scans for the same subscription and produces a
structured delta: new nodes, removed nodes, risk-changed nodes, new findings,
resolved findings.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.orm import Session

from ..models.db_models import Finding, Node, Scan

logger = logging.getLogger(__name__)


@dataclass
class NodeDelta:
    node_id: str
    node_type: str
    name: str
    display_name: str


@dataclass
class RiskChange:
    node_id: str
    node_type: str
    name: str
    display_name: str
    risk_level_before: str
    risk_level_after: str
    risk_score_before: float
    risk_score_after: float
    # positive = risk went up
    delta: float


@dataclass
class FindingDelta:
    id: str
    finding_type: str
    severity: str
    title: str
    affected_node_name: Optional[str]
    risk_score: float


@dataclass
class ScanDiff:
    scan_a_id: str
    scan_b_id: str
    scan_a_label: Optional[str]
    scan_b_label: Optional[str]
    scan_a_date: str
    scan_b_date: str

    # Nodes
    new_nodes: list[NodeDelta] = field(default_factory=list)
    removed_nodes: list[NodeDelta] = field(default_factory=list)
    risk_changed_nodes: list[RiskChange] = field(default_factory=list)

    # Findings
    new_findings: list[FindingDelta] = field(default_factory=list)
    resolved_findings: list[FindingDelta] = field(default_factory=list)

    # Summary
    @property
    def summary(self) -> dict:
        return {
            "new_nodes": len(self.new_nodes),
            "removed_nodes": len(self.removed_nodes),
            "risk_increased": sum(1 for r in self.risk_changed_nodes if r.delta > 0),
            "risk_decreased": sum(1 for r in self.risk_changed_nodes if r.delta < 0),
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
            "new_critical": sum(1 for f in self.new_findings if f.severity == "critical"),
            "new_high": sum(1 for f in self.new_findings if f.severity == "high"),
        }


def compute_diff(scan_a_id: str, scan_b_id: str, db: Session) -> ScanDiff:
    """
    Compute the diff between scan_a (older) and scan_b (newer).
    scan_a = baseline, scan_b = current.
    """
    scan_a = db.query(Scan).filter(Scan.id == scan_a_id).first()
    scan_b = db.query(Scan).filter(Scan.id == scan_b_id).first()
    if not scan_a or not scan_b:
        raise ValueError("One or both scans not found")

    diff = ScanDiff(
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        scan_a_label=scan_a.snapshot_label,
        scan_b_label=scan_b.snapshot_label,
        scan_a_date=scan_a.completed_at.isoformat() if scan_a.completed_at else "",
        scan_b_date=scan_b.completed_at.isoformat() if scan_b.completed_at else "",
    )

    # Load nodes by node_id
    nodes_a: dict[str, Node] = {
        n.node_id: n for n in db.query(Node).filter(Node.scan_id == scan_a_id).all()
    }
    nodes_b: dict[str, Node] = {
        n.node_id: n for n in db.query(Node).filter(Node.scan_id == scan_b_id).all()
    }

    ids_a = set(nodes_a)
    ids_b = set(nodes_b)

    # New nodes (in B but not A)
    for nid in ids_b - ids_a:
        n = nodes_b[nid]
        diff.new_nodes.append(NodeDelta(
            node_id=n.node_id,
            node_type=n.node_type,
            name=n.name,
            display_name=n.display_name or n.name,
        ))

    # Removed nodes (in A but not B)
    for nid in ids_a - ids_b:
        n = nodes_a[nid]
        diff.removed_nodes.append(NodeDelta(
            node_id=n.node_id,
            node_type=n.node_type,
            name=n.name,
            display_name=n.display_name or n.name,
        ))

    # Risk-changed nodes (same ID, different risk)
    _risk_order = {"safe": 0, "risky": 1, "critical": 2}
    for nid in ids_a & ids_b:
        na, nb = nodes_a[nid], nodes_b[nid]
        if na.risk_level != nb.risk_level or abs(na.risk_score - nb.risk_score) >= 0.5:
            diff.risk_changed_nodes.append(RiskChange(
                node_id=nid,
                node_type=nb.node_type,
                name=nb.name,
                display_name=nb.display_name or nb.name,
                risk_level_before=na.risk_level,
                risk_level_after=nb.risk_level,
                risk_score_before=na.risk_score,
                risk_score_after=nb.risk_score,
                delta=round(nb.risk_score - na.risk_score, 1),
            ))

    # Sort risk-changed: biggest risk increase first
    diff.risk_changed_nodes.sort(key=lambda x: x.delta, reverse=True)

    # Findings diff — match by (finding_type, title) as stable key
    def _finding_key(f: Finding) -> str:
        return f"{f.finding_type}|{f.title[:80]}"

    findings_a = {_finding_key(f): f for f in db.query(Finding).filter(Finding.scan_id == scan_a_id).all()}
    findings_b = {_finding_key(f): f for f in db.query(Finding).filter(Finding.scan_id == scan_b_id).all()}

    def _fdelta(f: Finding) -> FindingDelta:
        return FindingDelta(
            id=f.id,
            finding_type=f.finding_type,
            severity=f.severity,
            title=f.title,
            affected_node_name=f.affected_node_name,
            risk_score=f.risk_score,
        )

    for key in set(findings_b) - set(findings_a):
        diff.new_findings.append(_fdelta(findings_b[key]))

    for key in set(findings_a) - set(findings_b):
        diff.resolved_findings.append(_fdelta(findings_a[key]))

    # Sort new findings by severity
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    diff.new_findings.sort(key=lambda f: _sev_order.get(f.severity, 9))

    return diff


def diff_to_dict(d: ScanDiff) -> dict:
    return {
        "scan_a": {"id": d.scan_a_id, "label": d.scan_a_label, "date": d.scan_a_date},
        "scan_b": {"id": d.scan_b_id, "label": d.scan_b_label, "date": d.scan_b_date},
        "summary": d.summary,
        "new_nodes": [vars(n) for n in d.new_nodes],
        "removed_nodes": [vars(n) for n in d.removed_nodes],
        "risk_changed": [vars(r) for r in d.risk_changed_nodes],
        "new_findings": [vars(f) for f in d.new_findings],
        "resolved_findings": [vars(f) for f in d.resolved_findings],
    }
