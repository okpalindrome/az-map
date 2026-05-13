"""Export API: JSON (full scan) and CSV (findings)."""
import csv
import io
import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.db_models import Edge, Finding, Node, RoleAssignment, Scan

router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/{scan_id}/json")
def export_json(scan_id: str, db: Session = Depends(get_db)):
    scan, findings, nodes, edges, ras = _load_scan_data(scan_id, db)

    payload = {
        "az_map_version": "1.1",
        "exported_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": scan.id,
            "subscription_id": scan.subscription_id,
            "subscription_name": scan.subscription_name,
            "tenant_id": scan.tenant_id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_findings": len(findings),
            "critical_findings": sum(1 for f in findings if f.severity == "critical"),
            "high_findings": sum(1 for f in findings if f.severity == "high"),
        },
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "affected_node": f.affected_node_name,
                "affected_node_id": f.affected_node_id,
                "risk_score": f.risk_score,
                "blast_radius": f.blast_radius,
                "why_risky": f.why_risky,
                "remediation": f.remediation,
                "attack_chain": f.attack_chain,
                "tags": f.tags,
            }
            for f in sorted(findings, key=lambda x: x.risk_score, reverse=True)
        ],
        "nodes": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "name": n.name,
                "display_name": n.display_name,
                "risk_level": n.risk_level,
                "risk_score": n.risk_score,
                "risk_reasons": n.risk_reasons or [],
                "properties": n.properties or {},
            }
            for n in nodes
        ],
        "edges": [
            {
                "source_node_id": e.source_node_id,
                "target_node_id": e.target_node_id,
                "edge_type": e.edge_type,
                "properties": e.properties or {},
            }
            for e in edges
        ],
        "role_assignments": [
            {
                "principal_id": ra.principal_id,
                "principal_name": ra.principal_name,
                "principal_type": ra.principal_type,
                "role_name": ra.role_name,
                "scope": ra.scope,
                "scope_level": ra.scope_level,
            }
            for ra in ras
        ],
    }
    safe_name = re.sub(r'[^\w\-]', '_', scan.subscription_name or 'azmap')[:60]
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.json"'},
    )


@router.get("/{scan_id}/csv")
def export_csv(scan_id: str, db: Session = Depends(get_db)):
    scan, findings, nodes, edges, ras = _load_scan_data(scan_id, db)
    sub_name = scan.subscription_name or scan.subscription_id

    buf = io.StringIO()
    writer = csv.writer(buf)

    # ── Findings ──
    writer.writerow(["=== FINDINGS ==="])
    writer.writerow(["severity", "risk_score", "title", "type", "affected_resource", "affected_resource_id", "blast_radius", "subscription"])
    for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
        writer.writerow([
            f.severity, f.risk_score, f.title,
            f.finding_type.replace("_", " "),
            f.affected_node_name or "",
            f.affected_node_id or "",
            f.blast_radius,
            sub_name,
        ])

    writer.writerow([])
    # ── Inventory ──
    writer.writerow(["=== INVENTORY ==="])
    writer.writerow(["node_id", "node_type", "name", "display_name", "risk_level", "risk_score", "risk_reasons", "subscription"])
    for n in sorted(nodes, key=lambda x: x.risk_score, reverse=True):
        writer.writerow([
            n.node_id, n.node_type, n.name, n.display_name or "",
            n.risk_level, n.risk_score,
            "; ".join((n.risk_reasons or [])[:3]),
            sub_name,
        ])

    writer.writerow([])
    # ── Role Assignments ──
    writer.writerow(["=== ROLE ASSIGNMENTS ==="])
    writer.writerow(["principal_name", "principal_type", "principal_id", "role_name", "scope", "scope_level", "subscription"])
    for ra in ras:
        writer.writerow([
            ra.principal_name or "", ra.principal_type or "", ra.principal_id,
            ra.role_name or "", ra.scope, ra.scope_level or "",
            sub_name,
        ])

    safe_name = re.sub(r'[^\w\-]', '_', sub_name)[:60]
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_findings.csv"'},
    )


def _load_scan_data(scan_id: str, db: Session):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()
    ras = db.query(RoleAssignment).filter(RoleAssignment.scan_id == scan_id).all()
    return scan, findings, nodes, edges, ras
