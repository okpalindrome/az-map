"""Graph data API: cytoscape elements, node detail, path queries."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..graph.builder import graph_to_cytoscape, build_graph
from ..models.db_models import Edge, Node, Scan

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("/{scan_id}/elements")
def get_graph_elements(
    scan_id: str,
    node_types: Optional[str] = Query(None, description="Comma-separated node types to include"),
    risk_levels: Optional[str] = Query(None, description="Comma-separated risk levels: safe,risky,critical"),
    search: Optional[str] = Query(None, description="Search string for node name/id", max_length=200),
    db: Session = Depends(get_db),
):
    """Return Cytoscape.js-ready graph elements for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    nt = [t.strip() for t in node_types.split(",")] if node_types else None
    rl = [l.strip() for l in risk_levels.split(",")] if risk_levels else None

    return graph_to_cytoscape(scan_id, db, node_types=nt, risk_levels=rl, search=search)


@router.get("/{scan_id}/node/{node_id}")
def get_node_detail(scan_id: str, node_id: str, db: Session = Depends(get_db)):
    """Return full detail for a single node including its edges."""
    node = db.query(Node).filter(
        Node.scan_id == scan_id, Node.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(404, "Node not found")

    out_edges = db.query(Edge).filter(
        Edge.scan_id == scan_id, Edge.source_node_id == node_id
    ).all()
    in_edges = db.query(Edge).filter(
        Edge.scan_id == scan_id, Edge.target_node_id == node_id
    ).all()

    def _edge_dict(e: Edge, direction: str) -> dict:
        other_id = e.target_node_id if direction == "outbound" else e.source_node_id
        other = db.query(Node).filter(Node.scan_id == scan_id, Node.node_id == other_id).first()
        return {
            "direction": direction,
            "edge_type": e.edge_type,
            "other_node_id": other_id,
            "other_node_name": other.display_name or other.name if other else other_id,
            "other_node_type": other.node_type if other else "unknown",
            "properties": e.properties or {},
        }

    return {
        "node_id": node.node_id,
        "node_type": node.node_type,
        "name": node.name,
        "display_name": node.display_name,
        "risk_score": node.risk_score,
        "risk_level": node.risk_level,
        "risk_reasons": node.risk_reasons or [],
        "properties": node.properties or {},
        "relationships": (
            [_edge_dict(e, "outbound") for e in out_edges]
            + [_edge_dict(e, "inbound") for e in in_edges]
        ),
    }


@router.get("/{scan_id}/paths")
def get_attack_paths(
    scan_id: str,
    from_node: Optional[str] = Query(None),
    to_node: Optional[str] = Query(None),
    max_depth: int = Query(5, ge=1, le=8),
    db: Session = Depends(get_db),
):
    """Find attack paths between nodes using NetworkX."""
    from ..analyzers.attack_paths import AttackPathAnalyzer

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    G = build_graph(scan_id, db)
    analyzer = AttackPathAnalyzer(G)

    if from_node and to_node:
        paths = analyzer.find_paths_to_target(from_node, [to_node], max_depth)
    elif from_node:
        paths = analyzer.find_lateral_movement(from_node, max_depth)
    else:
        # Find all escalation paths to Owner-equivalent nodes
        import networkx as nx
        owner_nodes = [
            nid for nid, data in G.nodes(data=True)
            if data.get("node_type") == "role_definition"
            and "owner" in data.get("name", "").lower()
        ]
        paths = analyzer.find_all_escalation_paths(owner_nodes)

    return {"paths": paths[:100]}  # cap at 100 for performance


@router.get("/{scan_id}/stats")
def get_graph_stats(scan_id: str, db: Session = Depends(get_db)):
    """Return high-level stats for the scan graph."""
    from sqlalchemy import func
    from ..models.db_models import Finding, RoleAssignment

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    node_counts = (
        db.query(Node.node_type, func.count(Node.id))
        .filter(Node.scan_id == scan_id)
        .group_by(Node.node_type)
        .all()
    )
    risk_counts = (
        db.query(Node.risk_level, func.count(Node.id))
        .filter(Node.scan_id == scan_id)
        .group_by(Node.risk_level)
        .all()
    )
    finding_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )

    total_ra = db.query(func.count(RoleAssignment.id)).filter(
        RoleAssignment.scan_id == scan_id
    ).scalar()

    return {
        "scan_id": scan_id,
        "subscription_id": scan.subscription_id,
        "subscription_name": scan.subscription_name,
        "status": scan.status,
        "node_counts": {t: c for t, c in node_counts},
        "risk_counts": {l: c for l, c in risk_counts},
        "finding_counts": {s: c for s, c in finding_counts},
        "total_role_assignments": total_ra,
    }
