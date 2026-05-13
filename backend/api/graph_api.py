"""Graph data API: cytoscape elements, node detail, path queries, owned nodes."""
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..graph.builder import graph_to_cytoscape, build_graph
from ..models.db_models import Edge, Node, Scan

router = APIRouter(prefix="/api/graph", tags=["graph"])

# In-memory graph cache: scan_id → (G, timestamp)
_graph_cache: dict[str, tuple] = {}
_CACHE_TTL = 300  # 5 minutes


def _get_cached_graph(scan_id: str, db: Session):
    now = time.time()
    if scan_id in _graph_cache:
        G, ts = _graph_cache[scan_id]
        if now - ts < _CACHE_TTL:
            return G
    G = build_graph(scan_id, db)
    _graph_cache[scan_id] = (G, now)
    return G


def _invalidate_cache(scan_id: str):
    _graph_cache.pop(scan_id, None)


@router.get("/{scan_id}/elements")
def get_graph_elements(
    scan_id: str,
    node_types: Optional[str] = Query(None),
    risk_levels: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=200),
    limit: int = Query(2000, ge=100, le=10000),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    nt = [t.strip() for t in node_types.split(",")] if node_types else None
    rl = [l.strip() for l in risk_levels.split(",")] if risk_levels else None

    return graph_to_cytoscape(scan_id, db, node_types=nt, risk_levels=rl, search=search, limit=limit)


@router.get("/{scan_id}/inventory")
def get_inventory(
    scan_id: str,
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    node_type: Optional[str] = Query(None),
    sort_by: str = Query("risk_score", enum=["risk_score", "name", "node_type"]),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    q = db.query(Node).filter(Node.scan_id == scan_id)
    if node_type:
        types = [t.strip() for t in node_type.split(",")]
        q = q.filter(Node.node_type.in_(types))

    order_col = {
        "risk_score": Node.risk_score.desc(),
        "name": Node.name,
        "node_type": Node.node_type,
    }[sort_by]

    total = q.count()
    nodes = q.order_by(order_col).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "nodes": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "name": n.name,
                "display_name": n.display_name,
                "risk_score": n.risk_score,
                "risk_level": n.risk_level,
                "risk_reasons": n.risk_reasons or [],
            }
            for n in nodes
        ],
    }


@router.get("/{scan_id}/node/{node_id}")
def get_node_detail(scan_id: str, node_id: str, db: Session = Depends(get_db)):
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

    props = node.properties or {}
    return {
        "node_id": node.node_id,
        "node_type": node.node_type,
        "name": node.name,
        "display_name": node.display_name,
        "risk_score": node.risk_score,
        "risk_level": node.risk_level,
        "risk_reasons": node.risk_reasons or [],
        "properties": props,
        "is_owned": bool(props.get("is_owned")),
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
    max_depth: int = Query(4, ge=1, le=6),
    db: Session = Depends(get_db),
):
    from ..analyzers.attack_paths import AttackPathAnalyzer

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    G = _get_cached_graph(scan_id, db)
    analyzer = AttackPathAnalyzer(G)

    if from_node and to_node:
        paths = analyzer.find_paths_to_target(from_node, [to_node], max_depth)
    elif from_node:
        paths = analyzer.find_lateral_movement(from_node, max_depth)
    else:
        owner_nodes = [
            nid for nid, data in G.nodes(data=True)
            if data.get("node_type") == "role_definition"
            and "owner" in data.get("name", "").lower()
        ]
        paths = analyzer.find_all_escalation_paths(owner_nodes)

    return {"paths": paths[:50]}


@router.get("/{scan_id}/paths-from-owned")
def get_paths_from_owned(
    scan_id: str,
    max_depth: int = Query(4, ge=1, le=6),
    db: Session = Depends(get_db),
):
    """Find attack paths from all nodes marked as owned in this scan."""
    from ..analyzers.attack_paths import AttackPathAnalyzer

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    owned_nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    owned_ids = [n.node_id for n in owned_nodes if (n.properties or {}).get("is_owned")]

    if not owned_ids:
        return {"paths": [], "owned_nodes": []}

    G = _get_cached_graph(scan_id, db)
    analyzer = AttackPathAnalyzer(G)

    all_paths = []
    for node_id in owned_ids:
        paths = analyzer.find_lateral_movement(node_id, max_depth)
        all_paths.extend(paths[:10])

    return {"paths": all_paths[:100], "owned_nodes": owned_ids}


class OwnedRequest(BaseModel):
    node_id: str
    owned: bool = True


@router.post("/{scan_id}/owned")
def set_node_owned(scan_id: str, body: OwnedRequest, db: Session = Depends(get_db)):
    """Mark or unmark a node as owned/pwned."""
    node = db.query(Node).filter(
        Node.scan_id == scan_id, Node.node_id == body.node_id
    ).first()
    if not node:
        raise HTTPException(404, "Node not found")
    props = dict(node.properties or {})
    props["is_owned"] = body.owned
    node.properties = props
    db.commit()
    _invalidate_cache(scan_id)
    return {"node_id": body.node_id, "is_owned": body.owned}


@router.get("/{scan_id}/owned")
def get_owned_nodes(scan_id: str, db: Session = Depends(get_db)):
    """Return all node IDs marked as owned in this scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    return {
        "owned_nodes": [
            {"node_id": n.node_id, "node_type": n.node_type, "name": n.display_name or n.name}
            for n in nodes if (n.properties or {}).get("is_owned")
        ]
    }


@router.get("/{scan_id}/stats")
def get_graph_stats(scan_id: str, db: Session = Depends(get_db)):
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
        "tenant_id": scan.tenant_id,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "snapshot_label": scan.snapshot_label,
        "node_counts": {t: c for t, c in node_counts},
        "risk_counts": {l: c for l, c in risk_counts},
        "finding_counts": {s: c for s, c in finding_counts},
        "total_role_assignments": total_ra,
    }
