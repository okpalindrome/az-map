"""
Builds a NetworkX DiGraph from the DB for a given scan_id.
Also provides serialization to Cytoscape.js format.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..models.db_models import Edge, Node

logger = logging.getLogger(__name__)

# Node type → color
# Chosen for legibility on a white background; avoids purple which blends poorly.
NODE_COLORS: dict[str, str] = {
    "user": "#2563EB",               # blue-600
    "group": "#0891B2",              # cyan-600
    "service_principal": "#EA580C",  # orange-600
    "managed_identity": "#7C3AED",   # violet-600
    "subscription": "#1D4ED8",       # blue-700 (darker than user)
    "resource_group": "#93C5FD",     # blue-300 (light, structural)
    "storage_account": "#16A34A",    # green-600
    "key_vault": "#DC2626",          # red-600 (sensitive — stands out)
    "function_app": "#D97706",       # amber-600
    "app_service": "#CA8A04",        # yellow-600
    "automation_account": "#9333EA", # purple-600
    "vm": "#475569",                 # slate-600
    "role_definition": "#6B7280",    # gray-500
    "unknown": "#D1D5DB",            # gray-300
}

NODE_SHAPES: dict[str, str] = {
    "user": "ellipse",
    "group": "hexagon",
    "service_principal": "diamond",
    "managed_identity": "round-diamond",
    "subscription": "star",
    "resource_group": "round-rectangle",
    "storage_account": "rectangle",
    "key_vault": "pentagon",
    "function_app": "round-triangle",
    "role_definition": "triangle",
}

RISK_BORDER_COLORS: dict[str, str] = {
    "critical": "#F44336",
    "risky": "#FF9800",
    "safe": "#9E9E9E",
}


def build_graph(scan_id: str, db: Session):
    """Build a NetworkX DiGraph for a scan."""
    import networkx as nx

    G = nx.DiGraph()

    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    for n in nodes:
        G.add_node(n.node_id, **{
            "db_id": n.id,
            "node_type": n.node_type,
            "name": n.name,
            "display_name": n.display_name,
            "risk_score": n.risk_score,
            "risk_level": n.risk_level,
            "risk_reasons": n.risk_reasons or [],
            "properties": n.properties or {},
        })

    edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()
    for e in edges:
        G.add_edge(e.source_node_id, e.target_node_id, **{
            "db_id": e.id,
            "edge_type": e.edge_type,
            "properties": e.properties or {},
        })

    return G


def graph_to_cytoscape(
    scan_id: str,
    db: Session,
    node_types: Optional[list[str]] = None,
    risk_levels: Optional[list[str]] = None,
    search: Optional[str] = None,
    limit: int = 2000,
) -> dict:
    """
    Serialize DB graph to Cytoscape.js elements format with filtering.
    Returns {"elements": {"nodes": [...], "edges": [...]}}
    """
    node_query = db.query(Node).filter(Node.scan_id == scan_id)
    if node_types:
        node_query = node_query.filter(Node.node_type.in_(node_types))
    if risk_levels:
        node_query = node_query.filter(Node.risk_level.in_(risk_levels))
    if search:
        s = f"%{search.lower()}%"
        from sqlalchemy import or_, func
        node_query = node_query.filter(
            or_(
                func.lower(Node.name).like(s),
                func.lower(Node.display_name).like(s),
                Node.node_id.like(s),
            )
        )

    nodes = node_query.order_by(Node.risk_score.desc()).limit(limit).all()
    visible_ids = {n.node_id for n in nodes}

    cy_nodes = []
    for n in nodes:
        color = NODE_COLORS.get(n.node_type, NODE_COLORS["unknown"])
        shape = NODE_SHAPES.get(n.node_type, "ellipse")
        border_color = RISK_BORDER_COLORS.get(n.risk_level, RISK_BORDER_COLORS["safe"])
        label = n.display_name or n.name or n.node_id or ""
        if len(label) > 25:
            label = label[:23] + "..."
        is_owned = bool((n.properties or {}).get("is_owned"))
        cy_nodes.append({
            "data": {
                "id": n.node_id,
                "nodeLabel": label,
                "fullLabel": n.display_name or n.name,
                "nodeType": n.node_type,
                "riskLevel": n.risk_level,
                "riskScore": n.risk_score,
                "riskReasons": n.risk_reasons or [],
                "properties": n.properties or {},
                "color": color,
                "shape": shape,
                "borderColor": "#F59E0B" if is_owned else border_color,
                "borderWidth": 4 if is_owned else (3 if n.risk_level in ("critical", "risky") else 1),
                "isOwned": is_owned,
            },
            "classes": "owned" if is_owned else "",
        })

    edge_query = db.query(Edge).filter(
        Edge.scan_id == scan_id,
        Edge.source_node_id.in_(visible_ids),
        Edge.target_node_id.in_(visible_ids),
    )
    edges = edge_query.all()

    cy_edges = []
    for e in edges:
        cy_edges.append({
            "data": {
                "id": e.id,
                "source": e.source_node_id,
                "target": e.target_node_id,
                "edgeType": e.edge_type,
                "edgeLabel": _edge_label(e.edge_type, e.properties or {}),
                "properties": e.properties or {},
            }
        })

    return {
        "elements": {
            "nodes": cy_nodes,
            "edges": cy_edges,
        },
        "stats": {
            "total_nodes": len(cy_nodes),
            "total_edges": len(cy_edges),
            "critical_nodes": sum(1 for n in nodes if n.risk_level == "critical"),
            "risky_nodes": sum(1 for n in nodes if n.risk_level == "risky"),
        }
    }


def _edge_label(edge_type: str, props: dict) -> str:
    labels = {
        "has_role": props.get("role_name", "has_role"),
        "member_of": "member of",
        "contains": "contains",
        "assigned_to": "assigned to",
        "has_system_identity": "system identity",
        "can_escalate_to": "→ escalates",
        "has_entra_role": props.get("role_name", "entra role"),
    }
    return labels.get(edge_type, edge_type.replace("_", " "))
