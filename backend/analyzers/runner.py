"""
Analyzer runner: coordinates all analyzers, writes Finding rows to DB.
"""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict

from sqlalchemy.orm import Session

from ..models.db_models import Finding, Node, RoleAssignment
from .effective_permissions import EffectivePermissionEngine
from .privilege_escalation import PrivilegeEscalationAnalyzer
from .risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


def run_all_analyzers(
    scan_id: str,
    db: Session,
    rbac_data: dict,
    graph_data: dict,
    role_name_map: dict,
):
    """Main entry: runs all analyzers and persists findings + node risk scores."""

    role_assignments = rbac_data.get("role_assignments", [])
    group_memberships = graph_data.get("group_memberships", {})
    service_principals = graph_data.get("service_principals", [])
    directory_roles = graph_data.get("directory_roles", [])

    # ------------------------------------------------------------------
    # 1. Effective permissions
    # ------------------------------------------------------------------
    perm_engine = EffectivePermissionEngine(role_assignments, group_memberships)

    # Collect all principal IDs from DB
    all_nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    principal_types = {"user", "group", "service_principal", "managed_identity"}
    principal_ids = [n.node_id for n in all_nodes if n.node_type in principal_types]

    principal_effective_roles = perm_engine.compute_all(principal_ids)

    # ------------------------------------------------------------------
    # 2. Risk scoring — update Node records
    # ------------------------------------------------------------------
    scorer = RiskScorer(
        principal_effective_roles=principal_effective_roles,
        directory_roles=directory_roles,
        group_memberships=group_memberships,
        service_principals=service_principals,
    )
    node_map = {n.node_id: n for n in all_nodes}
    for n in all_nodes:
        if n.node_type in principal_types:
            result = scorer.score_principal(n.node_id, n.node_type)
            n.risk_score = result["risk_score"]
            n.risk_level = result["risk_level"]
            n.risk_reasons = result["risk_reasons"]
    db.commit()

    # ------------------------------------------------------------------
    # 3. Privilege escalation rules
    # ------------------------------------------------------------------
    # Build resource context for rules
    def _nodes_of_type(t: str) -> list[dict]:
        return [
            {**n.properties, "id": n.node_id, "name": n.name}
            for n in all_nodes if n.node_type == t
        ]

    resource_nodes_dict = {n.node_id: {"name": n.name, "display_name": n.display_name,
                                        "node_type": n.node_type} for n in all_nodes}

    context = {
        "role_assignments": role_assignments,
        "principal_effective_roles": principal_effective_roles,
        "resource_nodes": resource_nodes_dict,
        "service_principals": service_principals,
        "function_apps": _nodes_of_type("function_app"),
        "virtual_machines": _nodes_of_type("vm"),
        "automation_accounts": _nodes_of_type("automation_account"),
        "key_vaults": _nodes_of_type("key_vault"),
        "directory_roles": directory_roles,
        # Checkpoint 2 rules
        "group_memberships_raw": graph_data.get("group_memberships", {}),
        "app_registrations": graph_data.get("app_registrations", []),
        # Checkpoint 3 rules
        "ca_policies": graph_data.get("ca_policies", []),
        "runbooks": rbac_data.get("runbooks", []),
        # Checkpoint 4 rules
        "storage_accounts": _nodes_of_type("storage_account"),
        "policy_assignments": rbac_data.get("policy_assignments", []),
    }

    priv_analyzer = PrivilegeEscalationAnalyzer(context)
    raw_findings = priv_analyzer.run_all()

    # Deduplicate by (finding_type, affected_node_id, title)
    seen: set = set()
    for f in raw_findings:
        key = (f["finding_type"], f.get("affected_node_id", ""), f["title"][:80])
        if key in seen:
            continue
        seen.add(key)
        db.add(Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            finding_type=f["finding_type"],
            severity=f["severity"],
            title=f["title"],
            description=f.get("description", ""),
            affected_node_id=f.get("affected_node_id"),
            affected_node_name=f.get("affected_node_name"),
            attack_chain=f.get("attack_chain", []),
            why_risky=f.get("why_risky", ""),
            remediation=f.get("remediation", ""),
            tags=f.get("tags", []),
            risk_score=f.get("risk_score", 0.0),
            blast_radius=f.get("blast_radius", 0),
        ))

    db.commit()
    logger.info(f"Scan {scan_id}: {len(raw_findings)} findings generated")
