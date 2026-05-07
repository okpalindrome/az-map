"""SQLAlchemy ORM models for az-map."""
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator, TEXT
import json

from ..database import Base


class JSONType(TypeDecorator):
    """Stores Python dicts/lists as JSON text in SQLite."""
    impl = TEXT
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return None


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Scan — top-level scan session record
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    subscription_id = Column(String, nullable=False, index=True)
    subscription_name = Column(String)
    tenant_id = Column(String)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")  # running | completed | failed
    error = Column(Text, nullable=True)
    # JSON progress object: {phase: str, current: int, total: int, message: str}
    progress = Column(JSONType, default=dict)
    # Snapshot label for diff/compare mode
    snapshot_label = Column(String, nullable=True)

    nodes = relationship("Node", back_populates="scan", cascade="all, delete-orphan")
    edges = relationship("Edge", back_populates="scan", cascade="all, delete-orphan")
    role_definitions = relationship("RoleDefinition", back_populates="scan", cascade="all, delete-orphan")
    role_assignments = relationship("RoleAssignment", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# TenantConfig — saved tenant / subscription bookmarks
# ---------------------------------------------------------------------------

class TenantConfig(Base):
    __tablename__ = "tenant_configs"

    id = Column(String, primary_key=True, default=_uuid)
    display_name = Column(String, nullable=False)
    tenant_id = Column(String, nullable=True)
    # JSON list of subscription IDs belonging to this tenant config
    subscription_ids = Column(JSONType, default=list)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("display_name", name="uq_tenant_display_name"),
    )


# ---------------------------------------------------------------------------
# Node — every identity and resource in the graph
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "user",
    "group",
    "service_principal",
    "managed_identity",
    "subscription",
    "resource_group",
    "storage_account",
    "key_vault",
    "function_app",
    "app_service",
    "automation_account",
    "vm",
    "role_definition",
    "unknown",
}

RISK_LEVELS = {"safe", "risky", "critical"}


class Node(Base):
    __tablename__ = "nodes"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)

    # Stable Azure identifier (object_id / resource_id)
    node_id = Column(String, nullable=False, index=True)
    node_type = Column(String, nullable=False, index=True)

    name = Column(String, nullable=False)
    display_name = Column(String)
    # Extra type-specific data (upn, app_id, subscription_id, location, kind, etc.)
    properties = Column(JSONType, default=dict)

    # Risk assessment (populated by analyzers)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="safe")  # safe | risky | critical
    risk_reasons = Column(JSONType, default=list)

    scan = relationship("Scan", back_populates="nodes")

    __table_args__ = (
        UniqueConstraint("scan_id", "node_id", name="uq_node_scan_node"),
    )


# ---------------------------------------------------------------------------
# Edge — directed relationship between two nodes
# ---------------------------------------------------------------------------

EDGE_TYPES = {
    "has_role",        # principal → role_definition (via role assignment at scope)
    "member_of",       # user/SP → group
    "assigned_to",     # managed_identity → resource (assigned/used by)
    "owns",            # SP/app → resource
    "contains",        # subscription → RG, RG → resource
    "can_access",      # derived effective access
    "can_escalate_to", # derived priv-esc path
    "app_of",          # service_principal → application object
}


class Edge(Base):
    __tablename__ = "edges"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)

    source_node_id = Column(String, nullable=False, index=True)  # references Node.node_id
    target_node_id = Column(String, nullable=False, index=True)
    edge_type = Column(String, nullable=False)
    # e.g. {"scope": "/subscriptions/...", "role_name": "Owner", "assignment_id": "..."}
    properties = Column(JSONType, default=dict)

    scan = relationship("Scan", back_populates="edges")


# ---------------------------------------------------------------------------
# RoleDefinition — Azure RBAC role definitions collected from subscription
# ---------------------------------------------------------------------------

class RoleDefinition(Base):
    __tablename__ = "role_definitions"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)

    role_id = Column(String, nullable=False)  # Azure role definition ID (GUID)
    name = Column(String, nullable=False)
    description = Column(Text)
    # {"actions": [...], "not_actions": [...], "data_actions": [...]}
    permissions = Column(JSONType, default=dict)
    is_builtin = Column(Boolean, default=True)
    # Pre-computed: owner/contributor/reader/custom
    privilege_level = Column(String, default="unknown")

    scan = relationship("Scan", back_populates="role_definitions")

    __table_args__ = (
        UniqueConstraint("scan_id", "role_id", name="uq_roledef_scan_role"),
    )


# ---------------------------------------------------------------------------
# RoleAssignment — Azure RBAC role assignments
# ---------------------------------------------------------------------------

class RoleAssignment(Base):
    __tablename__ = "role_assignments"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)

    assignment_id = Column(String, nullable=False)
    principal_id = Column(String, nullable=False, index=True)
    principal_type = Column(String)  # User | Group | ServicePrincipal | Unknown
    principal_name = Column(String)
    role_definition_id = Column(String, nullable=False)
    role_name = Column(String)
    scope = Column(String, nullable=False)
    # Derived scope level: subscription | resource_group | resource
    scope_level = Column(String)

    scan = relationship("Scan", back_populates="role_assignments")

    __table_args__ = (
        UniqueConstraint("scan_id", "assignment_id", name="uq_ra_scan_assign"),
    )


# ---------------------------------------------------------------------------
# Finding — security findings produced by analyzers
# ---------------------------------------------------------------------------

FINDING_TYPES = {
    "privilege_escalation",
    "excessive_privilege",
    "lateral_movement",
    "dangerous_role_combo",
    "misconfigured_identity",
    "high_risk_role",
    "sensitive_resource_access",
    "persistence_risk",
    "over_privileged_sp",
    "over_privileged_group",
}

SEVERITIES = {"critical", "high", "medium", "low", "info"}


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)

    finding_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)  # critical|high|medium|low|info
    title = Column(String, nullable=False)
    description = Column(Text)

    # Primary affected resource
    affected_node_id = Column(String, nullable=True)
    affected_node_name = Column(String, nullable=True)

    # Attack chain as list of {node_id, node_name, action} dicts
    attack_chain = Column(JSONType, default=list)
    # Why this is risky (short)
    why_risky = Column(Text)
    # Step-by-step remediation
    remediation = Column(Text)
    # MITRE ATT&CK or custom tags
    tags = Column(JSONType, default=list)

    risk_score = Column(Float, default=0.0)
    # Blast radius: how many resources/identities are at risk
    blast_radius = Column(Integer, default=0)

    scan = relationship("Scan", back_populates="findings")
