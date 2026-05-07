"""
Orchestrates a full scan: runs collectors, persists nodes/edges/role data,
then triggers analyzers.
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Callable, Optional

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models.db_models import (
    Edge, Finding, Node, RoleAssignment, RoleDefinition, Scan,
)
from .azure_collector import AzureCollector
from .rbac_collector import RBACCollector
from .graph_collector import GraphCollector

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Full scan pipeline: collect → persist → analyze."""

    def __init__(
        self,
        scan_id: str,
        subscription_id: str,
        db: Session,
        reuse_collection: bool = False,
    ):
        self.scan_id = scan_id
        self.subscription_id = subscription_id
        self.db = db
        self.reuse_collection = reuse_collection
        self._progress: dict = {}
        self._subscribers: list[asyncio.Queue] = []

    # ------------------------------------------------------------------
    # Progress / SSE helpers
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def _publish(self, phase: str, message: str, current: int = 0, total: int = 0):
        self._progress = {
            "phase": phase,
            "message": message,
            "current": current,
            "total": total,
        }
        # Update DB progress
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan:
            scan.progress = self._progress
            self.db.commit()
        for q in list(self._subscribers):
            try:
                q.put_nowait(self._progress.copy())
            except asyncio.QueueFull:
                pass

    def _progress_callback(self, phase: str, message: str, current: int = 0, total: int = 0):
        self._publish(phase, message, current, total)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> str:
        """Execute full scan. Returns scan_id."""
        db = self.db
        scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError(f"Scan {self.scan_id} not found")

        try:
            async with httpx.AsyncClient(timeout=settings.api_timeout) as client:
                self._publish("init", "Initializing scan...", 0, 5)

                # --- 1. Collect (or reuse cached collection) ---
                if self.reuse_collection:
                    cached = self._find_cached_scan()
                    if cached:
                        self._publish("collect", f"Reusing collection from scan {cached.id[:8]}…", 1, 5)
                        nodes, role_name_map = await asyncio.to_thread(self._copy_collection, cached)
                        # Pull rbac/graph data from cache for analyzer
                        rbac_data, graph_data = await asyncio.to_thread(self._load_rbac_graph_from_db)
                        scan.subscription_name = cached.subscription_name
                        scan.tenant_id = cached.tenant_id
                        db.commit()
                        # Jump straight to analyze
                        self._publish("analyze", "Running security analysis...", 3, 5)
                        await asyncio.to_thread(self._run_analyzers, nodes, rbac_data, graph_data, role_name_map)
                        scan.status = "completed"
                        scan.completed_at = datetime.utcnow()
                        scan.progress = {"phase": "done", "message": "Scan complete (cached)", "current": 5, "total": 5}
                        db.commit()
                        self._publish("done", "Scan complete (cached collection)", 5, 5)
                        return self.scan_id

                azure_col = AzureCollector(self.subscription_id, self._progress_callback)
                rbac_col = RBACCollector(self.subscription_id, self._progress_callback)
                graph_col = GraphCollector(self._progress_callback)

                self._publish("collect", "Collecting Azure resources and identities...", 1, 5)
                azure_data, rbac_data, graph_data = await asyncio.gather(
                    azure_col.collect_all(client),
                    rbac_col.collect_all(client),
                    graph_col.collect_all(client),
                )

                # Update subscription metadata on scan record
                sub_info = azure_data.get("subscription", {})
                scan.subscription_name = sub_info.get("display_name", "")
                scan.tenant_id = (
                    sub_info.get("tenant_id")
                    or graph_data.get("tenant_info", {}).get("tenant_id", "")
                )
                db.commit()

                # Merge runbooks + policy_assignments into rbac_data for analyzer context
                rbac_data["runbooks"] = azure_data.get("runbooks", [])
                rbac_data["policy_assignments"] = azure_data.get("policy_assignments", [])
                # Merge CA policies into graph_data
                graph_data["ca_policies"] = graph_data.get("ca_policies", [])

                # --- 2. Persist ---
                self._publish("persist", "Persisting collected data...", 2, 5)
                nodes, role_name_map = await asyncio.to_thread(
                    self._persist_all, azure_data, rbac_data, graph_data
                )

                # --- 3. Analyze ---
                self._publish("analyze", "Running security analysis...", 3, 5)
                await asyncio.to_thread(self._run_analyzers, nodes, rbac_data, graph_data, role_name_map)

                # --- 4. Done ---
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.progress = {"phase": "done", "message": "Scan complete", "current": 5, "total": 5}
                db.commit()
                self._publish("done", "Scan complete", 5, 5)

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed: {e}")
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
            self._publish("error", f"Scan failed: {e}")
            raise

        return self.scan_id

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist_all(
        self,
        azure_data: dict,
        rbac_data: dict,
        graph_data: dict,
    ) -> tuple[dict, dict]:
        """Write all nodes, edges, role defs, and role assignments to DB. Returns node registry."""
        db = self.db
        scan_id = self.scan_id
        node_registry: dict[str, str] = {}  # azure_id → node_id

        def _add_node(node_id: str, node_type: str, name: str, display_name: str = "", properties: dict = None):
            if not node_id:
                return
            n = Node(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                node_id=node_id,
                node_type=node_type,
                name=name,
                display_name=display_name or name,
                properties=properties or {},
            )
            db.add(n)
            node_registry[node_id] = n.id

        def _add_edge(src: str, tgt: str, edge_type: str, props: dict = None):
            if not src or not tgt:
                return
            db.add(Edge(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                source_node_id=src,
                target_node_id=tgt,
                edge_type=edge_type,
                properties=props or {},
            ))

        # --- Subscription node ---
        sub = azure_data.get("subscription", {})
        sub_id = sub.get("subscription_id", self.subscription_id)
        _add_node(sub_id, "subscription", sub.get("display_name", sub_id), properties=sub)

        # --- Resource groups ---
        for rg in azure_data.get("resource_groups", []):
            _add_node(rg["id"], "resource_group", rg["name"], properties=rg)
            _add_edge(sub_id, rg["id"], "contains")

        # --- Storage accounts ---
        for s in azure_data.get("storage_accounts", []):
            _add_node(s["id"], "storage_account", s["name"], properties=s)
            _add_edge(s.get("resource_group", ""), s["id"], "contains")

        # --- Key Vaults ---
        for kv in azure_data.get("key_vaults", []):
            _add_node(kv["id"], "key_vault", kv["name"], properties=kv)
            _add_edge(kv.get("resource_group", ""), kv["id"], "contains")

        # --- Web Apps / Function Apps ---
        for app in azure_data.get("web_apps", []):
            _add_node(app["id"], app["node_type"], app["name"], properties=app)
            _add_edge(app.get("resource_group", ""), app["id"], "contains")
            # System-assigned MI creates an edge: function_app → service principal
            if app.get("system_identity_principal_id"):
                _add_edge(app["id"], app["system_identity_principal_id"], "has_system_identity", {
                    "identity_type": "SystemAssigned"
                })
            # User-assigned MIs
            for ua_id, ua_info in app.get("user_assigned_identities", {}).items():
                pid = ua_info.get("principalId") if isinstance(ua_info, dict) else None
                if pid:
                    _add_edge(app["id"], pid, "assigned_to", {"resource_id": ua_id})

        # --- Automation Accounts ---
        for aa in azure_data.get("automation_accounts", []):
            _add_node(aa["id"], "automation_account", aa["name"], properties=aa)
            _add_edge(aa.get("resource_group", ""), aa["id"], "contains")
            sys_pid = aa.get("identity", {}).get("principalId")
            if sys_pid:
                _add_edge(aa["id"], sys_pid, "has_system_identity")

        # --- VMs ---
        for vm in azure_data.get("virtual_machines", []):
            _add_node(vm["id"], "vm", vm["name"], properties=vm)
            _add_edge(vm.get("resource_group", ""), vm["id"], "contains")
            if vm.get("system_identity_principal_id"):
                _add_edge(vm["id"], vm["system_identity_principal_id"], "has_system_identity")

        # --- User-Assigned Managed Identities ---
        for mi in azure_data.get("managed_identities", []):
            _add_node(
                mi.get("principal_id") or mi["id"],
                "managed_identity",
                mi["name"],
                properties=mi,
            )
            if mi.get("principal_id"):
                node_registry[mi["id"]] = mi["principal_id"]

        # --- Role Definitions ---
        role_name_map: dict[str, str] = {}
        for rd in rbac_data.get("role_definitions", []):
            role_name_map[rd["role_id"]] = rd["name"]
            _add_node(rd["role_id"], "role_definition", rd["name"], properties=rd)
            db.add(RoleDefinition(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                role_id=rd["role_id"],
                name=rd["name"],
                description=rd.get("description", ""),
                permissions=rd.get("permissions", {}),
                is_builtin=rd.get("is_builtin", True),
                privilege_level=rd.get("privilege_level", "low"),
            ))

        # --- Role Assignments ---
        for ra in rbac_data.get("role_assignments", []):
            role_id = ra["role_definition_id"].split("/")[-1]
            db.add(RoleAssignment(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                assignment_id=ra["assignment_id"],
                principal_id=ra["principal_id"],
                principal_type=ra.get("principal_type", "Unknown"),
                role_definition_id=ra["role_definition_id"],
                role_name=ra.get("role_name", ""),
                scope=ra["scope"],
                scope_level=ra.get("scope_level", "resource"),
            ))
            # Edge: principal → role_definition
            _add_edge(ra["principal_id"], role_id, "has_role", {
                "scope": ra["scope"],
                "scope_level": ra.get("scope_level", ""),
                "role_name": ra.get("role_name", ""),
                "assignment_id": ra["assignment_id"],
            })

        # --- Users ---
        for u in graph_data.get("users", []):
            _add_node(u["id"], "user", u.get("display_name", u["id"]),
                      display_name=u.get("display_name", ""), properties=u)

        # --- Groups ---
        for g in graph_data.get("groups", []):
            _add_node(g["id"], "group", g.get("display_name", g["id"]),
                      display_name=g.get("display_name", ""), properties=g)

        # --- Group memberships ---
        for gid, members in graph_data.get("group_memberships", {}).items():
            for m in members:
                _add_edge(m["id"], gid, "member_of", {"member_type": m.get("type", "user")})

        # --- Service Principals ---
        for sp in graph_data.get("service_principals", []):
            _add_node(sp["id"], "service_principal", sp.get("display_name", sp["id"]),
                      display_name=sp.get("display_name", ""), properties=sp)

        # --- Entra directory role assignments (edges) ---
        for dr in graph_data.get("directory_roles", []):
            _add_edge(dr["principal_id"], f"entra_role_{dr['role_id']}", "has_entra_role", {
                "role_name": dr["role_name"],
                "is_privileged": dr["is_privileged"],
            })

        db.commit()
        return node_registry, role_name_map

    # ------------------------------------------------------------------
    # Incremental scan helpers
    # ------------------------------------------------------------------

    def _find_cached_scan(self) -> Optional[Scan]:
        """Return the most recent completed scan for this subscription (if any)."""
        return (
            self.db.query(Scan)
            .filter(
                Scan.subscription_id == self.subscription_id,
                Scan.status == "completed",
                Scan.id != self.scan_id,
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )

    def _copy_collection(self, source: Scan) -> tuple[dict, dict]:
        """Copy all nodes/edges/role-defs/role-assignments from source scan into this scan."""
        db = self.db
        target_id = self.scan_id
        node_registry: dict[str, str] = {}
        role_name_map: dict[str, str] = {}

        for n in db.query(Node).filter(Node.scan_id == source.id).all():
            new_n = Node(
                id=str(uuid.uuid4()),
                scan_id=target_id,
                node_id=n.node_id,
                node_type=n.node_type,
                name=n.name,
                display_name=n.display_name,
                properties=n.properties,
            )
            db.add(new_n)
            node_registry[n.node_id] = new_n.id

        for e in db.query(Edge).filter(Edge.scan_id == source.id).all():
            db.add(Edge(
                id=str(uuid.uuid4()),
                scan_id=target_id,
                source_node_id=e.source_node_id,
                target_node_id=e.target_node_id,
                edge_type=e.edge_type,
                properties=e.properties,
            ))

        for rd in db.query(RoleDefinition).filter(RoleDefinition.scan_id == source.id).all():
            role_name_map[rd.role_id] = rd.name
            db.add(RoleDefinition(
                id=str(uuid.uuid4()),
                scan_id=target_id,
                role_id=rd.role_id,
                name=rd.name,
                description=rd.description,
                permissions=rd.permissions,
                is_builtin=rd.is_builtin,
                privilege_level=rd.privilege_level,
            ))

        for ra in db.query(RoleAssignment).filter(RoleAssignment.scan_id == source.id).all():
            db.add(RoleAssignment(
                id=str(uuid.uuid4()),
                scan_id=target_id,
                assignment_id=ra.assignment_id,
                principal_id=ra.principal_id,
                principal_type=ra.principal_type,
                principal_name=ra.principal_name,
                role_definition_id=ra.role_definition_id,
                role_name=ra.role_name,
                scope=ra.scope,
                scope_level=ra.scope_level,
            ))

        db.commit()
        return node_registry, role_name_map

    def _load_rbac_graph_from_db(self) -> tuple[dict, dict]:
        """Reconstruct minimal rbac_data/graph_data dicts from DB for analyzer re-run."""
        db = self.db
        ras = db.query(RoleAssignment).filter(RoleAssignment.scan_id == self.scan_id).all()
        rbac_data = {
            "role_assignments": [
                {
                    "assignment_id": ra.assignment_id,
                    "principal_id": ra.principal_id,
                    "principal_type": ra.principal_type or "Unknown",
                    "role_definition_id": ra.role_definition_id,
                    "role_name": ra.role_name or "",
                    "scope": ra.scope,
                    "scope_level": ra.scope_level or "resource",
                }
                for ra in ras
            ],
            "role_definitions": [],
            "role_name_map": {ra.role_definition_id.split("/")[-1]: ra.role_name for ra in ras if ra.role_name},
        }

        # Reconstruct minimal graph_data from node properties
        nodes = db.query(Node).filter(Node.scan_id == self.scan_id).all()
        users, groups, sps, dir_roles = [], [], [], []
        group_memberships: dict[str, list] = {}

        for n in nodes:
            props = n.properties or {}
            if n.node_type == "user":
                users.append({"id": n.node_id, "display_name": n.display_name, **props})
            elif n.node_type == "group":
                groups.append({"id": n.node_id, "display_name": n.display_name, **props})
            elif n.node_type == "service_principal":
                sps.append({"id": n.node_id, "display_name": n.display_name, **props})

        # Rebuild group memberships from edges
        from ..models.db_models import Edge as EdgeModel
        for e in db.query(EdgeModel).filter(
            EdgeModel.scan_id == self.scan_id, EdgeModel.edge_type == "member_of"
        ).all():
            group_memberships.setdefault(e.target_node_id, []).append({"id": e.source_node_id})

        graph_data = {
            "users": users,
            "groups": groups,
            "service_principals": sps,
            "group_memberships": group_memberships,
            "directory_roles": dir_roles,
            "tenant_info": {},
            "app_registrations": [],
        }
        return rbac_data, graph_data

    # ------------------------------------------------------------------
    # Analyzer invocation
    # ------------------------------------------------------------------

    def _run_analyzers(
        self,
        node_registry: dict,
        rbac_data: dict,
        graph_data: dict,
        role_name_map: dict,
    ):
        from ..analyzers import run_all_analyzers
        run_all_analyzers(
            scan_id=self.scan_id,
            db=self.db,
            rbac_data=rbac_data,
            graph_data=graph_data,
            role_name_map=role_name_map,
        )
