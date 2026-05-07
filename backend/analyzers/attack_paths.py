"""
Attack Path Builder: uses NetworkX to find shortest privilege escalation paths.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """
    Given a NetworkX directed graph of the Azure environment, finds:
    - All paths from a given principal to high-value targets
    - Shortest paths to Owner-equivalent privilege
    - Lateral movement opportunities
    """

    def __init__(self, graph):
        self.G = graph

    def find_paths_to_target(
        self, source_id: str, target_ids: list[str], max_depth: int = 5
    ) -> list[dict]:
        """Find all paths from source to any target (within max_depth hops)."""
        import networkx as nx
        paths = []
        for target in target_ids:
            if source_id not in self.G or target not in self.G:
                continue
            try:
                for path in nx.all_simple_paths(self.G, source_id, target, cutoff=max_depth):
                    path_details = []
                    for i, node_id in enumerate(path):
                        node_data = self.G.nodes.get(node_id, {})
                        step = {
                            "node_id": node_id,
                            "node_type": node_data.get("node_type", "unknown"),
                            "name": node_data.get("name", node_id),
                        }
                        if i > 0:
                            edge_data = self.G.get_edge_data(path[i - 1], node_id) or {}
                            step["edge_type"] = edge_data.get("edge_type", "")
                            step["edge_props"] = edge_data
                        path_details.append(step)
                    paths.append({
                        "source": source_id,
                        "target": target,
                        "length": len(path) - 1,
                        "path": path_details,
                    })
            except Exception as e:
                logger.debug(f"Path search error {source_id}→{target}: {e}")
        return sorted(paths, key=lambda p: p["length"])

    def find_all_escalation_paths(self, owner_node_ids: list[str]) -> list[dict]:
        """Find all principals that can reach Owner-equivalent nodes."""
        import networkx as nx
        all_paths = []
        for target in owner_node_ids:
            if target not in self.G:
                continue
            try:
                ancestors = nx.ancestors(self.G, target)
                for source in ancestors:
                    node_data = self.G.nodes.get(source, {})
                    if node_data.get("node_type") in {"user", "group", "service_principal", "managed_identity"}:
                        try:
                            path = nx.shortest_path(self.G, source, target)
                            all_paths.append({
                                "source": source,
                                "source_name": node_data.get("name", source),
                                "target": target,
                                "length": len(path) - 1,
                                "path": path,
                            })
                        except nx.NetworkXNoPath:
                            pass
            except Exception as e:
                logger.debug(f"Ancestor search error for {target}: {e}")
        return sorted(all_paths, key=lambda p: p["length"])

    def find_lateral_movement(self, from_node_id: str, max_depth: int = 3) -> list[dict]:
        """Find resources reachable from a compromised identity."""
        import networkx as nx
        if from_node_id not in self.G:
            return []
        reachable = []
        for target in nx.descendants(self.G, from_node_id):
            node_data = self.G.nodes.get(target, {})
            if node_data.get("node_type") in {
                "storage_account", "key_vault", "function_app",
                "vm", "automation_account",
            }:
                try:
                    path = nx.shortest_path(self.G, from_node_id, target)
                    if len(path) - 1 <= max_depth:
                        reachable.append({
                            "target": target,
                            "target_name": node_data.get("name", target),
                            "target_type": node_data.get("node_type", ""),
                            "hops": len(path) - 1,
                            "path": path,
                        })
                except nx.NetworkXNoPath:
                    pass
        return sorted(reachable, key=lambda x: x["hops"])
