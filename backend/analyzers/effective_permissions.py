"""
Effective Permission Engine.

Calculates what an identity can ACTUALLY do by resolving:
  - Direct role assignments
  - Group-inherited role assignments (transitive)
  - Managed identity transitive access
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class EffectivePermissionEngine:
    """
    Given collected data, computes effective permissions for every principal.
    """

    def __init__(self, role_assignments: list[dict], group_memberships: dict[str, list[dict]]):
        # role_assignments: list of {principal_id, role_name, role_definition_id, scope, scope_level, principal_type}
        self.role_assignments = role_assignments
        # group_memberships: {group_id: [{id, type}, ...]}
        self.group_memberships = group_memberships

        # Build reverse: member_id → set of group_ids
        self._member_to_groups: dict[str, set[str]] = defaultdict(set)
        for gid, members in group_memberships.items():
            for m in members:
                self._member_to_groups[m["id"]].add(gid)

        # principal_id → list of role assignment dicts (direct)
        self._direct: dict[str, list[dict]] = defaultdict(list)
        for ra in role_assignments:
            self._direct[ra["principal_id"]].append(ra)

    def _all_groups_for(self, principal_id: str, visited: set | None = None) -> set[str]:
        """Recursively resolve all group memberships (handles nested groups)."""
        if visited is None:
            visited = set()
        if principal_id in visited:
            return set()
        visited.add(principal_id)
        direct_groups = self._member_to_groups.get(principal_id, set())
        all_groups = set(direct_groups)
        for gid in direct_groups:
            all_groups |= self._all_groups_for(gid, visited)
        return all_groups

    def compute(self, principal_id: str) -> list[dict]:
        """Return all effective role assignments for a principal (direct + group-inherited)."""
        effective: list[dict] = []
        seen_assignments: set[str] = set()

        # Direct assignments
        for ra in self._direct.get(principal_id, []):
            key = f"{ra['role_definition_id']}|{ra['scope']}"
            if key not in seen_assignments:
                seen_assignments.add(key)
                effective.append({**ra, "inherited_from": None})

        # Group-inherited
        for gid in self._all_groups_for(principal_id):
            for ra in self._direct.get(gid, []):
                key = f"{ra['role_definition_id']}|{ra['scope']}"
                if key not in seen_assignments:
                    seen_assignments.add(key)
                    effective.append({**ra, "inherited_from": gid})

        return effective

    def compute_all(self, principal_ids: list[str]) -> dict[str, list[dict]]:
        return {pid: self.compute(pid) for pid in principal_ids}

    def principals_with_role(self, role_name: str) -> list[str]:
        """Return all principal IDs that have a given role (directly or via group)."""
        matching = [ra["principal_id"] for ra in self.role_assignments if ra.get("role_name") == role_name]
        # Also check who is a member of a group that has the role
        group_matches = [ra["principal_id"] for ra in self.role_assignments
                         if ra.get("role_name") == role_name and ra.get("principal_type") == "Group"]
        extra = []
        for gid in group_matches:
            members = self.group_memberships.get(gid, [])
            extra.extend(m["id"] for m in members)
        return list(set(matching + extra))
