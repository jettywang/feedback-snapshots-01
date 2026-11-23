# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Role-chain resolution, including domain inheritance.

Casbin stores grants as directed links ``user -> role`` (optionally scoped to a
domain).  A "role chain" for a candidate rule is every concrete path that
connects a real subject (a name that only appears as a user, never as a role)
to the rule's subject token, including transitive hierarchy links.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple


def _extract_edges(role_manager, domain: Optional[str]):
    """Return ``(edges, known_names)`` from a default role manager."""

    edges: Set[Tuple[str, str]] = set()
    known: Set[str] = set()

    domain_links = getattr(role_manager, "all_links", None)
    if isinstance(domain_links, dict):
        # DomainManager: {domain: [Link(user, role), ...]}
        for stored_domain, links in domain_links.items():
            if domain is not None and stored_domain != domain:
                continue
            for link in links:
                edges.add((link.user, link.role))
                known.update((link.user, link.role))
    elif isinstance(domain_links, list):
        # RoleManager: [Link(user, role), ...]
        for link in domain_links:
            edges.add((link.user, link.role))
            known.update((link.user, link.role))

    all_roles = getattr(role_manager, "all_roles", None)
    if isinstance(all_roles, dict):
        known.update(all_roles.keys())
    # A domain role manager keeps no flat role table, so make sure every edge
    # endpoint is still discoverable as a traversable name.
    for user, role in edges:
        known.add(user)
        known.add(role)

    if not known:
        # Fallback for custom role managers: walk the public API.
        queue = deque()
        for name in list(getattr(role_manager, "rm_map", {}).keys()):
            queue.append(name)
        while queue:
            current = queue.popleft()
            try:
                if domain is not None:
                    roles = role_manager.get_roles(current, domain)
                else:
                    roles = role_manager.get_roles(current)
            except TypeError:
                roles = role_manager.get_roles(current)
            for role in roles:
                edges.add((current, role))
                if role not in known:
                    known.add(role)
                    queue.append(role)

    return edges, known


def find_role_chains(role_manager, target_role: str, domain: Optional[str] = None) -> Dict[str, List[List[str]]]:
    """Map every root subject to the chains reaching ``target_role``.

    The result keys are concrete subjects (names with no incoming grant in the
    relevant domain); each value is the list of chains
    ``[subject, ..., target_role]``.  A target with no incoming grant maps to
    the trivial one-hop chain ``[target_role]``.
    """

    edges, known = _extract_edges(role_manager, domain)
    known.add(target_role)

    incoming: Dict[str, List[str]] = {}
    for user, role in edges:
        incoming.setdefault(role, []).append(user)

    def chains_to_target(root: str) -> List[List[str]]:
        """All forward paths ``[root, ..., target_role]``.

        ``incoming[role]`` lists the users granting into ``role``, so the
        search walks backwards from the target and reverses each path.
        """
        found: List[List[str]] = []
        stack: List[Tuple[str, Tuple[str, ...]]] = [(target_role, (target_role,))]
        seen_paths = set()
        while stack:
            current, reverse_path = stack.pop()
            if current == root:
                forward = list(reversed(reverse_path))
                key = tuple(forward)
                if key not in seen_paths:
                    seen_paths.add(key)
                    found.append(forward)
                continue
            for ancestor in incoming.get(current, []):
                if ancestor in reverse_path:  # guard against cyclic grants
                    continue
                stack.append((ancestor, reverse_path + (ancestor,)))
        return found

    # Walk backwards from the target: every ancestor without an incoming grant
    # is a concrete root subject whose chains reach the target.
    result: Dict[str, List[List[str]]] = {}
    queue = deque([target_role])
    visited = {target_role}
    while queue:
        current = queue.popleft()
        ancestors = incoming.get(current, [])
        if not ancestors and current in known:
            chains = chains_to_target(current)
            if chains:
                result[current] = chains
        for ancestor in ancestors:
            if ancestor not in visited:
                visited.add(ancestor)
                queue.append(ancestor)

    return dict(sorted(result.items()))
