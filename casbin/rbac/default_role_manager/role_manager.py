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

import logging
from collections import OrderedDict, namedtuple
from enum import Enum

from casbin.rbac import RoleManager as RM
from casbin.rbac import ConditionalRoleManager as CRM
from casbin.util.evaluation import (
    RoleEdge,
    current_link_condition_snapshot,
    record_role_edge,
)

Link = namedtuple("Link", ["user", "role"])


class MatchOrder(Enum):
    STR_PATTERN = 0
    PATTERN_STR = 1
    PATTERN_PATTERN = 2


class Role:
    def __init__(self, name):
        self.name = name
        self.roles = set()
        self.users = set()
        self.link_condition_func_map = dict()
        self.link_condition_func_params_map = dict()

    def add_role(self, role):
        self.roles.add(role)
        role._add_user(self)

    def remove_role(self, role):
        self.roles.remove(role)
        role._remove_user(self)

    def _add_user(self, user):
        self.users.add(user)

    def _remove_user(self, user):
        self.users.remove(user)

    def copy_from(self, role):
        for r in role.roles:
            self.add_role(r)
        for u in role.users:
            u.add_role(self)

    def empty(self):
        return len(self.users) + len(self.roles) == 0

    def to_string(self):
        if len(self.roles) == 0:
            return ""

        names = ", ".join(self.get_roles())

        if len(self.roles) == 1:
            return self.name + " < " + names
        else:
            return self.name + " < (" + names + ")"

    def get_roles(self):
        roles = []
        for role in self.roles:
            roles.append(role.name)

        return roles

    def add_link_condition_func(self, role, domain, fn):
        self.link_condition_func_map[(role.name, domain)] = fn

    def get_link_condition_func(self, role, domain):
        key = (role.name, domain)
        return self.link_condition_func_map.get(key)

    def set_link_condition_func_params(self, role, domain, *params):
        self.link_condition_func_params_map[(role.name, domain)] = params

    def get_link_condition_func_params(self, role, domain):
        key = (role.name, domain)
        params = self.link_condition_func_params_map.get(key)
        return list(params) if params is not None else []


class RoleManager(RM):
    """provides a default implementation for the RoleManager interface"""

    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger("casbin.role")
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.all_links = list()
        self.all_roles = dict()

    def _rebuild(self):
        self.all_roles = dict()
        links = self.all_links
        self.all_links = list()
        for link in links:
            self.add_link(link.user, link.role)

    def _matching_fn(self, str1, str2, match_order=MatchOrder.STR_PATTERN):
        if match_order == MatchOrder.PATTERN_STR:
            return match_error_handler(self.matching_func, str2, str1)
        elif match_order == MatchOrder.PATTERN_PATTERN:
            return match_error_handler(self.matching_func, str1, str2) or match_error_handler(
                self.matching_func, str2, str1
            )
        else:  # match_order == MatchOrder.STR_PATTERN
            return match_error_handler(self.matching_func, str1, str2)

    def _matching_roles(self, name, match_order=MatchOrder.STR_PATTERN):
        return [
            role
            for role_name, role in list(
                self.all_roles.items()
            )  # convert view to list to avoid RuntimeError: dictionary changed size during iteration
            if self._matching_fn(name, role_name, match_order)
        ]

    def _get_role(self, name):
        if name not in self.all_roles:
            role = Role(name)
            if self.matching_func != None:
                for pattern_role in self._matching_roles(name):
                    role.copy_from(pattern_role)
            self.all_roles[name] = role
        return self.all_roles[name]

    def add_matching_func(self, fn):
        self.matching_func = fn
        self._rebuild()

    def add_domain_matching_func(self, fn=None):
        self.domain_matching_func = fn

    def clear(self):
        self.all_roles = dict()
        self.all_links = list()

    def add_link(self, name1, name2, *domain):
        self.all_links.append(Link(name1, name2))

        user = self._get_role(name1)
        role = self._get_role(name2)

        user.add_role(role)

        if self.matching_func != None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.add_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.add_role(r)

    def delete_link(self, name1, name2, *domain):
        if Link(name1, name2) not in self.all_links:
            return
        self.all_links.remove(Link(name1, name2))

        user = self._get_role(name1)
        role = self._get_role(name2)
        user.remove_role(role)

        if self.matching_func != None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.remove_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.remove_role(r)

    def has_link(self, name1, name2, *domain):
        user = self._get_role(name1)
        role = self._get_role(name2)

        return self._has_link(name2, [user], self.max_hierarchy_level)

    def _has_link(self, name, roles, level):
        if level <= 0 or len(roles) == 0:
            return False

        next_roles = set()
        for role in roles:
            if name == role.name:
                return True
            next_roles.update(set(role.roles))

        return self._has_link(name, list(next_roles), level - 1)

    def get_roles(self, name, *domain):
        user = self._get_role(name)
        return [r.name for r in user.roles]

    def get_users(self, name, *domain):
        role = self._get_role(name)
        return [u.name for u in role.users]

    def to_string(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)
        return ", ".join(line)

    def print_roles(self):
        self.logger.debug(self.to_string())


class DomainManagerBase(RM):
    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger("casbin.role")
        self.all_links = dict()
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.matching_func = lambda name1, name2: name1 == name2

    def add_matching_func(self, fn):
        self.matching_func = fn

    def add_domain_matching_func(self, fn=None):
        self.domain_matching_func = fn

    def _get_domain(self, *domain):
        if len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")
        elif len(domain) == 1:
            domain = domain[0]
        else:
            domain = ""

        return domain

    def _get_links(self, *domain):
        domain = self._get_domain(*domain)

        if domain not in self.all_links:
            self.all_links[domain] = []

        return self.all_links[domain]

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        domain_links = self.all_links.get(domain1, [])

        if self.domain_matching_func != None:
            for domain2, links in self.all_links.items():
                if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                    domain_links = domain_links + links

        rm = RoleManager(max_hierarchy_level=self.max_hierarchy_level)
        rm.add_matching_func(self.matching_func)
        for link in domain_links:
            rm.add_link(link[0], link[1])
        return rm

    def clear(self):
        self.all_links = dict()

    def add_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        links.append(Link(name1, name2))

    def delete_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        if Link(name1, name2) not in links:
            raise RuntimeError(f"error: link between {name1} and {name2} does not exist")
        links.remove(Link(name1, name2))

    def has_link(self, name1, name2, *domain):
        rm = self._get_role_manager(*domain)
        return rm.has_link(name1, name2)

    def get_roles(self, name, *domain):
        rm = self._get_role_manager(*domain)
        return rm.get_roles(name)

    def get_users(self, name, *domain):
        rm = self._get_role_manager(*domain)
        return rm.get_users(name)

    def print_roles(self):
        pass


class DomainManager(DomainManagerBase):
    def __init__(self, max_hierarchy_level=10, max_cached_role_managers=1000):
        """Caches one role manager per domain.

        max_cached_role_managers limits the cache; the least recently used role
        manager is evicted when the limit is exceeded. Pass 0 or None for no limit.
        ConditionalDomainManager does not use this limit because its link
        conditions live in the role managers.
        """
        super().__init__(max_hierarchy_level)
        self.max_cached_role_managers = max_cached_role_managers
        self.rm_map = OrderedDict()  # type: OrderedDict[str, RoleManager]

    def _rebuild(self):
        self.rm_map = OrderedDict()

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        rm = self.rm_map.get(domain1)
        if rm is None:
            rm = super()._get_role_manager(*domain)
            self.rm_map[domain1] = rm
            if self.max_cached_role_managers and self.max_cached_role_managers > 0:
                while len(self.rm_map) > self.max_cached_role_managers:
                    self.rm_map.popitem(last=False)
        else:
            self.rm_map.move_to_end(domain1)

        return rm

    def _affected_role_managers(self, *domain):
        domain_pattern = self._get_domain(*domain)

        if self.domain_matching_func != None:
            return [
                self.rm_map[domain_str]
                for domain_str in self.rm_map.keys()
                if match_error_handler(self.domain_matching_func, domain_str, domain_pattern)
            ]
        else:
            return [self.rm_map[domain_pattern]] if domain_pattern in self.rm_map else []

    def add_matching_func(self, fn):
        super().add_matching_func(fn)
        for rm in self.rm_map.values():
            rm.add_matching_func(fn)

    def add_domain_matching_func(self, fn):
        super().add_domain_matching_func(fn)
        for rm in self.rm_map.values():
            rm.add_domain_matching_func(fn)
        self._rebuild()

    def clear(self):
        super().clear()
        self.rm_map = OrderedDict()

    def add_link(self, name1, name2, *domain):
        super().add_link(name1, name2, *domain)
        for rm in self._affected_role_managers(*domain):
            rm.add_link(name1, name2, *domain)

    def delete_link(self, name1, name2, *domain):
        super().delete_link(name1, name2, *domain)
        for rm in self._affected_role_managers(*domain):
            rm.delete_link(name1, name2, *domain)

    def has_link(self, name1, name2, *domain):
        return super().has_link(name1, name2, *domain)

    def get_roles(self, name, *domain):
        return super().get_roles(name, *domain)

    def get_users(self, name, *domain):
        return super().get_users(name, *domain)

    def print_roles(self):
        for domain, rm in self.rm_map.items():
            line = rm.to_string()
            self.logger.debug(f"{domain}: {line}")


def match_error_handler(fn, key1, key2):
    try:
        return fn(key1, key2)
    except:
        return False


class ConditionalRoleManager(RoleManager, CRM):
    ptype = "g"
    _owner = None

    def has_link(self, name1, name2, *domains):
        """determines whether role: name1 inherits role: name2.

        The search carries the conditional edges along each path, so an
        explanation names only the edges that actually established the link
        rather than every edge it happened to evaluate.
        """
        if name1 == name2 or (self.matching_func is not None and self._matching_fn(name1, name2)):
            return True

        user = self._get_role(name1)
        role = self._get_role(name2)

        path = self._find_path(role.name, [(user, ())], self.max_hierarchy_level, *domains)
        if path is None:
            return False
        for edge in path:
            record_role_edge(edge)
        return True

    def _find_path(self, target_name, frontier, level, *domains):
        """breadth first search that returns the conditional edges of a found path."""
        if level < 0 or not frontier:
            return None

        next_frontier = []
        seen = set()
        for role, path in frontier:
            if target_name == role.name or (
                self.matching_func is not None and self._matching_fn(role.name, target_name)
            ):
                return path

            for next_role in role.roles:
                if next_role.name in seen:
                    continue
                seen.add(next_role.name)
                domain = domains[0] if domains else None
                edge, fn = self.resolve_edge(role.name, next_role.name, domain)
                if self._edge_passes(edge, fn):
                    next_frontier.append((next_role, path + (edge,)))

        return self._find_path(target_name, next_frontier, level - 1, *domains)

    def resolve_edge(self, user_name, role_name, domain=None):
        """returns the grouping-policy edge to report and its condition.

        For a pattern domain the reported edge uses the stored policy domain,
        because that is the row an explanation can point back to.
        """
        if self._owner is not None:
            return self._owner.resolve_edge(user_name, role_name, domain)
        params = self.edge_params(user_name, role_name, domain)
        edge = RoleEdge(self.ptype or "g", user_name, role_name, domain, params)
        return edge, self.get_edge_condition(user_name, role_name, domain)

    def edge_condition(self, user_name, role_name, domain=None):
        return self.get_edge_condition(user_name, role_name, domain)

    def edge_params(self, user_name, role_name, domain=None):
        if domain is None:
            return self.get_link_condition_func_params(user_name, role_name)
        return self.get_link_condition_func_params(user_name, role_name, [domain])

    def _edge_passes(self, edge, fn):
        """evaluates one link condition against the batch view, if there is one."""
        snapshot = current_link_condition_snapshot()
        if snapshot is None:
            if fn is not None:
                passed = bool(fn(*edge.params))
            else:
                passed = True
        else:
            key = (edge.ptype, edge.user, edge.role, edge.domain)
            captured = snapshot.condition_for(key)
            if captured is None:
                # An edge that did not exist when the batch started: evaluate the
                # condition as it is now, but memoise it for the rest of the batch.
                params = edge.params
            else:
                fn, params = captured
            passed = snapshot.decide(key, fn, params)

        return passed

    def get_edge_condition(self, user_name, role_name, domain=None):
        """returns the condition function attached to one link, if any."""
        if domain is None:
            return self.get_link_condition_func(user_name, role_name)
        return self.get_domain_link_condition_func(user_name, role_name, domain)

    def iter_condition_rows(self):
        """yields ``(key, fn, params)`` for every link in this manager."""
        seen = set()
        for link in self.all_links:
            key = (self.ptype or "g", link.user, link.role, None)
            if key in seen:
                continue
            seen.add(key)
            yield (
                key,
                self.get_link_condition_func(link.user, link.role),
                self.get_link_condition_func_params(link.user, link.role),
            )

    def get_link_condition_func(self, user_name, role_name):
        """get_link_condition_func get link_condition_func based on userName, roleName"""
        return self.get_domain_link_condition_func(user_name, role_name, "")

    def get_domain_link_condition_func(self, user_name, role_name, domain):
        """get_domain_link_condition_func get link_condition_func based on userName, roleName, domain"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)

        return user.get_link_condition_func(role, domain)

    def get_link_condition_func_params(self, user_name, role_name, domains=None):
        """get_link_condition_func_params gets parameters of link_condition_func based on userName, roleName, domain"""
        if domains is None:
            domains = []

        user = self._get_role(user_name)
        role = self._get_role(role_name)

        domain_name = ""
        if len(domains) != 0:
            domain_name = domains[0]

        return user.get_link_condition_func_params(role, domain_name)

    def add_link_condition_func(self, user_name, role_name, fn):
        """add_link_condition_func is based on userName, roleName, add LinkConditionFunc"""
        self.add_domain_link_condition_func(user_name, role_name, "", fn)

    def add_domain_link_condition_func(self, user_name, role_name, domain, fn):
        """add_domain_link_condition_func is based on userName, roleName, domain, add LinkConditionFunc"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)
        user.add_link_condition_func(role, domain, fn)

    def set_link_condition_func_params(self, user_name, role_name, *params):
        """set_link_condition_func_params sets parameters of LinkConditionFunc based on userName, roleName, domain"""
        self.set_domain_link_condition_func_params(user_name, role_name, "", *params)

    def set_domain_link_condition_func_params(self, user_name, role_name, domain, *params):
        """set_domain_link_condition_func_params sets parameters of LinkConditionFunc based on userName, roleName, domain"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)
        user.set_link_condition_func_params(role, domain, *params)


class ConditionalDomainManager(DomainManager, ConditionalRoleManager):
    """a conditional role manager per domain.

    Conditions and their parameters are kept here rather than only on the
    cached per-domain role managers: a condition is usually registered before
    the first request builds any of them, and a request may also arrive with a
    domain that only matches a policy domain through the domain matching
    function.  Building a role manager replays this registry into it.
    """

    ptype = "g"

    def __init__(self, max_hierarchy_level=10):
        super().__init__(max_hierarchy_level)
        self._conditions = {}
        self._condition_params = {}

    def clear(self):
        super().clear()
        self._conditions = {}
        self._condition_params = {}

    def edge_condition(self, user_name, role_name, domain=None):
        """finds a link condition on this domain or on a matching policy domain."""
        return self._lookup(user_name, role_name, domain)[0]

    def edge_params(self, user_name, role_name, domain=None):
        return self._lookup(user_name, role_name, domain)[1]

    def resolve_edge(self, user_name, role_name, domain=None):
        fn, params, resolved = self._lookup(user_name, role_name, domain)
        edge = RoleEdge(self.ptype or "g", user_name, role_name, resolved, params)
        return edge, fn

    def _lookup(self, user_name, role_name, domain):
        """returns ``(condition, params, stored domain)`` for one grouping row."""
        for candidate in self._condition_domains(domain, user_name, role_name):
            fn = self._conditions.get((user_name, role_name, candidate))
            params = self._condition_params.get((user_name, role_name, candidate))
            if fn is not None or params:
                return fn, list(params or ()), candidate
        return None, [], self.canonical_domain(user_name, role_name, domain)

    def iter_condition_rows(self):
        """yields ``(key, fn, params)`` for every stored grouping row."""
        for domain, links in self.all_links.items():
            for link in links:
                yield (
                    (self.ptype or "g", link.user, link.role, domain),
                    self._conditions.get((link.user, link.role, domain)),
                    list(self._condition_params.get((link.user, link.role, domain), ())),
                )

    def canonical_domain(self, user_name, role_name, domain=None):
        """maps a request domain to the stored domain whose row it came from."""
        link = Link(user_name, role_name)
        if domain is not None and link in self.all_links.get(domain, []):
            return domain
        for stored, links in self.all_links.items():
            if stored == domain or link not in links:
                continue
            if domain is not None and self.domain_matching_func is not None:
                if match_error_handler(self.domain_matching_func, domain, stored):
                    return stored
            elif stored == domain:
                return stored
        return domain

    def _condition_domains(self, domain, user_name=None, role_name=None):
        """the request's domain first, then matching policy domains."""
        candidates = [domain] if domain is not None else []
        for stored_domain in self.all_links:
            if stored_domain == domain or stored_domain in candidates:
                continue
            if domain is not None and self.domain_matching_func is not None:
                if not match_error_handler(self.domain_matching_func, domain, stored_domain):
                    continue
            elif domain != stored_domain:
                continue
            if user_name is not None and Link(user_name, role_name) not in self.all_links.get(stored_domain, []):
                continue
            candidates.append(stored_domain)
        return candidates

    def domain_matching_func_for_trace(self):
        """the function that maps a request domain to a stored policy domain."""
        return self.domain_matching_func

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        if domain1 not in self.rm_map:
            self.rm_map[domain1] = self._get_conditional_role_manager(*domain)

        return self.rm_map[domain1]

    def _get_conditional_role_manager(self, *domain, store=False):
        domain1 = self._get_domain(*domain)
        domain_links = self.all_links.get(domain1, [])

        rm = self.rm_map.get(domain1, None)

        if rm is None:
            rm = ConditionalRoleManager(max_hierarchy_level=self.max_hierarchy_level)
            rm.ptype = self.ptype
            rm._owner = self
            if store:
                self.rm_map[domain1] = rm
            if self.domain_matching_func is not None:
                for domain2, links in self.all_links.items():
                    if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                        domain_links = domain_links + links

            rm.add_matching_func(self.matching_func)
            for link in domain_links:
                rm.add_link(link[0], link[1])
            for (user_name, role_name, registered_domain), fn in self._conditions.items():
                if registered_domain == domain1:
                    rm.add_domain_link_condition_func(user_name, role_name, registered_domain, fn)
            for (user_name, role_name, registered_domain), params in self._condition_params.items():
                if registered_domain == domain1:
                    rm.set_domain_link_condition_func_params(user_name, role_name, registered_domain, *params)
        return rm

    def has_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        rm = self._get_conditional_role_manager(domain)
        return rm.has_link(name1, name2, domain)

    def add_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        # Keep the raw grouping policy as the source of truth: a role manager
        # for a pattern domain is built from it on first use.
        self.all_links.setdefault(domain, []).append(Link(name1, name2))
        rm = self._get_conditional_role_manager(domain, store=True)
        if Link(name1, name2) not in rm.all_links:
            rm.add_link(name1, name2, domain)

    def delete_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        links = self.all_links.get(domain, [])
        if Link(name1, name2) in links:
            links.remove(Link(name1, name2))
        rm = self._get_conditional_role_manager(domain, store=True)
        if Link(name1, name2) in rm.all_links:
            rm.delete_link(name1, name2, domain)

    def add_link_condition_func(self, user_name, role_name, fn):
        self.add_domain_link_condition_func(user_name, role_name, "", fn)

    def add_domain_link_condition_func(self, user_name, role_name, domain, fn):
        self._conditions[(user_name, role_name, domain)] = fn
        for rm in self.rm_map.values():
            rm.add_domain_link_condition_func(user_name, role_name, domain, fn)

    def set_link_condition_func_params(self, user_name, role_name, *params):
        self.set_domain_link_condition_func_params(user_name, role_name, "", *params)

    def set_domain_link_condition_func_params(self, user_name, role_name, domain, *params):
        self._condition_params[(user_name, role_name, domain)] = tuple(params)
        for rm in self.rm_map.values():
            rm.set_domain_link_condition_func_params(user_name, role_name, domain, *params)
