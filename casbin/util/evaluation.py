# Copyright 2026 The casbin Authors. All Rights Reserved.
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

"""The evaluation clock and role-edge trace shared by one authorization call.

Conditional role edges are not a pure function of the request: a link condition
usually compares the wall clock with a validity window stored on the grouping
policy row.  A batch preview has to answer every request against the same
instant, otherwise a temporary role can expire half way through the batch and
the requests that run after it disagree with the ones before it.

``evaluation_snapshot()`` pins that instant in a :class:`contextvars.ContextVar`,
so it is local to the current thread or asyncio task.  Built-in operators such as
``timeMatch`` and application supplied link conditions can read it through
``evaluation_now()``.  An explicit ``at`` also makes the instant reproducible,
which is what a caller needs when it has to say which moment a preview used.
"""

import contextvars
from contextlib import contextmanager
from datetime import date, datetime


__all__ = [
    "EvaluationResult",
    "Explanation",
    "LinkConditionSnapshot",
    "RoleEdge",
    "capture_role_edges",
    "current_evaluation_time",
    "current_link_condition_snapshot",
    "evaluation_now",
    "evaluation_snapshot",
    "link_condition_snapshot",
    "record_role_edge",
]


_time = contextvars.ContextVar("casbin_evaluation_time", default=None)
_role_edges = contextvars.ContextVar("casbin_role_edges", default=None)
_link_conditions = contextvars.ContextVar("casbin_link_conditions", default=None)


def _coerce_time(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            # Link conditions in pycasbin are written against naive local time.
            return value.astimezone().replace(tzinfo=None)
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    raise TypeError("evaluation time must be a datetime, date, string or None")


def evaluation_now():
    """returns the instant the current decision is evaluated at.

    Inside a batch this is the batch's single time basis; outside one it falls
    back to the wall clock.  Custom link condition functions should call this
    instead of ``datetime.now()`` so that a batch preview is reproducible.
    """
    at = _time.get()
    return at if at is not None else datetime.now()


def current_evaluation_time():
    """returns the pinned evaluation instant, or None outside a snapshot."""
    return _time.get()


@contextmanager
def evaluation_snapshot(at=None):
    """pins one evaluation instant for the duration of the block.

    An existing snapshot is inherited by nested blocks when ``at`` is omitted;
    this is what lets every request in a batch keep the batch's time basis.
    Passing ``at`` explicitly always installs that instant.
    """
    pinned = _coerce_time(at)
    if pinned is None:
        pinned = _time.get()
        if pinned is None:
            pinned = datetime.now()

    token = _time.set(pinned)
    try:
        yield pinned
    finally:
        _time.reset(token)


class RoleEdge(list):
    """one grouping-policy edge traversed while a role link was established.

    The value compares equal to the grouping-policy row, prefixed with its
    policy type, e.g. ``["g", "alice", "admin", "domain1", start, end]``.  The
    individual fields are available as attributes as well.
    """

    __slots__ = ("ptype", "user", "role", "domain", "params")

    def __init__(self, ptype, user, role, domain=None, params=()):
        self.ptype = ptype
        self.user = user
        self.role = role
        self.domain = domain
        self.params = tuple(params)
        row = [ptype, user, role]
        if domain is not None:
            row.append(domain)
        row.extend(self.params)
        super().__init__(row)

    @property
    def rule(self):
        """the grouping-policy row without the policy type."""
        return list(self)[1:]

    def to_policy(self):
        """the edge as a grouping-policy row, including its policy type."""
        return list(self)

    def copy(self):
        """a detached edge, safe to hand to a caller or store in a cache."""
        return RoleEdge(self.ptype, self.user, self.role, self.domain, self.params)

    def to_dict(self):
        return {
            "ptype": self.ptype,
            "user": self.user,
            "role": self.role,
            "domain": self.domain,
            "params": list(self.params),
        }

    def __repr__(self):
        return "RoleEdge({})".format(", ".join(repr(v) for v in self))


class Explanation(list):
    """the responding policy rule, plus the role edges used to reach it.

    It is still a plain list of policy fields, so existing callers that compare
    ``enforce_ex`` style explanations keep working.  The batch entry point
    attaches the edges that were actually traversed for this rule and the
    evaluation instant they were checked at.
    """

    def __init__(self, rule=(), role_edges=(), evaluated_at=None):
        super().__init__(rule)
        self.role_edges = [edge.copy() if isinstance(edge, RoleEdge) else edge for edge in role_edges]
        self.evaluated_at = evaluated_at

    def to_dict(self):
        return {
            "rule": list(self),
            "role_edges": [edge.to_policy() if isinstance(edge, RoleEdge) else list(edge) for edge in self.role_edges],
            "evaluated_at": self.evaluated_at.isoformat(sep=" ") if self.evaluated_at is not None else None,
        }


class EvaluationResult:
    """a decision together with the moment and the role edges it rests on.

    Unpacks like the historical ``(allowed, explanation)`` pair; the richer
    values are available as attributes (``rule``, ``role_edges``,
    ``evaluated_at``) and through ``to_dict()``.
    """

    __slots__ = ("allowed", "explanation", "request")

    def __init__(self, allowed, explanation, request=()):
        self.allowed = bool(allowed)
        self.explanation = explanation
        self.request = tuple(request)

    @property
    def rule(self):
        return list(self.explanation)

    @property
    def role_edges(self):
        return list(getattr(self.explanation, "role_edges", ()))

    @property
    def evaluated_at(self):
        return getattr(self.explanation, "evaluated_at", None)

    @property
    def request_values(self):
        return self.request

    def to_dict(self):
        return {
            "allowed": self.allowed,
            "rule": self.rule,
            "role_edges": [edge.to_policy() for edge in self.role_edges],
            "evaluated_at": self.evaluated_at.isoformat(sep=" ") if self.evaluated_at is not None else None,
            "request": list(self.request),
        }

    def __iter__(self):
        # Keeps ``allowed, explanation = result`` working.
        yield self.allowed
        yield self.explanation

    def __getitem__(self, index):
        if isinstance(index, str):
            return self.to_dict()[index]
        return (self.allowed, self.explanation)[index]

    def __eq__(self, other):
        if isinstance(other, EvaluationResult):
            return (self.allowed, self.explanation) == (other.allowed, other.explanation)
        if isinstance(other, tuple):
            return (self.allowed, self.explanation) == other
        return NotImplemented

    def __repr__(self):
        return "EvaluationResult(allowed={!r}, rule={!r}, role_edges={!r})".format(
            self.allowed, self.rule, self.role_edges
        )


class LinkConditionSnapshot:
    """the link conditions and their outcome for one batch.

    The parameters are copied when the batch starts, so changing them through
    ``set_named_domain_link_condition_func_params`` while the batch runs cannot
    make later requests disagree with earlier ones.  The outcome of each
    condition is memoised as well: a condition that consults a clock of its own
    is still asked only once for the batch.
    """

    def __init__(self, conditions, domain_matchers=None, pre_evaluate=True):
        self.conditions = dict(conditions)
        self.domain_matchers = dict(domain_matchers or {})
        self.results = {}
        self.errors = {}
        if pre_evaluate:
            self._freeze()

    def _freeze(self):
        """asks every known condition once, before the batch reads any request.

        A condition that closes over its own clock can therefore expire while
        the batch is running without splitting the batch's answers.  A failing
        condition is remembered and re-raised only if a request actually needs
        that edge.
        """
        for key, (fn, params) in self.conditions.items():
            if fn is None:
                continue
            try:
                self.results[key] = bool(fn(*params))
            except Exception as error:
                self.errors[key] = error

    def condition_for(self, key):
        """returns the ``(fn, params)`` captured for a link, or None.

        A request domain that only matches a policy domain through a custom
        domain matching function is resolved to the captured policy domain, so
        the batch keeps using the view it started with.
        """
        if key in self.conditions:
            return self.conditions[key]

        ptype, user, role, domain = key
        if domain is None:
            return None
        matcher = self.domain_matchers.get(ptype)
        if matcher is None:
            return None
        for (key_ptype, key_user, key_role, key_domain), value in self.conditions.items():
            if key_ptype != ptype or key_user != user or key_role != role or key_domain is None:
                continue
            try:
                if matcher(domain, key_domain):
                    return value
            except Exception:
                continue
        return None

    def decide(self, key, fn, params):
        if key in self.results:
            return self.results[key]
        if key in self.errors:
            raise self.errors[key]
        result = bool(fn(*params)) if fn is not None else True
        self.results[key] = result
        return result


def current_link_condition_snapshot():
    return _link_conditions.get()


@contextmanager
def link_condition_snapshot(conditions, domain_matchers=None):
    """installs a batch-wide view of conditional role edges."""
    snapshot = LinkConditionSnapshot(conditions, domain_matchers)
    token = _link_conditions.set(snapshot)
    try:
        yield snapshot
    finally:
        _link_conditions.reset(token)


def record_role_edge(edge):
    """adds an edge to the active trace, ignoring duplicates in one path."""
    sink = _role_edges.get()
    if sink is None:
        return
    key = tuple(edge)
    for existing in sink:
        if tuple(existing) == key:
            return
    sink.append(edge)


@contextmanager
def capture_role_edges():
    """starts a new edge trace for the duration of the block."""
    sink = []
    token = _role_edges.set(sink)
    try:
        yield sink
    finally:
        _role_edges.reset(token)
