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

"""Consistent request-attribute views for one authorization decision.

ABAC requests pass ordinary Python objects to the matcher.  Those objects are
often live: an application may update the row they were loaded from, or a
custom function may change them, while the enforcer is still walking the
policy.  A decision that reads such an object more than once can then mix two
versions of the same attributes.

:class:`AttributeView` captures one version of the request values.  The
``enforce*_with_attributes`` entry points evaluate the whole decision -- every
policy row, every matcher evaluation and every custom function that works from
the request arguments -- against that one view.  A later decision captures a
new view and therefore observes updates.

The view is deliberately opt-in.  ``enforce()`` and ``enforce_ex()`` keep
passing the caller's objects through unchanged, so existing callers and custom
functions are unaffected.  The compatibility boundary for custom functions is:
a function registered with ``add_function()`` keeps receiving the values the
matcher passes it; through the new entry point those values come from the
view.  Functions that need the exact view can call
:func:`current_attribute_view`; functions that mutate their arguments, rely on
object identity, or read unrelated global state are outside the guarantee.
"""

import copy
import itertools
import threading
from contextvars import ContextVar
from datetime import datetime


__all__ = [
    "AttributeDecision",
    "AttributeExplanation",
    "AttributeView",
    "capture_attributes",
    "current_attribute_view",
    "current_attributes",
    "use_attribute_view",
]

_version_counter = itertools.count(1)
_version_lock = threading.Lock()
_current_view = ContextVar("casbin_attribute_view", default=None)


def _next_version():
    # itertools.count() is atomic under CPython, but an explicit lock keeps the
    # identity unique on implementations that do not guarantee that.
    with _version_lock:
        return next(_version_counter)


def _snapshot_values(values):
    """returns ``(values, isolated, fallbacks)`` for one decision.

    Copying the tuple as a whole (rather than value by value) preserves shared
    references and cycles between the request arguments.  If a value cannot be
    deep-copied, a shallow copy still gives the decision its own top-level
    object, and a value that cannot be copied at all stays a live reference.
    Both cases are reported in ``fallbacks``; ``isolated`` is only True when
    every value was deep-copied.
    """

    try:
        return copy.deepcopy(tuple(values)), True, ()
    except Exception:
        pass

    captured = []
    fallbacks = []
    isolated = True
    for index, value in enumerate(values):
        try:
            captured.append(copy.deepcopy(value))
            continue
        except Exception:
            isolated = False

        try:
            captured.append(copy.copy(value))
        except Exception:
            captured.append(value)
        fallbacks.append(index)
    return tuple(captured), isolated, tuple(fallbacks)


class AttributeView:
    """one consistent view of the attributes used by a decision.

    ``AttributeView.capture(*rvals)`` deep-copies the request values once.  The
    same instance can be passed to several ``enforce*_with_attributes`` calls
    (for example to evaluate several named matchers for one request) and every
    call sees the same version, even if the original objects change in between.
    Values that cannot be deep-copied are shallow-copied where possible; those
    indices are listed in ``fallbacks`` and ``isolated`` becomes False.

    ``AttributeView.live(*rvals)`` keeps the original references.  It is useful
    when a caller has already frozen or projected the values itself; the
    ``isolated`` flag is False because the view does not guarantee isolation
    from later changes.

    ``AttributeView.from_mapping(mapping, order=None)`` builds a view from an
    explicit ``{token: value}`` mapping, so the application can hand Casbin the
    exact attribute projection it wants the decision to use.
    """

    __slots__ = ("_values", "_tokens", "_named", "version", "captured_at", "isolated", "fallbacks")

    def __init__(self, values, tokens=None, named=None, version=None, captured_at=None, isolated=True, fallbacks=()):
        self._values = tuple(values)
        self._tokens = tuple(tokens) if tokens is not None else None
        self._named = dict(named) if named is not None else None
        self.version = version if version is not None else _next_version()
        self.captured_at = captured_at if captured_at is not None else datetime.now()
        self.isolated = bool(isolated)
        self.fallbacks = tuple(fallbacks)

    @classmethod
    def capture(cls, *rvals):
        """captures one consistent, deep-copied version of the request values."""
        values, isolated, fallbacks = _snapshot_values(rvals)
        return cls(values, isolated=isolated, fallbacks=fallbacks)

    @classmethod
    def live(cls, *rvals):
        """uses the request values as they are, without copying them."""
        return cls(rvals, isolated=False)

    @classmethod
    def from_mapping(cls, mapping, order=None, isolate=True):
        """builds a view from an explicit ``{token: value}`` mapping.

        ``order`` lists the token names in request-definition order.  It is only
        needed when the mapping itself is not ordered the way the request is;
        binding by token name works either way.

        ``isolate`` (the default) copies the values, so the mapping describes a
        version rather than a reference to objects the caller keeps changing.
        Pass ``isolate=False`` when the mapping already holds values that must
        keep their identity.
        """
        mapping = dict(mapping)
        keys = tuple(order) if order is not None else tuple(mapping)
        values = tuple(mapping[key] for key in keys)
        isolated = True
        fallbacks = ()
        if isolate:
            values, isolated, fallbacks = _snapshot_values(values)
        # Keep the keyed form in step with the values: binding by token name must
        # read the same captured version, not the caller's live mapping.
        return cls(values, tokens=keys, named=dict(zip(keys, values)), isolated=isolated, fallbacks=fallbacks)

    @property
    def values(self):
        """the request values, in request-definition order."""
        return self._values

    @property
    def tokens(self):
        """the request tokens of the view, once it has been bound."""
        return self._tokens

    @property
    def attributes(self):
        """the view as a ``{token: value}`` mapping."""
        return self.as_dict()

    @property
    def is_isolated(self):
        return self.isolated

    @property
    def is_fully_isolated(self):
        """True when every value was deep-copied, so no live reference remains."""
        return self.isolated and not self.fallbacks

    def bind(self, tokens):
        """returns this view bound to ``tokens``, without copying the values.

        Binding is what lets a caller reuse one capture for several matchers
        with different request definitions: the values stay the same, only the
        names used to report them change.
        """
        tokens = tuple(tokens)
        if self._named is not None:
            values = tuple(self._named_value(token) for token in tokens)
        elif len(tokens) != len(self._values):
            raise RuntimeError("invalid request size")
        else:
            values = self._values
        return AttributeView(
            values,
            tokens=tokens,
            named=None,
            version=self.version,
            captured_at=self.captured_at,
            isolated=self.isolated,
            fallbacks=self.fallbacks,
        )

    def _named_value(self, token):
        candidates = [token]
        if "_" in token:
            prefix, suffix = token.split("_", 1)
            candidates.append(prefix + "." + suffix)
            candidates.append(suffix)
        for candidate in candidates:
            if candidate in self._named:
                return self._named[candidate]
        raise KeyError("attribute {!r} is not present in the view".format(token))

    def as_dict(self):
        """reports the captured attributes, keyed by request token."""
        if self._tokens is not None:
            return dict(zip(self._tokens, self._values))
        if self._named is not None:
            return dict(self._named)
        return {index: value for index, value in enumerate(self._values)}

    def get(self, name, default=None):
        """returns one attribute by token, short name or an index."""
        try:
            return self[name]
        except (KeyError, IndexError):
            return default

    def _index_for(self, key):
        if isinstance(key, int):
            if -len(self._values) <= key < len(self._values):
                return key
            raise IndexError(key)

        tokens = self._tokens or ()
        if key in tokens:
            return tokens.index(key)

        normalized = key.replace(".", "_")
        if normalized in tokens:
            return tokens.index(normalized)
        for index, token in enumerate(tokens):
            if "_" in token and token.split("_", 1)[1] == key:
                return index

        raise KeyError(key)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return self._values[key]
        return self._values[self._index_for(key)]

    def __contains__(self, key):
        try:
            self._index_for(key)
        except (KeyError, IndexError):
            return False
        return True

    def __len__(self):
        return len(self._values)

    def __iter__(self):
        return iter(self._values)

    def to_dict(self):
        """a description of this view and the values it captured.

        The attribute values are returned as they are.  They are not converted
        to JSON, because request objects are arbitrary Python values.
        """
        return {
            "version": self.version,
            "captured_at": self.captured_at.isoformat(sep=" "),
            "isolated": self.isolated,
            "fully_isolated": self.is_fully_isolated,
            "fallbacks": list(self.fallbacks),
            "tokens": list(self._tokens or ()),
            "attributes": self.as_dict(),
        }

    def __repr__(self):
        return "AttributeView(version={!r}, tokens={!r}, attributes={!r})".format(
            self.version, self._tokens, self.as_dict()
        )

    def __eq__(self, other):
        if isinstance(other, AttributeView):
            return self.version == other.version
        return NotImplemented

    def __hash__(self):
        # Two views are the same version when they share an identity, even if
        # the captured request values are unhashable arbitrary objects.
        return hash(self.version)

    def copy(self):
        """a detached view with a fresh identity and a fresh copy of the values.

        ``bind()`` keeps the identity because it relabels one capture; ``copy()``
        is for a caller that wants a new decision version from these values.
        """
        values, isolated, fallbacks = _snapshot_values(self._values)
        return AttributeView(
            values,
            tokens=self._tokens,
            named=dict(zip(self._tokens, values)) if self._tokens is not None else None,
            isolated=isolated,
            fallbacks=fallbacks,
        )


class AttributeExplanation(list):
    """the responding policy rule, plus the attribute view used to decide it.

    It remains a plain list of policy fields, so callers that unpack or compare
    ``enforce_ex`` style explanations keep working.
    """

    def __init__(self, rule=(), attributes=None):
        super().__init__(rule)
        self.attributes = attributes

    @property
    def rule(self):
        return list(self)

    @property
    def view(self):
        return self.attributes

    def copy(self):
        return AttributeExplanation(self, self.attributes)

    def to_dict(self):
        return {
            "rule": list(self),
            "attribute_version": getattr(self.attributes, "version", None),
            "attributes": self.attributes.as_dict() if self.attributes is not None else None,
        }


class AttributeDecision(tuple):
    """a decision together with the attribute view it used.

    Unpacks like the historical ``(allowed, explanation)`` pair.  The view is
    available as ``decision.attributes`` and ``decision.view``; the explanation
    carries it as well, so both of the usual access styles work.
    """

    def __new__(cls, allowed, explanation, attributes=None):
        decision = super().__new__(cls, (bool(allowed), explanation))
        decision.attributes = attributes
        return decision

    @property
    def allowed(self):
        return self[0]

    @property
    def explanation(self):
        return self[1]

    @property
    def view(self):
        return self.attributes

    @property
    def rule(self):
        return list(self[1])

    @property
    def attribute_version(self):
        return getattr(self.attributes, "version", None)

    @property
    def request_values(self):
        return getattr(self.attributes, "values", ())

    def to_dict(self):
        return {
            "allowed": self[0],
            "rule": self.rule,
            "attribute_version": self.attribute_version,
            "attributes": self.attributes.as_dict() if self.attributes is not None else None,
        }

    def __repr__(self):
        return "AttributeDecision(allowed={!r}, rule={!r}, attribute_version={!r})".format(
            self[0], self.rule, self.attribute_version
        )


def capture_attributes(*rvals):
    """module-level convenience for :meth:`AttributeView.capture`."""
    return AttributeView.capture(*rvals)


def current_attribute_view():
    """returns the view of the decision currently being evaluated, or None.

    This is available while an ``enforce*_with_attributes`` call is running.
    A custom function registered with ``add_function()`` can use it to inspect
    the exact version used for every policy row, without changing its existing
    signature.  Outside that entry point the function returns None.
    """
    return _current_view.get()


def current_attributes():
    """the current view as a ``{token: value}`` mapping, or None."""
    view = _current_view.get()
    return view.as_dict() if view is not None else None


class use_attribute_view:
    """context manager that publishes a view to custom functions.

    It is used by the enforcer itself; applications normally do not need it.
    """

    def __init__(self, view):
        self._view = view
        self._token = None

    def __enter__(self):
        self._token = _current_view.set(self._view)
        return self._view

    def __exit__(self, exc_type, exc_value, traceback):
        _current_view.reset(self._token)
        return False
