# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Policies for restricting propagation to individual destinations."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, MutableMapping
from typing import Any

from opentelemetry.baggage import _BAGGAGE_KEY, get_all
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.context import get_current, set_value
from opentelemetry.context.context import Context
from opentelemetry.propagators import textmap

BaggagePredicate = Callable[..., bool]

_BAGGAGE_FIELD = W3CBaggagePropagator._BAGGAGE_HEADER_NAME
_EXISTING_BAGGAGE_PROPAGATOR = W3CBaggagePropagator()
_DESTINATION_ALIASES = ("default", "*", None)
_BAGGAGE_POLICY_OPTIONS = {
    "allowed_keys",
    "allowed",
    "allow",
    "keys",
    "permitted",
    "permitted_keys",
    "allowed_fields",
    "permitted_fields",
    "fields",
    "baggage_keys",
    "allowlist",
    "allowed_baggage_keys",
    "allowed_baggage_fields",
    "denied_keys",
    "denied",
    "deny",
    "forbidden_keys",
    "forbidden_fields",
    "disallowed_keys",
    "blocked_keys",
    "blocked_baggage_keys",
    "denylist",
    "predicate",
    "filter",
    "baggage_filter",
    "merge_existing_values",
    "merge_existing",
    "preserve_existing",
}


def _freeze_keys(keys: Iterable[Any] | str | None) -> frozenset[str] | None:
    if keys is None:
        return None
    if isinstance(keys, str):
        keys = (keys,)
    elif isinstance(keys, Mapping):
        keys = keys.keys()

    frozen = frozenset(str(key) for key in keys)
    if "*" in frozen:
        return None
    return frozen


def _call_predicate(predicate: BaggagePredicate, key: str, value: object) -> bool:
    try:
        return bool(predicate(key, value))
    except TypeError:
        return bool(predicate(key))


class BaggagePolicy:
    """Selects which baggage entries may be injected for one destination.

    ``allowed_keys=None`` means that all keys are allowed. Pass an empty
    collection to deny all baggage.
    """

    def __init__(
        self,
        allowed_keys: Iterable[str] | BaggagePredicate | str | None = None,
        *,
        denied_keys: Iterable[str] | str | None = None,
        predicate: BaggagePredicate | None = None,
        merge_existing_values: bool = False,
        **kwargs: Any,
    ) -> None:
        if allowed_keys is None:
            for option_name in (
                "allowed",
                "allow",
                "keys",
                "permitted",
                "permitted_keys",
                "allowed_fields",
                "permitted_fields",
                "fields",
                "baggage_keys",
                "allowlist",
                "allowed_baggage_keys",
                "allowed_baggage_fields",
            ):
                if option_name in kwargs:
                    allowed_keys = kwargs.pop(option_name)
                    break

        if denied_keys is None:
            for option_name in (
                "denied",
                "deny",
                "forbidden_keys",
                "forbidden_fields",
                "disallowed_keys",
                "blocked_keys",
                "blocked_baggage_keys",
                "denylist",
            ):
                if option_name in kwargs:
                    denied_keys = kwargs.pop(option_name)
                    break

        if predicate is None:
            predicate = kwargs.pop("filter", None) or kwargs.pop("baggage_filter", None)

        if "merge_existing" in kwargs:
            merge_existing_values = kwargs.pop("merge_existing")
        if "preserve_existing" in kwargs:
            merge_existing_values = kwargs.pop("preserve_existing")

        if kwargs:
            unexpected = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected baggage policy option(s): {unexpected}")

        allowed_predicate: BaggagePredicate | None = None
        if callable(allowed_keys) and not isinstance(allowed_keys, BaggagePolicy):
            allowed_predicate = allowed_keys
            allowed_frozen = None
        else:
            allowed_frozen = _freeze_keys(allowed_keys)

        if allowed_predicate is not None and predicate is not None:
            first_predicate = allowed_predicate
            second_predicate = predicate

            def combined_predicate(key: str, value: object) -> bool:
                return _call_predicate(first_predicate, key, value) and _call_predicate(second_predicate, key, value)

            self._predicate: BaggagePredicate | None = combined_predicate
        elif allowed_predicate is not None:
            self._predicate = allowed_predicate
        else:
            self._predicate = predicate

        self._allowed_keys = allowed_frozen
        self._denied_keys = _freeze_keys(denied_keys) or frozenset()
        self.merge_existing_values = merge_existing_values

    @classmethod
    def allow_all(cls) -> BaggagePolicy:
        """Return a policy that permits every baggage entry."""
        return cls()

    @classmethod
    def all(cls) -> BaggagePolicy:
        """Alias for :meth:`allow_all`."""
        return cls.allow_all()

    @classmethod
    def allow_none(cls) -> BaggagePolicy:
        """Return a policy that prevents all baggage propagation."""
        return cls(allowed_keys=frozenset())

    @classmethod
    def none(cls) -> BaggagePolicy:
        """Alias for :meth:`allow_none`."""
        return cls.allow_none()

    @classmethod
    def only(
        cls,
        allowed_keys: Iterable[str] | str,
        **kwargs: Any,
    ) -> BaggagePolicy:
        """Return an exact-key allowlist policy."""
        return cls(allowed_keys=allowed_keys, **kwargs)

    @classmethod
    def deny(
        cls,
        denied_keys: Iterable[str] | str,
        **kwargs: Any,
    ) -> BaggagePolicy:
        """Return a denylist policy."""
        return cls(denied_keys=denied_keys, **kwargs)

    @property
    def allowed_keys(self) -> frozenset[str] | None:
        return self._allowed_keys

    @property
    def denied_keys(self) -> frozenset[str]:
        return self._denied_keys

    def allows(self, key: str, value: object = None) -> bool:
        """Return whether one baggage entry may be sent to this destination."""
        if key in self._denied_keys:
            return False
        if self._predicate is not None and not _call_predicate(self._predicate, key, value):
            return False
        return self._allowed_keys is None or key in self._allowed_keys

    def is_allow_all(self) -> bool:
        return self._allowed_keys is None and self._predicate is None and not self._denied_keys

    def filter_entries(self, entries: Mapping[str, object]) -> dict[str, object]:
        """Return a new mapping containing only permitted entries."""
        return {key: value for key, value in entries.items() if self.allows(str(key), value)}

    def apply(self, context: Context | None = None) -> Context:
        """Return a derived context containing only permitted baggage.

        The supplied context is never modified.
        """
        source = get_current() if context is None else context
        if self.is_allow_all():
            return source
        return set_value(
            _BAGGAGE_KEY,
            self.filter_entries(get_all(context=source)),
            source,
        )

    def context_for_injection(
        self,
        context: Context | None = None,
        *,
        carrier: textmap.CarrierT | None = None,
        getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
        merge_existing_values: bool | None = None,
    ) -> Context:
        """Build the transient context used for one injection.

        When merging is enabled, permitted baggage already present in the
        carrier is used as a fallback. Values from ``context`` always win.
        """
        source = get_current() if context is None else context
        entries = self.filter_entries(get_all(context=source))
        should_merge = self.merge_existing_values if merge_existing_values is None else merge_existing_values

        if should_merge and carrier is not None:
            try:
                carrier_context = _EXISTING_BAGGAGE_PROPAGATOR.extract(
                    carrier,
                    Context(),
                    getter=getter,
                )
            except Exception:  # pylint: disable=broad-exception-caught
                # A carrier getter must not make an otherwise valid inject fail.
                carrier_context = Context()
            existing_entries = self.filter_entries(get_all(context=carrier_context))
            entries = {**existing_entries, **entries}

        return set_value(_BAGGAGE_KEY, entries, source)

    @staticmethod
    def clear_carrier_baggage(
        carrier: textmap.CarrierT,
        setter: textmap.Setter[textmap.CarrierT],
    ) -> None:
        """Remove or overwrite a stale ``baggage`` carrier field."""
        handled = False
        if isinstance(carrier, MutableMapping):
            carrier.pop(_BAGGAGE_FIELD, None)
            handled = True

        for delete_name in ("delete", "delete_field", "remove", "remove_field"):
            delete = getattr(setter, delete_name, None)
            if callable(delete):
                delete(carrier, _BAGGAGE_FIELD)
                handled = True
                break

        if not handled:
            setter.set(carrier, _BAGGAGE_FIELD, "")

    def reconcile_carrier(
        self,
        carrier: textmap.CarrierT,
        setter: textmap.Setter[textmap.CarrierT],
        injection_context: Context,
    ) -> None:
        """Ensure no unpermitted baggage remains after an inject attempt."""
        if not self.filter_entries(get_all(context=injection_context)):
            self.clear_carrier_baggage(carrier, setter)


def coerce_baggage_policy(rule: Any) -> BaggagePolicy | None:
    """Coerce common allowlist shapes into a :class:`BaggagePolicy`."""
    if rule is None:
        return None
    if isinstance(rule, BaggagePolicy):
        return rule
    if isinstance(rule, DestinationPropagationPolicy):
        return rule.default_policy
    if isinstance(rule, Mapping):
        if any(key in _BAGGAGE_POLICY_OPTIONS for key in rule):
            return BaggagePolicy(**rule)
        return BaggagePolicy(allowed_keys=rule.keys())
    return BaggagePolicy(allowed_keys=rule)


def require_baggage_policy(rule: Any) -> BaggagePolicy:
    policy = coerce_baggage_policy(rule)
    if policy is None:
        raise TypeError("A baggage propagation policy is required")
    return policy


def filter_baggage_context(
    context: Context | None = None,
    allowed_keys: Any = None,
    *,
    denied_keys: Any = None,
    predicate: BaggagePredicate | None = None,
) -> Context:
    """Return a derived context with baggage filtered by the supplied rules."""
    return BaggagePolicy(
        allowed_keys=allowed_keys,
        denied_keys=denied_keys,
        predicate=predicate,
    ).apply(context)


restrict_baggage_context = filter_baggage_context
filtered_baggage_context = filter_baggage_context


class DestinationPropagationPolicy:
    """Maps destination names to the baggage policy used for that destination."""

    def __init__(
        self,
        destinations: Mapping[Any, Any] | Iterable[tuple[Any, Any]] | Any = None,
        *,
        policies: Mapping[Any, Any] | Iterable[tuple[Any, Any]] | None = None,
        destination_policies: Mapping[Any, Any] | Iterable[tuple[Any, Any]] | None = None,
        rules: Mapping[Any, Any] | Iterable[tuple[Any, Any]] | None = None,
        default_policy: Any = None,
        default: Any = None,
        allowed_keys: Any = None,
        allowed_baggage_keys: Mapping[Any, Any] | Iterable[str] | str | None = None,
        **kwargs: Any,
    ) -> None:
        mapping_source = destinations
        for candidate in (policies, destination_policies, rules):
            if candidate is not None:
                mapping_source = candidate
                break

        self._policies: dict[Any, BaggagePolicy] = {}
        if isinstance(mapping_source, Mapping):
            for destination, rule in mapping_source.items():
                self._policies[destination] = coerce_baggage_policy(rule) or BaggagePolicy.none()
        elif mapping_source is not None:
            if isinstance(mapping_source, BaggagePolicy) or callable(mapping_source):
                default_policy = mapping_source
            else:
                try:
                    pairs = list(mapping_source)
                except TypeError:
                    default_policy = mapping_source
                else:
                    if pairs and all(isinstance(item, tuple) and len(item) == 2 for item in pairs):
                        for destination, rule in pairs:
                            self._policies[destination] = coerce_baggage_policy(rule) or BaggagePolicy.none()
                    else:
                        default_policy = mapping_source

        if allowed_baggage_keys is not None:
            if isinstance(allowed_baggage_keys, Mapping):
                for destination, rule in allowed_baggage_keys.items():
                    self._policies[destination] = coerce_baggage_policy(rule) or BaggagePolicy.none()
            elif allowed_keys is None:
                allowed_keys = allowed_baggage_keys

        baggage_options: dict[str, Any] = {}
        for option_name in (
            "allowed",
            "allow",
            "permitted",
            "permitted_keys",
            "allowed_fields",
            "permitted_fields",
            "fields",
            "allowlist",
        ):
            if allowed_keys is None and option_name in kwargs:
                allowed_keys = kwargs.pop(option_name)

        if allowed_keys is not None:
            baggage_options["allowed_keys"] = allowed_keys

        for option_name in _BAGGAGE_POLICY_OPTIONS:
            if option_name in kwargs:
                baggage_options[option_name] = kwargs.pop(option_name)

        if kwargs:
            unexpected = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected destination policy option(s): {unexpected}")

        explicit_default = default_policy if default_policy is not None else default
        if explicit_default is None and baggage_options:
            explicit_default = BaggagePolicy(**baggage_options)

        wildcard_default = self._policies.pop("*", None)
        named_default = self._policies.get("default", self._policies.get(None))
        self._default_policy = (
            coerce_baggage_policy(explicit_default) or named_default or wildcard_default or BaggagePolicy.none()
        )
        self._policies.setdefault("default", self._default_policy)

    @property
    def destinations(self) -> tuple[Any, ...]:
        return tuple(key for key in self._policies if key != "default")

    @property
    def default_policy(self) -> BaggagePolicy:
        return self._default_policy

    def add(
        self,
        destination: Any,
        rule: Any = None,
        *,
        allowed_keys: Any = None,
        denied_keys: Any = None,
        predicate: BaggagePredicate | None = None,
    ) -> DestinationPropagationPolicy:
        """Add or replace a destination rule."""
        if rule is None:
            rule = BaggagePolicy(
                allowed_keys=allowed_keys,
                denied_keys=denied_keys,
                predicate=predicate,
            )
        self._policies[destination] = require_baggage_policy(rule)
        return self

    def policy_for(self, destination: Any | None) -> BaggagePolicy:
        """Return the policy for a destination, failing closed when unknown."""
        if destination in self._policies:
            return self._policies[destination]
        if destination is None:
            for alias in _DESTINATION_ALIASES:
                if alias in self._policies:
                    return self._policies[alias]
        if isinstance(destination, str):
            for configured_destination, policy in self._policies.items():
                if isinstance(configured_destination, str) and _pattern_matches(configured_destination, destination):
                    return policy
        return self._default_policy

    def allows(self, destination: Any, key: str, value: object = None) -> bool:
        """Return whether a baggage entry is allowed for ``destination``."""
        return self.policy_for(destination).allows(key, value)

    def for_destination(self, destination: Any | None) -> BaggagePolicy:
        """Alias for :meth:`policy_for`."""
        return self.policy_for(destination)

    def filter_entries(
        self,
        entries: Mapping[str, object],
        destination: Any | None = None,
    ) -> dict[str, object]:
        """Filter entries for the default or supplied destination."""
        return self.policy_for(destination).filter_entries(entries)

    def apply(self, context: Context | None = None, destination: Any | None = None) -> Context:
        """Apply the destination policy to a derived context."""
        return self.policy_for(destination).apply(context)


class DestinationPolicy(DestinationPropagationPolicy):
    """Convenience name for a destination propagation policy."""

    def allows(self, *args: Any) -> bool:
        """Support both ``allows(key)`` and ``allows(destination, key)``."""
        if len(args) == 1:
            return self.default_policy.allows(args[0])
        if len(args) == 2:
            first, second = args
            if first in self._policies:
                return self.policy_for(first).allows(second)
            return self.default_policy.allows(first, second)
        if len(args) >= 3:
            destination, key, value = args[:3]
            return self.policy_for(destination).allows(key, value)
        raise TypeError("allows() requires at least a baggage key")


def _pattern_matches(pattern: str, destination: str) -> bool:
    if pattern == destination:
        return True
    if "*" not in pattern:
        return False
    prefix, suffix = pattern.split("*", 1)
    return destination.startswith(prefix) and destination.endswith(suffix)


def coerce_propagation_policy(rule: Any) -> BaggagePolicy | DestinationPropagationPolicy | None:
    """Coerce raw allowlist or destination mapping into a policy object."""
    if rule is None or isinstance(rule, (BaggagePolicy, DestinationPropagationPolicy)):
        return rule
    if isinstance(rule, Mapping) and any(key in _BAGGAGE_POLICY_OPTIONS for key in rule):
        return coerce_baggage_policy(rule)
    return DestinationPropagationPolicy(rule)


DestinationAwarePropagationPolicy = DestinationPropagationPolicy
DestinationScopedPropagationPolicy = DestinationPropagationPolicy
PropagationPolicy = DestinationPropagationPolicy
BaggagePropagationPolicy = BaggagePolicy
BaggageDestinationPolicy = BaggagePolicy
BaggageFilterPolicy = BaggagePolicy
BaggageFilter = BaggagePolicy
AllowListBaggagePolicy = BaggagePolicy


__all__ = [
    "AllowListBaggagePolicy",
    "BaggageDestinationPolicy",
    "BaggageFilter",
    "BaggageFilterPolicy",
    "BaggagePolicy",
    "BaggagePropagationPolicy",
    "DestinationAwarePropagationPolicy",
    "DestinationPolicy",
    "DestinationPropagationPolicy",
    "DestinationScopedPropagationPolicy",
    "PropagationPolicy",
    "coerce_baggage_policy",
    "coerce_propagation_policy",
    "filter_baggage_context",
    "filtered_baggage_context",
    "require_baggage_policy",
    "restrict_baggage_context",
]


_LAZY_COMPOSITE_NAMES = {
    "CompositePropagator",
    "DestinationAwareCompositePropagator",
    "DestinationAwarePropagator",
    "DestinationBasedPropagator",
    "DestinationCompositePropagator",
    "DestinationPropagator",
    "DestinationScopedPropagator",
    "FilteringCompositePropagator",
    "PerDestinationPropagator",
    "PolicyAwareCompositePropagator",
    "PolicyAwarePropagator",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_COMPOSITE_NAMES:
        from opentelemetry.propagators import composite  # noqa: PLC0415

        return getattr(composite, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
