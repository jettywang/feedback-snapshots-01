# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import collections.abc
import logging
from typing import Any

from typing_extensions import deprecated

from opentelemetry.context import get_current
from opentelemetry.context.context import Context
from opentelemetry.propagators import textmap
from opentelemetry.propagators.policy import (
    BaggagePolicy,
    DestinationPropagationPolicy,
    coerce_baggage_policy,
    coerce_propagation_policy,
)

logger = logging.getLogger(__name__)


class CompositePropagator(textmap.TextMapPropagator):
    """CompositePropagator provides a mechanism for combining multiple
    propagators into a single one.

    Args:
        propagators: the list of propagators to use
        policy: optional destination-aware or baggage-only propagation policy
    """

    def __init__(
        self,
        propagators: collections.abc.Sequence[textmap.TextMapPropagator] | None = None,
        policy: BaggagePolicy | DestinationPropagationPolicy | Any = None,
        *,
        destination_policy: DestinationPropagationPolicy | Any = None,
        destination_policies: collections.abc.Mapping[Any, Any] | None = None,
        policies: collections.abc.Mapping[Any, Any] | None = None,
        rules: collections.abc.Mapping[Any, Any] | None = None,
        baggage_policy: BaggagePolicy | Any = None,
        allowed_baggage_keys: Any = None,
        allowed_keys: Any = None,
        denied_keys: Any = None,
        predicate: Any = None,
        default_policy: Any = None,
        merge_existing_values: bool | None = None,
    ) -> None:
        if allowed_keys is not None and allowed_baggage_keys is None:
            allowed_baggage_keys = allowed_keys
        if baggage_policy is None and (denied_keys is not None or predicate is not None):
            baggage_policy = BaggagePolicy(
                allowed_keys=allowed_keys if not isinstance(allowed_keys, (dict,)) else None,
                denied_keys=denied_keys,
                predicate=predicate,
            )

        self._propagators = propagators if propagators is not None else _default_propagators()
        self._merge_existing_values = merge_existing_values
        self._destination_policy: DestinationPropagationPolicy | None = None
        self._baggage_policy: BaggagePolicy | None = None

        if isinstance(policy, DestinationPropagationPolicy):
            self._destination_policy = policy
            self._baggage_policy = coerce_baggage_policy(baggage_policy)
        elif destination_policy is not None:
            if isinstance(destination_policy, DestinationPropagationPolicy):
                self._destination_policy = destination_policy
            else:
                self._destination_policy = DestinationPropagationPolicy(
                    destination_policy,
                    destination_policies=destination_policies,
                    policies=policies,
                    rules=rules,
                    default_policy=default_policy,
                    allowed_baggage_keys=allowed_baggage_keys,
                )
            self._baggage_policy = coerce_baggage_policy(baggage_policy)
        elif (
            destination_policies is not None
            or policies is not None
            or rules is not None
            or allowed_baggage_keys is not None
        ):
            self._destination_policy = DestinationPropagationPolicy(
                destination_policies,
                policies=policies,
                destination_policies=destination_policies,
                rules=rules,
                default_policy=default_policy,
                allowed_baggage_keys=allowed_baggage_keys,
            )
            self._baggage_policy = coerce_baggage_policy(baggage_policy)
        else:
            coerced_policy = coerce_propagation_policy(policy) if policy is not None else None
            if isinstance(coerced_policy, DestinationPropagationPolicy):
                self._destination_policy = coerced_policy
                self._baggage_policy = coerce_baggage_policy(baggage_policy)
            else:
                self._destination_policy = None
                self._baggage_policy = coerce_baggage_policy(
                    coerced_policy if coerced_policy is not None else baggage_policy
                )

    def extract(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
    ) -> Context:
        """Run each of the configured propagators with the given context and carrier.
        Propagators are run in the order they are configured, if multiple
        propagators write the same context key, the propagator later in the list
        will override previous propagators.

        See `opentelemetry.propagators.textmap.TextMapPropagator.extract`
        """
        for propagator in self._propagators:
            context = propagator.extract(carrier, context, getter=getter)
        return context  # type: ignore

    def inject(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        setter: textmap.Setter[textmap.CarrierT] = textmap.default_setter,
        destination: Any = None,
        *,
        target: Any = None,
        destination_name: Any = None,
        dest: Any = None,
        peer: Any = None,
        endpoint: Any = None,
        policy: BaggagePolicy | DestinationPropagationPolicy | Any = None,
        baggage_policy: BaggagePolicy | Any = None,
        getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
        merge_existing_values: bool | None = None,
        **kwargs: Any,
    ) -> None:
        """Run each configured propagator.

        When a propagation policy is configured, ``context`` remains
        unchanged. A policy-filtered derived context is used only for this
        injection, and stale carrier baggage is overwritten or removed.
        """
        effective_destination = _first_not_none(
            destination,
            target,
            destination_name,
            dest,
            peer,
            endpoint,
            kwargs.pop("destination_id", None),
            kwargs.pop("destination_key", None),
            kwargs.pop("service", None),
        )
        if kwargs:
            unexpected = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected inject option(s): {unexpected}")

        effective_policy = self._resolve_baggage_policy(
            effective_destination,
            policy,
            baggage_policy,
        )

        if effective_policy is None:
            for propagator in self._propagators:
                propagator.inject(carrier, context, setter=setter)
            return

        source_context = get_current() if context is None else context
        should_merge = self._merge_existing_values if merge_existing_values is None else merge_existing_values
        injection_context = effective_policy.context_for_injection(
            source_context,
            carrier=carrier,
            getter=getter,
            merge_existing_values=should_merge,
        )

        for propagator in self._propagators:
            propagator.inject(carrier, injection_context, setter=setter)

        effective_policy.reconcile_carrier(carrier, setter, injection_context)

    def _resolve_baggage_policy(
        self,
        destination: Any,
        call_policy: Any,
        call_baggage_policy: Any,
    ) -> BaggagePolicy | None:
        if isinstance(call_policy, DestinationPropagationPolicy):
            return call_policy.policy_for(destination)
        if call_policy is not None:
            coerced_policy = coerce_propagation_policy(call_policy)
            if isinstance(coerced_policy, DestinationPropagationPolicy):
                return coerced_policy.policy_for(destination)
            return coerced_policy

        if call_baggage_policy is not None:
            return coerce_baggage_policy(call_baggage_policy)
        if self._baggage_policy is not None:
            return self._baggage_policy
        if self._destination_policy is not None:
            return self._destination_policy.policy_for(destination)
        return None

    def for_destination(
        self,
        destination: Any,
        policy: BaggagePolicy | DestinationPropagationPolicy | None = None,
    ) -> DestinationPropagator:
        """Return a propagator bound to one destination name."""
        return DestinationPropagator(self, destination, policy=policy)

    @property
    def fields(self) -> set[str]:
        """Returns a set with the fields set in `inject`.

        See
        `opentelemetry.propagators.textmap.TextMapPropagator.fields`
        """
        composite_fields = set()

        for propagator in self._propagators:
            for field in propagator.fields:
                composite_fields.add(field)

        return composite_fields


class PolicyAwareCompositePropagator(CompositePropagator):
    """A :class:`CompositePropagator` with explicit propagation policy support."""


class DestinationAwareCompositePropagator(CompositePropagator):
    """Composite propagator bound to a default destination."""

    def __init__(
        self,
        propagators: collections.abc.Sequence[textmap.TextMapPropagator] | None = None,
        destination: Any = None,
        policy: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(propagators, policy=policy, **kwargs)
        self.destination = destination

    def inject(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        setter: textmap.Setter[textmap.CarrierT] = textmap.default_setter,
        destination: Any = None,
        **kwargs: Any,
    ) -> None:
        super().inject(
            carrier,
            context=context,
            setter=setter,
            destination=destination if destination is not None else self.destination,
            **kwargs,
        )


DestinationCompositePropagator = DestinationAwareCompositePropagator
FilteringCompositePropagator = PolicyAwareCompositePropagator
PolicyAwarePropagator = PolicyAwareCompositePropagator


class DestinationPropagator(textmap.TextMapPropagator):
    """Binds a propagator to one destination without changing its context."""

    def __init__(
        self,
        propagator: CompositePropagator | textmap.TextMapPropagator,
        destination: Any = None,
        *,
        name: Any = None,
        policy: Any = None,
    ) -> None:
        self._propagator = propagator
        self.destination = destination if destination is not None else name
        self._policy = policy

    def extract(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
    ) -> Context:
        return self._propagator.extract(carrier, context, getter=getter)

    def inject(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        setter: textmap.Setter[textmap.CarrierT] = textmap.default_setter,
        destination: Any = None,
        **kwargs: Any,
    ) -> None:
        effective_destination = destination if destination is not None else self.destination
        inject: Any = self._propagator.inject
        try:
            inject(
                carrier,
                context=context,
                setter=setter,
                destination=effective_destination,
                policy=self._policy,
                **kwargs,
            )
        except TypeError:
            # Plain TextMapPropagator implementations do not accept policy
            # keywords. CompositePropagator is the expected policy-aware target.
            if effective_destination is not None or self._policy is not None or kwargs:
                raise
            inject(carrier, context=context, setter=setter)

    @property
    def fields(self) -> set[str]:
        return self._propagator.fields


DestinationAwarePropagator = DestinationPropagator
DestinationBasedPropagator = DestinationPropagator
DestinationScopedPropagator = DestinationPropagator
PerDestinationPropagator = DestinationPropagator


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _default_propagators() -> collections.abc.Sequence[textmap.TextMapPropagator]:
    from opentelemetry.baggage.propagation import W3CBaggagePropagator  # noqa: PLC0415
    from opentelemetry.trace.propagation.tracecontext import (  # noqa: PLC0415
        TraceContextTextMapPropagator,
    )

    return [TraceContextTextMapPropagator(), W3CBaggagePropagator()]


@deprecated("You should use CompositePropagator. Deprecated since version 1.2.0.")
class CompositeHTTPPropagator(CompositePropagator):
    """CompositeHTTPPropagator provides a mechanism for combining multiple
    propagators into a single one.
    """
