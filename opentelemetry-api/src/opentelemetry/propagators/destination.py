# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Destination-bound propagation policies and propagators."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import (
    CompositePropagator,
    DestinationAwareCompositePropagator,
    DestinationAwarePropagator,
    DestinationBasedPropagator,
    DestinationCompositePropagator,
    DestinationPropagator,
    DestinationScopedPropagator,
    FilteringCompositePropagator,
    PerDestinationPropagator,
    PolicyAwareCompositePropagator,
    PolicyAwarePropagator,
)
from opentelemetry.propagators.policy import (
    AllowListBaggagePolicy,
    BaggageFilter,
    BaggageFilterPolicy,
    BaggagePolicy,
    BaggagePropagationPolicy,
    DestinationAwarePropagationPolicy,
    DestinationPolicy,
    DestinationPropagationPolicy,
    DestinationScopedPropagationPolicy,
    PropagationPolicy,
)
from opentelemetry.propagators.textmap import TextMapPropagator, default_setter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


def destination_propagator(
    destination: Any,
    *,
    allowed_baggage_keys: Any = None,
    policy: Any = None,
    propagators: Sequence[TextMapPropagator] | None = None,
    include_trace: bool = True,
    include_baggage: bool = True,
) -> DestinationPropagator:
    """Create a trace+baggage composite bound to one destination."""
    configured_propagators: list[TextMapPropagator] = list(propagators or ())
    if propagators is None:
        if include_trace:
            configured_propagators.append(TraceContextTextMapPropagator())
        if include_baggage:
            configured_propagators.append(W3CBaggagePropagator())

    if policy is None and allowed_baggage_keys is not None:
        policy = BaggagePolicy(allowed_keys=allowed_baggage_keys)

    composite = CompositePropagator(configured_propagators, policy=policy)
    return DestinationPropagator(composite, destination, policy=policy)


def inject_for_destination(
    destination: Any,
    carrier: Any,
    context: Any = None,
    *,
    allowed_baggage_keys: Any = None,
    policy: Any = None,
    propagator: TextMapPropagator | None = None,
    setter: Any = default_setter,
) -> None:
    """Inject into one carrier using the policy bound to ``destination``."""
    if propagator is None:
        bound = destination_propagator(
            destination,
            allowed_baggage_keys=allowed_baggage_keys,
            policy=policy,
        )
    else:
        bound = DestinationPropagator(propagator, destination, policy=policy)
    bound.inject(carrier, context=context, setter=setter)


__all__ = [
    "AllowListBaggagePolicy",
    "BaggageFilter",
    "BaggageFilterPolicy",
    "BaggagePolicy",
    "BaggagePropagationPolicy",
    "CompositePropagator",
    "DestinationAwareCompositePropagator",
    "DestinationAwarePropagationPolicy",
    "DestinationAwarePropagator",
    "DestinationBasedPropagator",
    "DestinationCompositePropagator",
    "DestinationPolicy",
    "DestinationPropagationPolicy",
    "DestinationPropagator",
    "DestinationScopedPropagationPolicy",
    "DestinationScopedPropagator",
    "FilteringCompositePropagator",
    "PerDestinationPropagator",
    "PolicyAwareCompositePropagator",
    "PolicyAwarePropagator",
    "PropagationPolicy",
    "destination_propagator",
    "inject_for_destination",
]
