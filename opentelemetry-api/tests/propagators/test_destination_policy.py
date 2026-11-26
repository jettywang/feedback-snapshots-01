# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor

from opentelemetry import propagate
from opentelemetry.baggage import get_all, set_baggage
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.context import Context
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.propagators.destination import (
    BaggagePolicy,
    DestinationPropagationPolicy,
    DestinationPropagator,
    PolicyAwareCompositePropagator,
    destination_propagator,
    inject_for_destination,
)
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    get_current_span,
    set_span_in_context,
)
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

TRACE_ID = 0x0AF7651916CD43DD8448EB211C80319C
SPAN_ID = 0x00F067AA0BA902B7
INTERNAL = "internal-accounting"
EXTERNAL = "external-risk-control"


def _full_context() -> Context:
    span_context = SpanContext(
        trace_id=TRACE_ID,
        span_id=SPAN_ID,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    context = set_span_in_context(NonRecordingSpan(span_context), Context())
    context = set_baggage("account.id", "acct-1001", context)
    context = set_baggage("risk.score", "72", context)
    context = set_baggage("internal.signing_key", "do-not-share", context)
    return context


def _policy() -> DestinationPropagationPolicy:
    return DestinationPropagationPolicy(
        {
            INTERNAL: BaggagePolicy.allow_all(),
            EXTERNAL: BaggagePolicy.only({"risk.score"}),
        }
    )


def _propagator(**kwargs: object) -> PolicyAwareCompositePropagator:
    return PolicyAwareCompositePropagator(
        [TraceContextTextMapPropagator(), W3CBaggagePropagator()],
        _policy(),
        **kwargs,
    )


def _baggage_from_carrier(carrier: dict[str, str]) -> dict[str, object]:
    context = W3CBaggagePropagator().extract(carrier)
    return dict(get_all(context))


def test_same_context_injects_two_destinations_without_mutating_it() -> None:
    source_context = _full_context()
    internal_carrier: dict[str, str] = {}
    external_carrier: dict[str, str] = {}
    propagator = _propagator()

    with ThreadPoolExecutor(max_workers=2) as executor:
        internal_future = executor.submit(
            propagator.inject,
            internal_carrier,
            source_context,
            destination=INTERNAL,
        )
        external_future = executor.submit(
            propagator.inject,
            external_carrier,
            source_context,
            destination=EXTERNAL,
        )
        internal_future.result()
        external_future.result()

    internal_baggage = _baggage_from_carrier(internal_carrier)
    external_baggage = _baggage_from_carrier(external_carrier)

    assert internal_baggage == {
        "account.id": "acct-1001",
        "risk.score": "72",
        "internal.signing_key": "do-not-share",
    }
    assert external_baggage == {"risk.score": "72"}
    assert "traceparent" in external_carrier

    extracted = TraceContextTextMapPropagator().extract(external_carrier)
    extracted_span_context = get_current_span(extracted).get_span_context()
    assert extracted_span_context.trace_id == TRACE_ID
    assert extracted_span_context.span_id == SPAN_ID

    assert dict(get_all(source_context)) == {
        "account.id": "acct-1001",
        "risk.score": "72",
        "internal.signing_key": "do-not-share",
    }


def test_inbound_context_remains_complete_for_internal_processing() -> None:
    inbound = {
        "traceparent": ("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"),
        "baggage": "account.id=acct-1001,risk.score=72,internal.signing_key=do-not-share",
    }
    composite = CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])

    context = composite.extract(inbound)

    assert dict(get_all(context)) == {
        "account.id": "acct-1001",
        "risk.score": "72",
        "internal.signing_key": "do-not-share",
    }
    assert get_current_span(context).get_span_context().trace_id == TRACE_ID

    internal_carrier: dict[str, str] = {}
    _propagator().inject(internal_carrier, context, destination=INTERNAL)
    assert _baggage_from_carrier(internal_carrier)["internal.signing_key"] == "do-not-share"


def test_existing_forbidden_carrier_values_are_overwritten() -> None:
    carrier = {"baggage": ("account.id=stale-account," "risk.score=stale-score," "internal.signing_key=stale-secret")}

    _propagator().inject(carrier, _full_context(), destination=EXTERNAL)

    assert _baggage_from_carrier(carrier) == {"risk.score": "72"}
    assert "stale-account" not in carrier["baggage"]
    assert "stale-score" not in carrier["baggage"]
    assert "stale-secret" not in carrier["baggage"]


def test_carrier_baggage_field_is_removed_when_nothing_is_allowed() -> None:
    policy = DestinationPropagationPolicy(
        {EXTERNAL: BaggagePolicy.allow_none()},
        default_policy=BaggagePolicy.allow_all(),
    )
    propagator = PolicyAwareCompositePropagator(
        [TraceContextTextMapPropagator(), W3CBaggagePropagator()],
        policy,
    )
    carrier = {"baggage": "internal.signing_key=stale-secret"}

    propagator.inject(carrier, _full_context(), destination=EXTERNAL)

    assert "baggage" not in carrier
    assert "traceparent" in carrier


def test_permitted_existing_carrier_values_can_be_merged() -> None:
    policy = BaggagePolicy.only(
        {"risk.score", "carrier.only"},
        merge_existing_values=True,
    )
    propagator = CompositePropagator(
        [W3CBaggagePropagator()],
        policy,
        merge_existing_values=True,
    )
    carrier = {"baggage": "risk.score=carrier-value,carrier.only=keep,secret=remove"}
    context = set_baggage("risk.score", "context-value", Context())

    propagator.inject(carrier, context)

    assert _baggage_from_carrier(carrier) == {
        "risk.score": "context-value",
        "carrier.only": "keep",
    }


def test_unknown_destination_fails_closed() -> None:
    propagator = _propagator()
    carrier = {}

    propagator.inject(carrier, _full_context(), destination="untrusted-new-destination")

    assert "baggage" not in carrier
    assert "traceparent" in carrier


def test_w3c_baggage_propagator_allowlist_does_not_modify_context() -> None:
    context = _full_context()
    propagator = W3CBaggagePropagator(allowed_keys={"risk.score"})
    carrier: dict[str, str] = {"baggage": "internal.signing_key=stale"}

    propagator.inject(carrier, context)

    assert _baggage_from_carrier(carrier) == {"risk.score": "72"}
    assert set(get_all(context)) == {
        "account.id",
        "risk.score",
        "internal.signing_key",
    }


def test_bound_destination_propagator_and_factory() -> None:
    context = _full_context()
    bound = _propagator().for_destination(EXTERNAL)
    carrier: dict[str, str] = {}

    assert isinstance(bound, DestinationPropagator)
    bound.inject(carrier, context)

    assert _baggage_from_carrier(carrier) == {"risk.score": "72"}
    assert get_current_span(TraceContextTextMapPropagator().extract(carrier)).get_span_context().trace_id == TRACE_ID

    factory_carrier: dict[str, str] = {}
    factory = destination_propagator(
        EXTERNAL,
        allowed_baggage_keys={"risk.score"},
    )
    factory.inject(factory_carrier, context)
    assert _baggage_from_carrier(factory_carrier) == {"risk.score": "72"}


def test_global_inject_forwards_destination_to_composite() -> None:
    propagator = _propagator()
    original_propagator = propagate.get_global_textmap()
    carrier: dict[str, str] = {}
    propagate.set_global_textmap(propagator)
    try:
        propagate.inject(carrier, _full_context(), destination=EXTERNAL)
    finally:
        propagate.set_global_textmap(original_propagator)

    assert _baggage_from_carrier(carrier) == {"risk.score": "72"}


def test_raw_destination_mapping_and_functional_entrypoint() -> None:
    propagator = CompositePropagator(
        [TraceContextTextMapPropagator(), W3CBaggagePropagator()],
        {EXTERNAL: ["risk.score"]},
    )
    carrier: dict[str, str] = {}

    inject_for_destination(
        EXTERNAL,
        carrier,
        _full_context(),
        propagator=propagator,
    )

    assert _baggage_from_carrier(carrier) == {"risk.score": "72"}
    assert "traceparent" in carrier
