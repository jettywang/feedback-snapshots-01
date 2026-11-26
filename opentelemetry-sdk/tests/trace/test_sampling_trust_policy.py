# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry import context as context_api
from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.sdk.trace import TracerProvider, sampling
from opentelemetry.trace import Link, SpanKind
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)
from opentelemetry.trace.span import TraceState

TRACE_ID_HEX = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
INTERNAL_PARENT_SPAN_HEX = "1111111111111111"
PARTNER_PARENT_SPAN_HEX = "2222222222222222"
TRACE_ID = int(TRACE_ID_HEX, 16)


class RecordingSampler(sampling.Sampler):
    def __init__(self, decision: sampling.Decision) -> None:
        self.decision = decision
        self.calls = []

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes=None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> sampling.SamplingResult:
        parent = trace.get_current_span(parent_context).get_span_context()
        self.calls.append(
            {
                "parent": parent,
                "trace_id": trace_id,
                "name": name,
            }
        )
        return sampling.SamplingResult(self.decision)

    def get_description(self) -> str:
        return "RecordingSampler"


def traceparent(parent_span_hex: str, flags: str = "01") -> dict[str, str]:
    return {"traceparent": f"00-{TRACE_ID_HEX}-{parent_span_hex}-{flags}"}


def test_policy_allowlist_distinguishes_internal_and_partner() -> None:
    policy = sampling.SamplingTrustPolicy({"internal": True, "partner": False, "verified-partner": True})

    assert policy.is_trusted_source("internal")
    assert not policy.is_trusted_source("partner")
    assert policy.is_trusted_source("verified-partner")
    assert not policy.is_trusted_source("internet")
    assert not policy.is_trusted_source(None)

    internal = sampling.PropagationSource("internal")
    assert policy.evaluate(internal).trusted
    assert policy.evaluate("partner").trust is sampling.ParentSamplingTrust.UNTRUSTED


def test_source_bound_propagator_preserves_complete_remote_context() -> None:
    propagator = sampling.SourceBoundPropagator(TraceContextTextMapPropagator(), "internal")

    context = propagator.extract(traceparent(INTERNAL_PARENT_SPAN_HEX, "01"))
    parent = trace.get_current_span(context).get_span_context()

    assert sampling.get_propagation_source(context) == "internal"
    assert parent.is_remote
    assert parent.is_valid
    assert parent.trace_id == TRACE_ID
    assert parent.span_id == int(INTERNAL_PARENT_SPAN_HEX, 16)
    assert parent.trace_flags.sampled


def test_source_survives_composite_extraction() -> None:
    propagator = sampling.SourceBoundPropagator(
        CompositePropagator([TraceContextTextMapPropagator()]),
        sampling.PropagationSource("partner"),
    )

    context = propagator.extract(traceparent(PARTNER_PARENT_SPAN_HEX, "00"))

    assert sampling.get_propagation_source(context).name == "partner"
    parent = trace.get_current_span(context).get_span_context()
    assert parent.trace_id == TRACE_ID
    assert parent.span_id == int(PARTNER_PARENT_SPAN_HEX, 16)
    assert not parent.trace_flags.sampled


def test_trusted_remote_parent_uses_parent_delegate() -> None:
    local = RecordingSampler(sampling.Decision.RECORD_AND_SAMPLE)
    trusted_sampled = RecordingSampler(sampling.Decision.RECORD_AND_SAMPLE)
    sampler = sampling.TrustAwareParentBased(
        root=local,
        trust_policy=sampling.SamplingTrustPolicy.internal_only(),
        remote_parent_sampled=trusted_sampled,
    )
    carrier = traceparent(INTERNAL_PARENT_SPAN_HEX, "01")
    context = TraceContextTextMapPropagator().extract(carrier, sampling.with_propagation_source("internal"))

    result = sampler.should_sample(context, TRACE_ID, "inbound")

    assert result.decision is sampling.Decision.RECORD_AND_SAMPLE
    assert result.basis is sampling.SamplingDecisionBasis.TRUSTED_REMOTE_PARENT
    assert result.parent_sampling_applied
    assert result.trusted_source
    assert len(trusted_sampled.calls) == 1
    assert local.calls == []


def test_unapproved_source_uses_local_sampler_but_keeps_full_parent() -> None:
    local = RecordingSampler(sampling.Decision.RECORD_ONLY)
    sampler = sampling.TrustAwareParentBased(
        root=local,
        trust_policy=sampling.SamplingTrustPolicy.internal_only(),
    )
    carrier = traceparent(PARTNER_PARENT_SPAN_HEX, "01")
    context = TraceContextTextMapPropagator().extract(carrier, sampling.with_propagation_source("unapproved-partner"))

    result = sampler.should_sample(context, TRACE_ID, "inbound")

    assert result.decision is sampling.Decision.RECORD_ONLY
    assert result.basis is sampling.SamplingDecisionBasis.UNTRUSTED_REMOTE_SOURCE
    assert not result.parent_sampling_applied
    assert not result.trusted_source
    assert len(local.calls) == 1

    captured_parent = local.calls[0]["parent"]
    assert captured_parent.is_remote
    assert captured_parent.trace_id == TRACE_ID
    assert captured_parent.span_id == int(PARTNER_PARENT_SPAN_HEX, 16)
    assert captured_parent.trace_flags.sampled


def test_untrusted_unsampled_flag_does_not_force_local_drop() -> None:
    sampler = sampling.TrustAwareParentBased(
        root=sampling.ALWAYS_ON,
        trust_policy=sampling.SamplingTrustPolicy(),
    )
    context = TraceContextTextMapPropagator().extract(
        traceparent(PARTNER_PARENT_SPAN_HEX, "00"),
        sampling.with_propagation_source("internet"),
    )

    result = sampler.should_sample(context, TRACE_ID, "inbound")

    assert result.decision is sampling.Decision.RECORD_AND_SAMPLE
    assert result.basis is sampling.SamplingDecisionBasis.UNTRUSTED_REMOTE_SOURCE


def test_two_sources_share_trace_id_but_keep_parent_recording_and_flags() -> None:
    policy = sampling.SamplingTrustPolicy({sampling.INTERNAL_SOURCE: True, sampling.PARTNER_SOURCE: False})
    sampler = sampling.TrustAwareParentBased(
        root=sampling.ALWAYS_RECORD_ONLY,
        trust_policy=policy,
        local_parent_not_sampled=sampling.ALWAYS_RECORD_ONLY,
    )
    provider = TracerProvider(sampler=sampler)
    tracer = provider.get_tracer("trust-policy-test")
    propagator = TraceContextTextMapPropagator()

    def run_chain(source: str, parent_span_hex: str):
        receiver_propagator = sampling.SourceBoundPropagator(propagator, source)
        extracted = receiver_propagator.extract(traceparent(parent_span_hex, "01"))

        server = tracer.start_span("server", context=extracted)
        server_context = trace.set_span_in_context(server, extracted)
        child = tracer.start_span("child", context=server_context)
        child_context = trace.set_span_in_context(child, server_context)

        assert server.is_recording()
        assert child.is_recording()
        assert server.parent.span_id == int(parent_span_hex, 16)
        assert server.parent.trace_id == TRACE_ID
        assert server.parent.trace_flags.sampled
        assert child.parent.span_id == server.context.span_id
        assert child.context.trace_id == TRACE_ID

        outbound = {}
        propagator.inject(outbound, child_context)
        outbound_parts = outbound["traceparent"].split("-")

        assert outbound_parts[1] == TRACE_ID_HEX
        assert outbound_parts[2] == format(child.context.span_id, "016x")
        assert outbound_parts[3] == format(int(child.context.trace_flags), "02x")

        source_in_child = sampling.get_propagation_source(child_context)
        server.end()
        child.end()
        return server, child, outbound_parts, source_in_child

    internal_server, internal_child, internal_outbound, internal_source = run_chain(
        "internal", INTERNAL_PARENT_SPAN_HEX
    )
    partner_server, partner_child, partner_outbound, partner_source = run_chain("partner", PARTNER_PARENT_SPAN_HEX)

    assert internal_source == "internal"
    assert partner_source == "partner"

    assert internal_server.context.trace_id == partner_server.context.trace_id
    assert internal_server.parent.span_id != partner_server.parent.span_id
    assert internal_server.context.span_id != partner_server.context.span_id

    assert internal_server.context.trace_flags.sampled
    assert internal_child.context.trace_flags.sampled
    assert internal_outbound[3] == "01"

    assert not partner_server.context.trace_flags.sampled
    assert not partner_child.context.trace_flags.sampled
    assert partner_outbound[3] == "00"

    # The inbound partner bit remains available on the complete parent even
    # though it did not determine the local sampling flag.
    assert partner_server.parent.trace_flags.sampled


def test_trust_source_follows_implicit_current_parent_chain() -> None:
    sampler = sampling.TrustAwareParentBased(
        root=sampling.ALWAYS_ON,
        trust_policy=sampling.SamplingTrustPolicy.internal_only(),
    )
    provider = TracerProvider(sampler=sampler)
    tracer = provider.get_tracer("implicit-context-test")
    context = TraceContextTextMapPropagator().extract(
        traceparent(INTERNAL_PARENT_SPAN_HEX, "01"),
        sampling.with_propagation_source("internal"),
    )
    token = context_api.attach(context)
    try:
        with tracer.start_as_current_span("server") as server:
            assert sampling.get_propagation_source() == "internal"
            with tracer.start_as_current_span("child") as child:
                assert sampling.get_propagation_source() == "internal"
                assert child.parent.span_id == server.context.span_id
    finally:
        context_api.detach(token)


def test_trust_sampler_accepts_policy_first_construction() -> None:
    policy = sampling.SamplingTrustPolicy.internal_only()
    local = sampling.ALWAYS_OFF

    policy_first = sampling.TrustAwareParentBased(policy, local)
    keyword_form = sampling.TrustAwareParentBased(trust_policy=policy, local_sampler=local)

    context = TraceContextTextMapPropagator().extract(
        traceparent(PARTNER_PARENT_SPAN_HEX, "01"),
        sampling.with_propagation_source("internet"),
    )

    assert policy_first.should_sample(context, TRACE_ID, "x").decision is sampling.Decision.DROP
    assert keyword_form.should_sample(context, TRACE_ID, "x").decision is sampling.Decision.DROP
