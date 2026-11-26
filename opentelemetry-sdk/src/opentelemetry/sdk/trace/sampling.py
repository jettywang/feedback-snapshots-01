# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0


"""
For general information about sampling, see `the specification <https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/sdk.md#sampling>`_.

OpenTelemetry provides two types of samplers:

- `StaticSampler`
- `TraceIdRatioBased`

A `StaticSampler` always returns the same sampling result regardless of the conditions. Both possible StaticSamplers are already created:

- Always sample spans: ALWAYS_ON
- Never sample spans: ALWAYS_OFF

A `TraceIdRatioBased` sampler makes a random sampling result based on the sampling probability given.

If the span being sampled has a parent, `ParentBased` will respect the parent delegate sampler. Otherwise, it returns the sampling result from the given root sampler.

Currently, sampling results are always made during the creation of the span. However, this might not always be the case in the future (see `OTEP #115 <https://github.com/open-telemetry/oteps/pull/115>`_).

Custom samplers can be created by subclassing `Sampler` and implementing `Sampler.should_sample` as well as `Sampler.get_description`.

Samplers are able to modify the `opentelemetry.trace.span.TraceState` of the parent of the span being created. For custom samplers, it is suggested to implement `Sampler.should_sample` to utilize the
parent span context's `opentelemetry.trace.span.TraceState` and pass into the `SamplingResult` instead of the explicit trace_state field passed into the parameter of `Sampler.should_sample`.

To use a sampler, pass it into the tracer provider constructor. For example:

.. code:: python

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

    # sample 1 in every 1000 traces
    sampler = TraceIdRatioBased(1/1000)

    # set the sampler onto the global tracer provider
    trace.set_tracer_provider(TracerProvider(sampler=sampler))

    # set up an exporter for sampled spans
    trace.get_tracer_provider().add_span_processor(
        SimpleSpanProcessor(ConsoleSpanExporter())
    )

    # created spans will now be sampled by the TraceIdRatioBased sampler
    with trace.get_tracer(__name__).start_as_current_span("Test Span"):
        ...

The tracer sampler can also be configured via environment variables ``OTEL_TRACES_SAMPLER`` and ``OTEL_TRACES_SAMPLER_ARG`` (only if applicable).
The list of built-in values for ``OTEL_TRACES_SAMPLER`` are:

    * always_on - Sampler that always samples spans, regardless of the parent span's sampling decision.
    * always_off - Sampler that never samples spans, regardless of the parent span's sampling decision.
    * traceidratio - Sampler that samples probabilistically based on rate.
    * parentbased_always_on - (default) Sampler that respects its parent span's sampling decision, but otherwise always samples.
    * parentbased_always_off - Sampler that respects its parent span's sampling decision, but otherwise never samples.
    * parentbased_traceidratio - Sampler that respects its parent span's sampling decision, but otherwise samples probabilistically based on rate.

Sampling probability can be set with ``OTEL_TRACES_SAMPLER_ARG`` if the sampler is traceidratio or parentbased_traceidratio. Rate must be in the range [0.0,1.0]. When not provided rate will be set to
1.0 (maximum rate possible).

Prev example but with environment variables. Please make sure to set the env ``OTEL_TRACES_SAMPLER=traceidratio`` and ``OTEL_TRACES_SAMPLER_ARG=0.001``.

.. code:: python

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )

    trace.set_tracer_provider(TracerProvider())

    # set up an exporter for sampled spans
    trace.get_tracer_provider().add_span_processor(
        SimpleSpanProcessor(ConsoleSpanExporter())
    )

    # created spans will now be sampled by the TraceIdRatioBased sampler with rate 1/1000.
    with trace.get_tracer(__name__).start_as_current_span("Test Span"):
        ...

When utilizing a configurator, you can configure a custom sampler. In order to create a configurable custom sampler, create an entry point for the custom sampler
factory method or function under the entry point group, ``opentelemetry_traces_sampler``. The custom sampler factory method must be of type ``Callable[[str], Sampler]``, taking a single string argument and
returning a Sampler object. The single input will come from the string value of the ``OTEL_TRACES_SAMPLER_ARG`` environment variable. If ``OTEL_TRACES_SAMPLER_ARG`` is not configured, the input will
be an empty string. For example:

.. code:: python

    setup(
        ...
        entry_points={
            ...
            "opentelemetry_traces_sampler": [
                "custom_sampler_name = path.to.sampler.factory.method:CustomSamplerFactory.get_sampler"
            ]
        }
    )
    # ...
    class CustomRatioSampler(Sampler):
        def __init__(rate):
            # ...
    # ...
    class CustomSamplerFactory:
        @staticmethod
        def get_sampler(sampler_argument):
            try:
                rate = float(sampler_argument)
                return CustomSampler(rate)
            except ValueError: # In case argument is empty string.
                return CustomSampler(0.5)

In order to configure you application with a custom sampler's entry point, set the ``OTEL_TRACES_SAMPLER`` environment variable to the key name of the entry point. For example, to configured the
above sampler, set ``OTEL_TRACES_SAMPLER=custom_sampler_name`` and ``OTEL_TRACES_SAMPLER_ARG=0.5``.
"""

from __future__ import annotations

import abc
import contextlib
import enum
import math
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from logging import getLogger
from types import MappingProxyType

# pylint: disable=unused-import
from opentelemetry import context as context_api
from opentelemetry import propagate as propagate_api
from opentelemetry.context import Context
from opentelemetry.propagators import textmap
from opentelemetry.sdk.environment_variables import (
    OTEL_TRACES_SAMPLER,
    OTEL_TRACES_SAMPLER_ARG,
)
from opentelemetry.trace import Link, SpanKind, get_current_span
from opentelemetry.trace.span import TraceState
from opentelemetry.util.types import Attributes

_logger = getLogger(__name__)


class Decision(enum.Enum):
    # IsRecording() == false, span will not be recorded and all events and attributes will be dropped.
    DROP = 0
    # IsRecording() == true, but Sampled flag MUST NOT be set.
    RECORD_ONLY = 1
    # IsRecording() == true AND Sampled flag` MUST be set.
    RECORD_AND_SAMPLE = 2

    def is_recording(self):
        return self in (Decision.RECORD_ONLY, Decision.RECORD_AND_SAMPLE)

    def is_sampled(self):
        return self is Decision.RECORD_AND_SAMPLE


class SamplingResult:
    """A sampling result as applied to a newly-created Span.

    Args:
        decision: A sampling decision based off of whether the span is recorded
            and the sampled flag in trace flags in the span context.
        attributes: Attributes to add to the `opentelemetry.trace.Span`.
        trace_state: The tracestate used for the `opentelemetry.trace.Span`.
            Could possibly have been modified by the sampler.
    """

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.decision!s}, attributes={self.attributes!s})"

    def __init__(
        self,
        decision: Decision,
        attributes: Attributes = None,
        trace_state: TraceState | None = None,
    ) -> None:
        self.decision = decision
        if attributes is None:
            self.attributes = MappingProxyType({})
        else:
            self.attributes = MappingProxyType(attributes)
        self.trace_state = trace_state


class Sampler(abc.ABC):
    @abc.abstractmethod
    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        pass

    @abc.abstractmethod
    def get_description(self) -> str:
        pass


class StaticSampler(Sampler):
    """Sampler that always returns the same decision."""

    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        if self._decision is Decision.DROP:
            attributes = None
        return SamplingResult(
            self._decision,
            attributes,
            _get_parent_trace_state(parent_context),
        )

    def get_description(self) -> str:
        if self._decision is Decision.DROP:
            return "AlwaysOffSampler"
        return "AlwaysOnSampler"


ALWAYS_OFF = StaticSampler(Decision.DROP)
"""Sampler that never samples spans, regardless of the parent span's sampling decision."""

ALWAYS_ON = StaticSampler(Decision.RECORD_AND_SAMPLE)
"""Sampler that always samples spans, regardless of the parent span's sampling decision."""


class TraceIdRatioBased(Sampler):
    """
    Sampler that makes sampling decisions probabilistically based on `rate`.

    Args:
        rate: Probability (between 0 and 1) that a span will be sampled
    """

    def __init__(self, rate: float):
        if math.isnan(rate) or rate < 0.0 or rate > 1.0:
            raise ValueError("Probability must be in range [0.0, 1.0].")
        self._rate = rate
        self._bound = self.get_bound_for_rate(self._rate)

    # For compatibility with 64 bit trace IDs, the sampler checks the 64
    # low-order bits of the trace ID to decide whether to sample a given trace.
    TRACE_ID_LIMIT = (1 << 64) - 1

    @classmethod
    def get_bound_for_rate(cls, rate: float) -> int:
        return round(rate * (cls.TRACE_ID_LIMIT + 1))

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def bound(self) -> int:
        return self._bound

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        decision = Decision.DROP
        if trace_id & self.TRACE_ID_LIMIT < self.bound:
            decision = Decision.RECORD_AND_SAMPLE
        if decision is Decision.DROP:
            attributes = None
        return SamplingResult(
            decision,
            attributes,
            _get_parent_trace_state(parent_context),
        )

    def get_description(self) -> str:
        return f"TraceIdRatioBased{{{self._rate}}}"


PROPAGATION_SOURCE_CONTEXT_KEY = context_api.create_key("opentelemetry.sdk.trace.sampling.propagation_source")

INTERNAL_SOURCE = "internal"
PARTNER_SOURCE = "partner"
EXTERNAL_SOURCE = "external"
UNTRUSTED_SOURCE = "untrusted"


@dataclass(frozen=True)
class PropagationSource:
    """A receiver-asserted origin of an extracted propagation carrier.

    The source must come from a receiver-controlled boundary, such as an
    authenticated connection or route. Do not populate it from an untrusted
    carrier field unless that field has already been authenticated.
    """

    name: str


SourceLike = str | PropagationSource | object | None


def normalize_propagation_source(source: SourceLike) -> str | None:
    if source is None:
        return None
    if isinstance(source, PropagationSource):
        return source.name
    if isinstance(source, str):
        return source
    value = getattr(source, "value", source)
    if isinstance(value, str):
        return value
    return str(source)


def with_propagation_source(source: SourceLike, parent_context: Context | None = None) -> Context:
    """Return a context tagged with a receiver-specified propagation source.

    If ``parent_context`` is omitted, the current context is used. Propagator
    extraction supplies an empty root context explicitly when its caller did
    not provide one.
    """
    return context_api.set_value(PROPAGATION_SOURCE_CONTEXT_KEY, source, parent_context)


def set_propagation_source(source: SourceLike, parent_context: Context | None = None) -> Context:
    """Alias for :func:`with_propagation_source`."""
    return with_propagation_source(source, parent_context)


def get_propagation_source(parent_context: Context | None = None) -> SourceLike:
    """Return the receiver-specified source from a context, if present."""
    return context_api.get_value(PROPAGATION_SOURCE_CONTEXT_KEY, parent_context)


@contextlib.contextmanager
def propagation_source_scope(source: SourceLike):
    """Temporarily attach a receiver-specified source to the current context."""
    context = with_propagation_source(source, context_api.get_current())
    token = context_api.attach(context)
    try:
        yield context
    finally:
        context_api.detach(token)


use_propagation_source = propagation_source_scope


class ParentSamplingTrust(enum.Enum):
    """Whether a parent sampled flag is allowed to influence local sampling."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class SamplingTrustVerdict:
    source: str | None
    trust: ParentSamplingTrust

    @property
    def trusted(self) -> bool:
        return self.trust is ParentSamplingTrust.TRUSTED

    @property
    def allowed(self) -> bool:
        return self.trusted


class SamplingTrustPolicy:
    """Receiver-specified allowlist for inbound parent sampling flags.

    A source may be supplied as a string or :class:`PropagationSource`. Sources
    absent from ``trusted_sources`` are not necessarily rejected for tracing:
    trace ID and parent context continue to be propagated. Only the parent's
    sampled flag is ignored by :class:`TrustAwareParentBased`.
    """

    def __init__(
        self,
        trusted_sources: (Mapping[str, bool] | Iterable[str] | Callable[[SourceLike], bool] | None) = None,
        *,
        rules: Mapping[str, bool] | None = None,
        default: bool = False,
        approved_sources: Iterable[str] | Mapping[str, bool] | None = None,
        allowed_sources: Iterable[str] | Mapping[str, bool] | None = None,
        trust_internal: bool | None = None,
        trust_partner: bool | None = None,
        internal_trusted: bool | None = None,
        partner_trusted: bool | None = None,
        trusted_internal: bool | None = None,
        trusted_partner: bool | None = None,
        internal: bool | None = None,
        partner: bool | None = None,
        is_trusted: Callable[[SourceLike], bool] | None = None,
    ) -> None:
        self._default = default
        self._rules: dict[str, bool] = {}
        self._evaluator = is_trusted

        if trusted_sources is None:
            trusted_sources = approved_sources if approved_sources is not None else allowed_sources

        if trusted_sources is not None:
            if callable(trusted_sources) and not isinstance(trusted_sources, Mapping):
                self._evaluator = trusted_sources
            elif isinstance(trusted_sources, str):
                self._rules[trusted_sources] = True
            elif isinstance(trusted_sources, Mapping):
                self._rules.update({str(source): bool(allowed) for source, allowed in trusted_sources.items()})
            else:
                self._rules.update({normalize_propagation_source(source) or "": True for source in trusted_sources})
                self._rules.pop("", None)

        if rules:
            self._rules.update({str(source): bool(allowed) for source, allowed in rules.items()})

        internal_trust = (
            trust_internal
            if trust_internal is not None
            else internal_trusted
            if internal_trusted is not None
            else trusted_internal
            if trusted_internal is not None
            else internal
        )
        partner_trust = (
            trust_partner
            if trust_partner is not None
            else partner_trusted
            if partner_trusted is not None
            else trusted_partner
            if trusted_partner is not None
            else partner
        )
        if internal_trust is not None:
            self._rules[INTERNAL_SOURCE] = internal_trust
        if partner_trust is not None:
            self._rules[PARTNER_SOURCE] = partner_trust

    @classmethod
    def internal_only(cls) -> SamplingTrustPolicy:
        return cls({INTERNAL_SOURCE: True})

    @classmethod
    def internal_and_partner(cls) -> SamplingTrustPolicy:
        return cls({INTERNAL_SOURCE: True, PARTNER_SOURCE: True})

    def is_trusted_source(self, source: SourceLike) -> bool:
        if self._evaluator is not None:
            return bool(self._evaluator(source))
        source_name = normalize_propagation_source(source)
        if source_name is None:
            return self._default
        return self._rules.get(source_name, self._default)

    is_trusted = is_trusted_source
    is_approved = is_trusted_source
    allows_parent_sampling = is_trusted_source
    allows_parent_sampled_flag = is_trusted_source

    def evaluate(self, source: SourceLike) -> SamplingTrustVerdict:
        trust = ParentSamplingTrust.TRUSTED if self.is_trusted_source(source) else ParentSamplingTrust.UNTRUSTED
        return SamplingTrustVerdict(normalize_propagation_source(source), trust)


TrustPolicy = SamplingTrustPolicy
ReceiverSamplingTrustPolicy = SamplingTrustPolicy
PropagationTrustPolicy = SamplingTrustPolicy


class ParentBased(Sampler):
    """
    If a parent is set, applies the respective delegate sampler.
    Otherwise, uses the root provided at initialization to make a
    decision.

    Args:
        root: Sampler called for spans with no parent (root spans).
        remote_parent_sampled: Sampler called for a remote sampled parent.
        remote_parent_not_sampled: Sampler called for a remote parent that is
            not sampled.
        local_parent_sampled: Sampler called for a local sampled parent.
        local_parent_not_sampled: Sampler called for a local parent that is
            not sampled.
    """

    def __init__(
        self,
        root: Sampler,
        remote_parent_sampled: Sampler = ALWAYS_ON,
        remote_parent_not_sampled: Sampler = ALWAYS_OFF,
        local_parent_sampled: Sampler = ALWAYS_ON,
        local_parent_not_sampled: Sampler = ALWAYS_OFF,
    ):
        self._root = root
        self._remote_parent_sampled = remote_parent_sampled
        self._remote_parent_not_sampled = remote_parent_not_sampled
        self._local_parent_sampled = local_parent_sampled
        self._local_parent_not_sampled = local_parent_not_sampled

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        parent_span_context = get_current_span(parent_context).get_span_context()
        # default to the root sampler
        sampler = self._root
        # respect the sampling and remote flag of the parent if present
        if parent_span_context is not None and parent_span_context.is_valid:
            if parent_span_context.is_remote:
                if parent_span_context.trace_flags.sampled:
                    sampler = self._remote_parent_sampled
                else:
                    sampler = self._remote_parent_not_sampled
            else:
                if parent_span_context.trace_flags.sampled:
                    sampler = self._local_parent_sampled
                else:
                    sampler = self._local_parent_not_sampled

        return sampler.should_sample(
            parent_context=parent_context,
            trace_id=trace_id,
            name=name,
            kind=kind,
            attributes=attributes,
            links=links,
        )

    def get_description(self):
        return f"ParentBased{{root:{self._root.get_description()},remoteParentSampled:{self._remote_parent_sampled.get_description()},remoteParentNotSampled:{self._remote_parent_not_sampled.get_description()},localParentSampled:{self._local_parent_sampled.get_description()},localParentNotSampled:{self._local_parent_not_sampled.get_description()}}}"


class SamplingDecisionBasis(enum.Enum):
    """Explains which boundary supplied the effective sampling decision."""

    ROOT = "root"
    TRUSTED_REMOTE_PARENT = "trusted_remote_parent"
    UNTRUSTED_REMOTE_SOURCE = "untrusted_remote_source"
    LOCAL_PARENT = "local_parent"


class TrustAwareSamplingResult(SamplingResult):
    """A sampling result with the receiver's trust decision retained."""

    def __init__(
        self,
        result: SamplingResult,
        *,
        propagation_source: SourceLike,
        trust_verdict: SamplingTrustVerdict | None,
        parent_sampling_applied: bool,
        basis: SamplingDecisionBasis,
    ) -> None:
        super().__init__(result.decision, result.attributes, result.trace_state)
        self.propagation_source = propagation_source
        self.trust_verdict = trust_verdict
        self.trusted_source = bool(trust_verdict and trust_verdict.trusted)
        self.parent_sampling_applied = parent_sampling_applied
        self.basis = basis


class TrustAwareParentBased(ParentBased):
    """ParentBased sampling that trusts the remote sampled flag by source.

    Valid parent span contexts are always retained. For a remote parent whose
    receiver-specified propagation source is not approved by
    ``trust_policy``, the parent's sampled flag is ignored and the local/root
    sampler makes the decision. Local parent spans continue to use the normal
    ParentBased delegates because their decision was already made inside this
    receiver's trust boundary.
    """

    def __init__(
        self,
        root: (
            Sampler | SamplingTrustPolicy | Mapping[str, bool] | Iterable[str] | Callable[[SourceLike], bool] | None
        ) = None,
        trust_policy: (
            SamplingTrustPolicy | Mapping[str, bool] | Iterable[str] | Callable[[SourceLike], bool] | Sampler | None
        ) = None,
        *,
        policy: (SamplingTrustPolicy | Mapping[str, bool] | Iterable[str] | Callable[[SourceLike], bool] | None) = None,
        local_sampler: Sampler | None = None,
        sampler: Sampler | None = None,
        local: Sampler | None = None,
        untrusted_parent: Sampler | None = None,
        unapproved_parent: Sampler | None = None,
        untrusted_remote_parent: Sampler | None = None,
        trusted_sources: Iterable[str] | Mapping[str, bool] | None = None,
        approved_sources: Iterable[str] | Mapping[str, bool] | None = None,
        remote_parent_sampled: Sampler = ALWAYS_ON,
        remote_parent_not_sampled: Sampler = ALWAYS_OFF,
        local_parent_sampled: Sampler = ALWAYS_ON,
        local_parent_not_sampled: Sampler = ALWAYS_OFF,
    ) -> None:
        effective_root: Sampler | None = None
        positional_policy = None

        if isinstance(root, Sampler):
            effective_root = root
        elif root is not None:
            positional_policy = root

        if isinstance(trust_policy, Sampler):
            effective_root = effective_root or trust_policy
        elif trust_policy is not None:
            positional_policy = trust_policy

        effective_root = effective_root or local_sampler or sampler or local or ALWAYS_ON
        super().__init__(
            root=effective_root,
            remote_parent_sampled=remote_parent_sampled,
            remote_parent_not_sampled=remote_parent_not_sampled,
            local_parent_sampled=local_parent_sampled,
            local_parent_not_sampled=local_parent_not_sampled,
        )

        policy_source = policy if policy is not None else positional_policy
        if isinstance(policy_source, SamplingTrustPolicy):
            self._trust_policy = policy_source
        elif policy_source is not None:
            self._trust_policy = SamplingTrustPolicy(policy_source)
        else:
            sources = trusted_sources if trusted_sources is not None else approved_sources
            self._trust_policy = SamplingTrustPolicy(sources)

        self._untrusted_remote_parent = (
            untrusted_remote_parent or unapproved_parent or untrusted_parent or effective_root
        )

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        parent_span_context = get_current_span(parent_context).get_span_context()
        trust_verdict: SamplingTrustVerdict | None = None
        parent_sampling_applied = False

        if parent_span_context is None or not parent_span_context.is_valid:
            sampler = self._root
            basis = SamplingDecisionBasis.ROOT
            propagation_source = None
        elif not parent_span_context.is_remote:
            if parent_span_context.trace_flags.sampled:
                sampler = self._local_parent_sampled
            else:
                sampler = self._local_parent_not_sampled
            basis = SamplingDecisionBasis.LOCAL_PARENT
            parent_sampling_applied = True
            propagation_source = get_propagation_source(parent_context)
        else:
            propagation_source = get_propagation_source(parent_context)
            trust_verdict = self._trust_policy.evaluate(propagation_source)
            if trust_verdict.trusted:
                if parent_span_context.trace_flags.sampled:
                    sampler = self._remote_parent_sampled
                else:
                    sampler = self._remote_parent_not_sampled
                basis = SamplingDecisionBasis.TRUSTED_REMOTE_PARENT
                parent_sampling_applied = True
            else:
                # Deliberately do not branch on the inbound sampled flag.
                sampler = self._untrusted_remote_parent
                basis = SamplingDecisionBasis.UNTRUSTED_REMOTE_SOURCE

        result = sampler.should_sample(
            parent_context=parent_context,
            trace_id=trace_id,
            name=name,
            kind=kind,
            attributes=attributes,
            links=links,
            trace_state=trace_state,
        )
        return TrustAwareSamplingResult(
            result,
            propagation_source=propagation_source,
            trust_verdict=trust_verdict,
            parent_sampling_applied=parent_sampling_applied,
            basis=basis,
        )

    def get_description(self) -> str:
        return (
            "TrustAwareParentBased{"
            f"root:{self._root.get_description()},"
            f"trust_policy:{self._trust_policy.__class__.__name__},"
            f"untrustedRemoteParent:{self._untrusted_remote_parent.get_description()}"
            "}"
        )


SamplingTrustSampler = TrustAwareParentBased
TrustSampler = TrustAwareParentBased
TrustBasedParentSampler = TrustAwareParentBased
TrustedParentBasedSampler = TrustAwareParentBased
TrustedParentSampler = TrustAwareParentBased
ReceiverTrustSampler = TrustAwareParentBased
SourceTrustSampler = TrustAwareParentBased


class SourceBoundPropagator(textmap.TextMapPropagator):
    """Tag extracted contexts with a fixed receiver-specified source.

    The wrapped propagator still performs all trace/baggage extraction. This
    wrapper only adds provenance to the returned Context before extraction so
    that composite propagators and later span creation retain the source.
    """

    def __init__(
        self,
        propagator: textmap.TextMapPropagator,
        source: SourceLike,
    ) -> None:
        self._propagator = propagator
        self._source = source

    def extract(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
    ) -> Context:
        context = with_propagation_source(self._source, Context() if context is None else context)
        return self._propagator.extract(carrier, context, getter)

    def inject(
        self,
        carrier: textmap.CarrierT,
        context: Context | None = None,
        setter: textmap.Setter[textmap.CarrierT] = textmap.default_setter,
    ) -> None:
        self._propagator.inject(carrier, context, setter)

    @property
    def fields(self) -> set[str]:
        return self._propagator.fields


ReceiverSourcePropagator = SourceBoundPropagator
SamplingTrustPropagator = SourceBoundPropagator
TrustPropagator = SourceBoundPropagator


def extract_with_source(
    carrier: textmap.CarrierT,
    source: SourceLike,
    propagator: textmap.TextMapPropagator | None = None,
    context: Context | None = None,
    getter: textmap.Getter[textmap.CarrierT] = textmap.default_getter,
) -> Context:
    """Extract ``carrier`` and tag the resulting context with ``source``.

    When ``propagator`` is omitted, the globally configured text map
    propagator is used.
    """
    if propagator is None:
        propagator = propagate_api.get_global_textmap()
    return SourceBoundPropagator(propagator, source).extract(carrier, context, getter)


extract_trusted_context = extract_with_source
extract_with_receiver_source = extract_with_source


class AlwaysRecordOnlySampler(StaticSampler):
    def __init__(self) -> None:
        super().__init__(Decision.RECORD_ONLY)


ALWAYS_RECORD_ONLY = AlwaysRecordOnlySampler()
"""Sampler that records spans but never sets the sampled flag."""


class AlwaysRecordSampler(Sampler):
    """
    This sampler will return the sampling result of the provided `root`, unless the
    sampling result contains the sampling decision `Decision.DROP`, in which case, a
    new sampling result will be returned that is functionally equivalent to the original, except that
    it contains the sampling decision `Decision.RECORD_ONLY`. This ensures that all
    spans are recorded, with no change to sampling.

    The intended use case of this sampler is to provide a means of sending all spans to a
    processor without having an impact on the sampling rate. This may be desirable if a user wishes
    to count or otherwise measure all spans produced in a service, without incurring the cost of 100%
    sampling.
    """

    def __init__(self, root: Sampler):
        if root is None:
            raise ValueError("root must not be None")
        self._root = root

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        result: SamplingResult = self._root.should_sample(
            parent_context,
            trace_id,
            name,
            kind,
            attributes,
            links,
            trace_state,
        )
        if result.decision is Decision.DROP:
            result = SamplingResult(Decision.RECORD_ONLY, result.attributes, result.trace_state)

        return result

    def get_description(self):
        return f"AlwaysRecordSampler{{{self._root.get_description()}}}"


DEFAULT_OFF = ParentBased(ALWAYS_OFF)
"""Sampler that respects its parent span's sampling decision, but otherwise never samples."""

DEFAULT_ON = ParentBased(ALWAYS_ON)
"""Sampler that respects its parent span's sampling decision, but otherwise always samples."""


class ParentBasedTraceIdRatio(ParentBased):
    """
    Sampler that respects its parent span's sampling decision, but otherwise
    samples probabilistically based on `rate`.
    """

    def __init__(self, rate: float):
        root = TraceIdRatioBased(rate=rate)
        super().__init__(root=root)


class _AlwaysOff(StaticSampler):
    def __init__(self, _):
        super().__init__(Decision.DROP)


class _AlwaysOn(StaticSampler):
    def __init__(self, _):
        super().__init__(Decision.RECORD_AND_SAMPLE)


class _ParentBasedAlwaysOff(ParentBased):
    def __init__(self, _):
        super().__init__(ALWAYS_OFF)


class _ParentBasedAlwaysOn(ParentBased):
    def __init__(self, _):
        super().__init__(ALWAYS_ON)


_KNOWN_SAMPLERS = {
    "always_on": ALWAYS_ON,
    "always_off": ALWAYS_OFF,
    "parentbased_always_on": DEFAULT_ON,
    "parentbased_always_off": DEFAULT_OFF,
    "traceidratio": TraceIdRatioBased,
    "parentbased_traceidratio": ParentBasedTraceIdRatio,
}


def _get_from_env_or_default() -> Sampler:
    trace_sampler = os.getenv(OTEL_TRACES_SAMPLER, "parentbased_always_on").lower()
    if trace_sampler not in _KNOWN_SAMPLERS:
        _logger.warning("Couldn't recognize sampler %s.", trace_sampler)
        trace_sampler = "parentbased_always_on"

    if trace_sampler in ("traceidratio", "parentbased_traceidratio"):
        try:
            rate = float(os.getenv(OTEL_TRACES_SAMPLER_ARG, ""))
            return _KNOWN_SAMPLERS[trace_sampler](rate)
        except (ValueError, TypeError):
            _logger.warning("Could not convert TRACES_SAMPLER_ARG to float. Using default rate 1.0.")
            return _KNOWN_SAMPLERS[trace_sampler](1.0)

    return _KNOWN_SAMPLERS[trace_sampler]


def _get_parent_trace_state(
    parent_context: Context | None,
) -> TraceState | None:
    parent_span_context = get_current_span(parent_context).get_span_context()
    if parent_span_context is None or not parent_span_context.is_valid:
        return None
    return parent_span_context.trace_state
