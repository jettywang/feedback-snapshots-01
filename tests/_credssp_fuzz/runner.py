# -*- coding: utf-8 -*-
# Fuzz campaign runner and the security oracle.
#
# The central invariant:
#
#   An acceptor must never consume delegated credentials (authInfo) while the
#   independent state model says the request is illegal for the phase.
#
# For every fixed-seed sample the runner compares the acceptor outcome against
# the state model. A strict acceptor and the model must agree; a permissive
# acceptor is expected to be caught consuming an early authInfo, proving the
# oracle has teeth. Decode-only failures (truncations, bad TLVs) are expected
# and must never reach the credential sink.

import dataclasses
import typing

from .acceptor import AcceptOutcome, StrictAcceptPolicy
from .harness import build_pair, finding_record, inject, advance
from .mutations import Sample


@dataclasses.dataclass
class CampaignResult:
    total: int
    findings: typing.List[typing.Dict[str, typing.Any]]
    premature_accepts: int
    decode_rejections: int
    structural_rejections: int

    @property
    def ok(self) -> bool:
        return not self.findings


def _oracle_violation(sample: Sample, outcome: AcceptOutcome) -> typing.Optional[str]:
    model = outcome.evaluation

    # The sink must never be reached for a request the model says is illegal.
    if outcome.credential_accepted and not model.legal:
        return "credential consumed on a request illegal for phase %s (%s)" % (
            sample.phase.value,
            "; ".join(model.reasons),
        )

    if outcome.credential_early:
        return "authInfo accepted before the credential phase"

    # Anything the codec could not parse must be rejected, not silently accepted.
    if not model.decode_ok and outcome.error is None:
        return "undecodable request produced no rejection"

    return None


def run_campaign(
    username: str,
    password: str,
    samples: typing.List[Sample],
    policy: typing.Any,
    *,
    fragment_size: typing.Optional[int] = None,
) -> CampaignResult:
    findings: typing.List[typing.Dict[str, typing.Any]] = []
    premature = 0
    decode_rejections = 0
    structural_rejections = 0

    for sample in samples:
        pair = build_pair(username, password, policy)
        advance(pair, sample.phase)

        outcome = inject(pair, sample, fragment_size=fragment_size)

        if not outcome.evaluation.decode_ok:
            decode_rejections += 1
        elif not outcome.evaluation.legal:
            structural_rejections += 1
        if outcome.credential_early:
            premature += 1

        reason = _oracle_violation(sample, outcome)
        if reason is not None:
            findings.append(finding_record(sample, outcome, reason))

    return CampaignResult(
        total=len(samples),
        findings=findings,
        premature_accepts=premature,
        decode_rejections=decode_rejections,
        structural_rejections=structural_rejections,
    )


def run_strict(username: str, password: str, samples: typing.List[Sample]) -> CampaignResult:
    return run_campaign(username, password, samples, StrictAcceptPolicy())


__all__ = [
    "CampaignResult",
    "run_campaign",
    "run_strict",
]
