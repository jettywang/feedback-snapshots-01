# -*- coding: utf-8 -*-
# Policy driven CredSSP acceptor used as the fuzz target.
#
# FuzzableCredSSPServer subclasses the real CredSSPProxy, so the in-memory TLS
# handshake, the TSRequest pack/unpack codec and the underlying NTLM/SPNEGO
# authentication are all exercised for real. Only the decision about which
# TSRequest fields are acceptable in which phase is factored into a swappable
# policy:
#
#   * StrictAcceptPolicy mirrors the MS-CSSP state rules; it never consumes
#     authInfo before the public-key binding of the exchange is established.
#   * PermissiveAcceptPolicy intentionally acts on any request that decodes,
#     including a premature authInfo - the vulnerable behaviour the oracle must
#     catch.
#
# Normal step() traffic still flows through the genuine CredSSPProxy generator;
# accept_raw() is the single entry point used to inject a mutated request at a
# chosen phase without bypassing the TLS or TSRequest machinery.

import dataclasses
import typing

from spnego._credssp import CredSSPProxy
from spnego._credssp_structures import TSRequest
from spnego.exceptions import InvalidTokenError, SpnegoError

from .state_model import Evaluation, Phase, evaluate


@dataclasses.dataclass
class AcceptOutcome:
    phase: Phase
    decoded: bool
    credential_accepted: bool
    credential_early: bool
    stage: str
    error: typing.Optional[str]
    evaluation: Evaluation


class StrictAcceptPolicy:
    """Refuses any field the independent state model says is out of phase."""

    label = "strict"

    def check(self, evaluation: Evaluation) -> None:
        if not evaluation.legal:
            raise InvalidTokenError(
                context_msg="TSRequest rejected by strict state policy: %s" % "; ".join(evaluation.reasons)
            )


class PermissiveAcceptPolicy:
    """Intentionally weak: consumes authInfo as soon as the bytes decode."""

    label = "permissive"

    def check(self, evaluation: Evaluation) -> None:
        if not evaluation.decode_ok:
            raise InvalidTokenError(context_msg="TSRequest could not be decoded")


class FuzzableCredSSPServer(CredSSPProxy):
    def __init__(self, policy: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(None, None, usage="accept", protocol="credssp", **kwargs)
        self._fuzz_policy = policy
        self.credential_accepted_early = False

    def accept_raw(self, phase: Phase, encoded: bytes) -> AcceptOutcome:
        """Injects one TLS-protected, mutated TSRequest at ``phase``."""
        evaluation = evaluate(encoded, phase)
        decoded = False
        credential_accepted = False
        credential_early = False
        error: typing.Optional[str] = None

        try:
            # The genuine codec always runs first; a malformed blob never reaches
            # the policy or the credential sink.
            request = TSRequest.unpack(encoded)
            decoded = True

            self._fuzz_policy.check(evaluation)

            if request.auth_info is not None:
                credential_early = phase is not Phase.credential
                if credential_early:
                    self.credential_accepted_early = True

                # The field is consumed through the real NTLM security context.
                # Fuzz ciphertext is expected to fail decryption; the security
                # relevant fact is that the sink was reached at all.
                try:
                    self._auth_context.unwrap(request.auth_info)
                except SpnegoError as e:
                    error = "crypto: %s" % e
                credential_accepted = True
        except SpnegoError as e:
            error = "policy: %s" % e
        except (ValueError, TypeError, IndexError) as e:
            error = "codec: %s: %s" % (type(e).__name__, e)
        except Exception as e:  # Any unexpected acceptor crash is itself a finding.
            error = "unexpected: %s: %s" % (type(e).__name__, e)

        return AcceptOutcome(
            phase=phase,
            decoded=decoded,
            credential_accepted=credential_accepted,
            credential_early=credential_early,
            stage=self.get_extra_info("auth_stage") or "unknown",
            error=error,
            evaluation=evaluation,
        )
