"""Non-sensitive, staged records of login authorization decisions.

Integrations can observe why an authentication was allowed or rejected without
receiving provider responses or credentials. The recorder is diagnostic only:
a missing or failing recorder never changes an authentication result.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from social_core.utils import social_logger, user_is_authenticated

if TYPE_CHECKING:
    from collections.abc import Sequence

    from social_core.backends.base import BaseAuth
    from social_core.storage import UserProtocol

LoginEvidenceDecision = Literal["allowed", "denied"]
LoginEvidenceAssociation = Literal["none", "existing", "created"]
LoginEvidenceInitiator = Literal["anonymous", "authenticated"]
LoginEvidenceStage = Literal["identity", "policy", "association", "login"]


@dataclass(frozen=True, slots=True)
class LoginEvidence:
    """One staged authorization decision for an authentication attempt.

    The record deliberately contains only stable labels and outcomes. The
    provider names the backend, ``pipeline`` and ``pipeline_version`` identify
    the selected policy configuration, and ``stage`` and ``actor`` identify
    where the decision was made. Tokens, provider identifiers, and profile
    values are not part of this contract.
    """

    provider: str
    pipeline: str
    pipeline_version: str
    stage: LoginEvidenceStage
    decision: LoginEvidenceDecision
    reason: str
    actor: str
    association: LoginEvidenceAssociation
    association_only: bool
    initiator: LoginEvidenceInitiator

    def as_dict(self) -> dict[str, Any]:
        """Return a plain mapping suitable for a log or audit store."""
        return asdict(self)


def pipeline_steps(
    backend: BaseAuth[object], pipeline: Sequence[str] | None = None
) -> tuple[str, ...]:
    """Return the steps that define the active login policy.

    The pipeline started by ``BaseAuth.run_authentication`` is preferred so a
    resumed partial reports the policy actually executing, not one selected
    later from settings.
    """
    if pipeline is not None:
        return tuple(str(step) for step in pipeline)
    captured = getattr(backend, "_login_evidence_pipeline", None)
    if captured is not None:
        return tuple(str(step) for step in captured)
    return tuple(str(step) for step in backend.strategy.get_pipeline(backend))


def pipeline_version(
    backend: BaseAuth[object], steps: Sequence[str] | None = None
) -> str:
    """Return a stable version for the active login policy.

    Operators that assign an explicit ``PIPELINE_VERSION`` get that label;
    otherwise the ordered step names are hashed so a record still identifies
    the exact pipeline that made the decision.
    """
    configured = backend.setting("PIPELINE_VERSION")
    if configured not in (None, ""):
        return str(configured)
    selected = pipeline_steps(backend, steps)
    cached = getattr(backend, "_login_evidence_version", None)
    if cached is not None and cached[0] == selected:
        return cast("str", cached[1])
    version = hashlib.sha256("\n".join(selected).encode("utf-8")).hexdigest()
    backend._login_evidence_version = (selected, version)
    return version


def evidence_actor(func: Callable[..., object]) -> str:
    """Return the stable name of the decision point that emitted a record."""
    return f"{func.__module__}.{func.__name__}"


def association_outcome(backend: BaseAuth[object]) -> LoginEvidenceAssociation:
    """Return whether this attempt created a new account association.

    ``BaseAuth.pipeline`` records the pipeline's ``new_association`` result on
    the backend that ran it, so a resumed partial reports the outcome of the
    full flow rather than only the steps that ran after the resume.
    """
    if getattr(backend, "_login_evidence_new_association", False):
        return "created"
    return "existing"


def _initiator(
    backend: BaseAuth[object], user: UserProtocol | None
) -> LoginEvidenceInitiator:
    # The pipeline may attach a freshly created user to an anonymous attempt,
    # so prefer the initiator captured when the pipeline started.
    captured = getattr(backend, "_login_evidence_initiator", None)
    if captured in ("anonymous", "authenticated"):
        return cast("LoginEvidenceInitiator", captured)
    return "authenticated" if user_is_authenticated(user) else "anonymous"


def _integration_recorder(
    backend: BaseAuth[object],
) -> Callable[[LoginEvidence], object] | None:
    """Return the strategy's recorder only when an integration overrides it.

    Skipping the default keeps uninstrumented installations free of record
    construction, pipeline hashing, and attribute bookkeeping.
    """
    recorder = getattr(backend.strategy, "record_login_evidence", None)
    if not callable(recorder):
        return None
    # Imported lazily to keep the strategy module free of a runtime cycle.
    from social_core.strategy import BaseStrategy

    if getattr(recorder, "__func__", None) is BaseStrategy.record_login_evidence:
        return None
    return recorder


def record_login_evidence(
    backend: BaseAuth[object],
    *,
    stage: LoginEvidenceStage,
    decision: LoginEvidenceDecision,
    reason: str,
    actor: str,
    association: LoginEvidenceAssociation = "none",
    user: UserProtocol | None = None,
) -> LoginEvidence | None:
    """Offer one non-sensitive authorization record to the strategy.

    The strategy chooses how to persist the record through
    :meth:`~social_core.strategy.BaseStrategy.record_login_evidence`. Recorder
    failures are swallowed and logged without exception text so that
    instrumentation cannot alter an authentication result or disclose
    provider data.
    """
    try:
        recorder = _integration_recorder(backend)
        if recorder is None:
            return None
        version = pipeline_version(backend)
        evidence = LoginEvidence(
            provider=backend.name,
            pipeline=str(backend.setting("PIPELINE_NAME") or version),
            pipeline_version=version,
            stage=stage,
            decision=decision,
            reason=reason,
            actor=actor,
            association=association,
            association_only=bool(backend.ASSOCIATION_ONLY),
            initiator=_initiator(backend, user),
        )
        recorder(evidence)
    # Recorder failures are diagnostic only and must not affect authorization.
    except Exception as error:  # noqa: BLE001
        social_logger.warning(
            "%s: login evidence recorder failed (%s)",
            getattr(backend, "name", ""),
            type(error).__name__,
        )
        return None
    return evidence
