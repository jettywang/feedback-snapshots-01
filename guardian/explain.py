"""Optional authorization explanations for trusted callers.

This module provides an opt-in, read-only explanation layer on top of the
regular boolean permission checks. It exists for trusted callers such as
support or audit tooling that need to answer "why does this identity (not)
have this permission" - distinguishing direct grants, group inheritance and
global (model-level) permission influence - without changing the behavior of
``has_perm`` and friends.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PermissionExplanation:
    """Verdict and evidence of a single permission evaluation.

    All evidence is collected during the single evaluation that produced
    this explanation: nothing is read from checker caches and nothing is
    re-queried lazily afterwards, so the verdict and the evidence always
    describe the same point-in-time decision.

    Attributes:
        user: The identity that was checked (a user, or a group when the
            explanation was produced by a group-based checker).
        perm: The normalized permission string (``app_label.codename``).
        obj: The object the permission was evaluated for (``None`` when the
            backend rejected the check as unsupported).
        allowed: The effective verdict. When ``consider_global`` is ``True``
            a held global permission also grants access (mirroring
            ``get_objects_for_user(..., accept_global_perms=True)``); the
            object-level boolean checks only count ``direct``/``group``
            sources.
        consider_global: Whether global permissions were taken into account.
        is_active: Whether the checked user is active.
        is_superuser: Whether the checked user is a superuser.
        direct_perms: Object-level permission codenames granted directly to
            the user for ``obj``.
        group_perms: Object-level permission codenames inherited per group,
            mapping group name to codenames for ``obj``.
        global_perms: Model-level (global) permission codenames held by the
            identity for the model of ``obj``. Empty when
            ``consider_global`` is ``False``.
        sources: The grant channels that make up the verdict: any of
            ``"superuser"``, ``"direct"``, ``"group:<name>"``, ``"global"``.
        reason: Human-readable summary of the verdict.
    """

    user: Any
    perm: str
    obj: Any
    allowed: bool
    consider_global: bool = True
    is_active: bool = True
    is_superuser: bool = False
    direct_perms: list[str] = field(default_factory=list)
    group_perms: dict[str, list[str]] = field(default_factory=dict)
    global_perms: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    reason: str = ""

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"{verdict} {self.perm} for {self.user} on {self.obj}: {self.reason}"
