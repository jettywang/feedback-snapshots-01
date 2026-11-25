"""Client-side project and action authorization for GitLab requests.

The policy is enforced in :meth:`gitlab.Gitlab.http_request` before the
backend is asked to send anything. A request is classified by:

* the project embedded in the request path (``/projects/<id-or-path>/...``),
* the action implied by the HTTP verb (read, write or delete).

Resource *names* never participate in the decision. Two projects may both
have a branch called ``main``; each branch object keeps the manager (and
therefore the project path) it was retrieved from, so a lazy object for
project A can never borrow the permission that was granted to project B.

Pagination links and other requests derived inside a single call carry a
:class:`RequestScope`. The scope pins both the project and the action, so a
link that leaves the project is refused even if the HTTP verb itself would
otherwise be allowed.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import unquote, urlsplit

from gitlab import exceptions

__all__ = [
    "Action",
    "PermissionDecision",
    "ProjectPermission",
    "ProjectPolicy",
    "RequestScope",
    "action_for_verb",
    "normalize_action",
    "normalize_actions",
    "project_from_path",
    "project_key",
    "resolve_policy",
]


class Action(enum.StrEnum):
    """The coarse action a request performs on a project."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"


#: A flexible description of allowed actions: a name, an :class:`Action`, a
#: boolean (``True`` allows all), an iterable of names, or a
#: :class:`ProjectPermission` (whose ``.actions`` are used).
ActionInput = Any

_READ_ALIASES = frozenset({"read", "get", "list", "head", "options", "view"})
_WRITE_ALIASES = frozenset(
    {"write", "post", "put", "patch", "create", "update", "set", "modify"}
)
_DELETE_ALIASES = frozenset({"delete", "remove", "destroy"})
_ALL_ALIASES = frozenset({"*", "all", "any"})

_VERB_ACTIONS: dict[str, Action] = {
    "get": Action.READ,
    "head": Action.READ,
    "list": Action.READ,
    "options": Action.READ,
    "post": Action.WRITE,
    "put": Action.WRITE,
    "patch": Action.WRITE,
    "create": Action.WRITE,
    "update": Action.WRITE,
    "set": Action.WRITE,
    "delete": Action.DELETE,
}

ALL_ACTIONS = frozenset({Action.READ, Action.WRITE, Action.DELETE})

# The first segment after ``/projects/`` is the project identifier. It is
# either a numeric ID or a percent-encoded namespace path such as
# ``group%2Fproject``.
_PROJECT_SEGMENT = "/projects/"


def action_for_verb(verb: str) -> Action | None:
    """Return the action implied by an HTTP verb (``None`` if unknown)."""
    return _VERB_ACTIONS.get(verb.lower())


def normalize_action(value: str | Action) -> Action:
    """Normalize a single action name, raising ``ValueError`` if unknown."""
    if isinstance(value, Action):
        return value

    text = str(value).strip().lower()
    if text in _READ_ALIASES:
        return Action.READ
    if text in _WRITE_ALIASES:
        return Action.WRITE
    if text in _DELETE_ALIASES:
        return Action.DELETE
    raise ValueError(
        f"Unknown action {value!r}. Use one of: read, write, delete (or '*')."
    )


def normalize_actions(value: ActionInput) -> frozenset[Action]:
    """Normalize a flexible action description into a set of :class:`Action`."""
    if value is None or value is False:
        return frozenset()
    if value is True:
        return ALL_ACTIONS
    if isinstance(value, Action):
        return frozenset({value})
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _ALL_ALIASES:
            return ALL_ACTIONS
        parts = [part.strip() for part in text.split(",")]
        return frozenset(normalize_action(part) for part in parts if part)
    if isinstance(value, ProjectPermission):
        return value.actions

    result: set[Action] = set()
    for item in value:
        result.update(normalize_actions(item))
    return frozenset(result)


def project_key(project: str | int) -> str:
    """Canonical comparison key for numeric IDs and namespace paths.

    GitLab accepts both ``123`` and a URL-encoded full path for the same
    project. Both forms resolve to the same key here so that a policy may
    mix them.
    """
    text = unquote(str(project)).strip().strip("/")
    return text


def project_from_path(path: str) -> str | int | None:
    """Return the project identifier embedded in a URL path, if any.

    Numeric IDs are returned as :class:`int`; namespace paths are
    percent-decoded strings. A path such as ``/projects`` (the project
    collection) intentionally yields ``None`` because it is not scoped to a
    single approved project.
    """
    path = urlsplit(path).path
    marker = path.find(_PROJECT_SEGMENT)
    if marker < 0:
        return None
    start = marker + len(_PROJECT_SEGMENT)
    end = len(path)
    for separator in ("/", "?", "#"):
        position = path.find(separator, start)
        if position >= 0:
            end = min(end, position)

    segment = path[start:end].strip("/")
    if not segment:
        return None

    decoded = unquote(segment)
    if decoded.isdigit():
        return int(decoded)
    return decoded


def _origin(url: str) -> tuple[str, str] | None:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return parsed.scheme.lower(), parsed.netloc.lower()


@dataclasses.dataclass(frozen=True)
class ProjectPermission:
    """Permissions granted for one project.

    ``project`` may be a numeric ID or the project's namespace path. The
    ``actions`` value accepts ``read``, ``write`` and ``delete`` (and their
    common aliases), ``*`` for all actions, or an iterable of these.
    """

    project: str | int
    actions: frozenset[Action] = frozenset({Action.READ})

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", normalize_actions(self.actions))

    @property
    def key(self) -> str:
        return project_key(self.project)

    def allows(self, action: str | Action) -> bool:
        return normalize_action(action) in self.actions


@dataclasses.dataclass(frozen=True)
class RequestScope:
    """The project/action pinned for a request and its derived requests."""

    project: str | int | None = None
    action: Action | None = None

    @classmethod
    def from_path(cls, path: str, action: str | Action | None = None) -> RequestScope:
        return cls(
            project=project_from_path(path),
            action=normalize_action(action) if action is not None else None,
        )

    @property
    def project_id(self) -> int | None:
        return self.project if isinstance(self.project, int) else None


@dataclasses.dataclass(frozen=True)
class PermissionDecision:
    """The outcome of a policy check, suitable for logging or assertions."""

    allowed: bool
    reason: str
    verb: str
    path: str
    project: str | int | None = None
    action: Action | None = None
    scope: RequestScope | None = None

    @property
    def message(self) -> str:
        project = "unscoped" if self.project is None else f"project {self.project}"
        action = "unknown" if self.action is None else self.action.value
        return (
            f"Request denied by the client permission policy: "
            f"{self.verb.upper()} {self.path} ({project}, {action}): {self.reason}"
        )

    def raise_if_denied(self) -> None:
        if self.allowed:
            return
        error = exceptions.GitlabPermissionError(self.message)
        error.decision = self
        raise error


class ProjectPolicy:
    """A fixed allowlist of projects and actions.

    Args:
        permissions: a mapping of ``project -> actions``, an iterable of
            :class:`ProjectPermission` objects, or ``(project, actions)``
            pairs. A plain string entry uses the ``"project:actions"`` form.
        unscoped_actions: actions allowed for requests that are not bound to
            a single project (for example ``GET /projects`` or ``GET /user``).
            Empty by default, because a restricted client should not be able
            to enumerate every project.
        allow_external_origins: if ``True``, requests to origins other than
            the configured GitLab instance are evaluated by path only. They
            are refused by default so credentials never leave the instance.
    """

    def __init__(
        self,
        permissions: (
            Mapping[str | int, ActionInput]
            | Iterable[ProjectPermission | tuple[str | int, ActionInput] | str]
            | None
        ) = None,
        *,
        unscoped_actions: ActionInput = (),
        allow_external_origins: bool = False,
    ) -> None:
        self.allow_external_origins = allow_external_origins
        self.unscoped_actions = normalize_actions(unscoped_actions)
        self._rules: dict[str, frozenset[Action]] = {}
        self._display: dict[str, str | int] = {}
        for permission in self._coerce_permissions(permissions):
            key = permission.key
            self._rules[key] = self._rules.get(key, frozenset()) | permission.actions
            self._display.setdefault(key, permission.project)

    @staticmethod
    def _coerce_permissions(
        permissions: (
            Mapping[str | int, ActionInput]
            | Iterable[ProjectPermission | tuple[str | int, ActionInput] | str]
            | None
        ),
    ) -> Iterable[ProjectPermission]:
        if permissions is None:
            return
        if isinstance(permissions, ProjectPolicy):  # pragma: no cover - defensive
            yield from permissions.permissions
            return
        if isinstance(permissions, Mapping):
            for project, actions in permissions.items():
                yield ProjectPermission(project, actions)
            return

        for entry in permissions:
            if isinstance(entry, ProjectPermission):
                yield entry
            elif isinstance(entry, str):
                project, separator, actions = entry.partition(":")
                yield ProjectPermission(project, actions if separator else Action.READ)
            elif isinstance(entry, (tuple, list)) and len(entry) == 2:
                project, actions = entry
                yield ProjectPermission(project, actions)
            else:
                raise TypeError(
                    f"Unsupported permission entry {entry!r}. Expected "
                    f"ProjectPermission, 'project:actions' or (project, actions)."
                )

    @classmethod
    def from_permissions(cls, permissions: Any, **kwargs: Any) -> ProjectPolicy:
        return cls(permissions, **kwargs)

    @property
    def permissions(self) -> tuple[ProjectPermission, ...]:
        return tuple(
            ProjectPermission(self._display[key], actions)
            for key, actions in self._rules.items()
        )

    @property
    def projects(self) -> tuple[str | int, ...]:
        return tuple(self._display.values())

    def actions_for(self, project: str | int) -> frozenset[Action]:
        return self._rules.get(project_key(project), frozenset())

    def allows(self, project: str | int, action: str | Action) -> bool:
        return normalize_action(action) in self.actions_for(project)

    def allows_unscoped(self, action: str | Action) -> bool:
        return normalize_action(action) in self.unscoped_actions

    def check(
        self,
        verb: str,
        url: str,
        *,
        scope: RequestScope | None = None,
        base_url: str | None = None,
    ) -> PermissionDecision:
        """Classify ``verb`` against ``url`` and return a decision."""
        verb = verb.lower()
        path = urlsplit(url).path
        derived = scope is not None
        default_action = action_for_verb(verb)

        origin = _origin(url)
        base_origin = _origin(base_url) if base_url else None
        if (
            not self.allow_external_origins
            and origin is not None
            and base_origin is not None
            and origin != base_origin
        ):
            return PermissionDecision(
                allowed=False,
                reason="external_origin",
                verb=verb,
                path=path,
                project=scope.project if scope else project_from_path(path),
                action=scope.action if scope else default_action,
                scope=scope,
            )

        parsed_project = project_from_path(path)
        project: str | int | None
        action: Action | None
        if scope is not None:
            project = scope.project
            action = scope.action or default_action
            if project is not None:
                if parsed_project is None or project_key(parsed_project) != project_key(
                    project
                ):
                    return PermissionDecision(
                        allowed=False,
                        reason="scope_mismatch",
                        verb=verb,
                        path=path,
                        project=project,
                        action=action,
                        scope=scope,
                    )
            elif parsed_project is not None:
                # The originating manager was not itself project-scoped
                # (for example the top-level ``/projects`` collection). The
                # concrete target path still names a project, which is what
                # the policy evaluates; no project was pinned in the scope.
                project = parsed_project
        else:
            project = parsed_project
            action = default_action

        if action is None:
            return PermissionDecision(
                allowed=False,
                reason="unsupported_action",
                verb=verb,
                path=path,
                project=project,
                action=None,
                scope=scope,
            )

        if project is None:
            if action in self.unscoped_actions:
                return PermissionDecision(
                    allowed=True,
                    reason="unscoped_allowed",
                    verb=verb,
                    path=path,
                    project=None,
                    action=action,
                    scope=scope,
                )
            return PermissionDecision(
                allowed=False,
                reason="unscoped_denied",
                verb=verb,
                path=path,
                project=None,
                action=action,
                scope=scope,
            )

        if project_key(project) not in self._rules:
            return PermissionDecision(
                allowed=False,
                reason="project_denied",
                verb=verb,
                path=path,
                project=project,
                action=action,
                scope=scope,
            )

        if action not in self._rules[project_key(project)]:
            return PermissionDecision(
                allowed=False,
                reason="action_denied",
                verb=verb,
                path=path,
                project=project,
                action=action,
                scope=scope,
            )

        return PermissionDecision(
            allowed=True,
            reason="project_allowed" if derived else "action_allowed",
            verb=verb,
            path=path,
            project=project,
            action=action,
            scope=scope,
        )

    def check_request(
        self,
        verb: str,
        url: str,
        *,
        scope: RequestScope | None = None,
        base_url: str | None = None,
    ) -> PermissionDecision:
        """Alias for :meth:`check`."""
        return self.check(verb, url, scope=scope, base_url=base_url)


def resolve_policy(
    *,
    permissions: (
        Mapping[str | int, ActionInput]
        | Iterable[ProjectPermission | tuple[str | int, ActionInput] | str]
        | None
    ) = None,
    permission_policy: ProjectPolicy | None = None,
    project_policy: ProjectPolicy | None = None,
    allowed_projects: Iterable[str | int] | None = None,
    allowed_actions: ActionInput = Action.READ,
    unscoped_actions: ActionInput = (),
    allow_external_origins: bool = False,
) -> ProjectPolicy | None:
    """Build the policy passed to :class:`gitlab.Gitlab`.

    At most one of ``permissions``, ``permission_policy``, ``project_policy``
    and ``allowed_projects`` may be supplied. ``allowed_projects`` is a
    convenience form where every listed project receives the same
    ``allowed_actions``.
    """
    explicit = [
        value is not None
        for value in (permissions, permission_policy, project_policy, allowed_projects)
    ]
    if sum(explicit) > 1:
        raise ValueError(
            "Only one of permissions, permission_policy, project_policy or "
            "allowed_projects may be provided"
        )

    if permission_policy is not None:
        return permission_policy
    if project_policy is not None:
        return project_policy
    if allowed_projects is not None:
        actions = normalize_actions(allowed_actions)
        return ProjectPolicy(
            {project: actions for project in allowed_projects},
            unscoped_actions=unscoped_actions,
            allow_external_origins=allow_external_origins,
        )
    if permissions is not None:
        return ProjectPolicy(
            permissions,
            unscoped_actions=unscoped_actions,
            allow_external_origins=allow_external_origins,
        )
    if unscoped_actions or allow_external_origins:
        raise ValueError(
            "unscoped_actions and allow_external_origins require a permission "
            "configuration"
        )
    return None
