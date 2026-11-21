#
# Copyright (c) 2012 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Common Policy Engine Implementation

Policies are expressed as a target and an associated rule::

    "<target>": <rule>

The `target` is specific to the service that is conducting policy
enforcement.  Typically, the target refers to an API call.

For the `<rule>` part, see `Policy Rule Expressions`.

Policy Rule Expressions
~~~~~~~~~~~~~~~~~~~~~~~

Policy rules can be expressed in one of two forms: a string written in the new
policy language or a list of lists. The string format is preferred since it's
easier for most people to understand.

In the policy language, each check is specified as a simple "a:b" pair that is
matched to the correct class to perform that check:

+--------------------------------+------------------------------------------+
|            TYPE                |                SYNTAX                    |
+================================+==========================================+
|User's Role                     |              role:admin                  |
+--------------------------------+------------------------------------------+
|Rules already defined on policy |          rule:admin_required             |
+--------------------------------+------------------------------------------+
|Against URLs¹                   |         http://my-url.org/check          |
+--------------------------------+------------------------------------------+
|User attributes²                |    project_id:%(target.project.id)s      |
+--------------------------------+------------------------------------------+
|Strings                         |        - <variable>:'xpto2035abc'        |
|                                |        - 'myproject':<variable>          |
+--------------------------------+------------------------------------------+
|                                |         - project_id:xpto2035abc         |
|Literals                        |         - domain_id:20                   |
|                                |         - True:%(user.enabled)s          |
+--------------------------------+------------------------------------------+

¹URL checking must return ``True`` to be valid

²User attributes (obtained through the token): user_id, domain_id or project_id

Conjunction operators ``and`` and ``or`` are available, allowing for more
expressiveness in crafting policies. For example::

    "role:admin or (project_id:%(project_id)s and role:projectadmin)"

The policy language also has the ``not`` operator, allowing a richer
policy rule::

    "project_id:%(project_id)s and not role:dunce"

Operator precedence is below:

+------------+-------------+-------------+
| PRECEDENCE |     TYPE    | EXPRESSION  |
+============+=============+=============+
|      4     |  Grouping   |    (...)    |
+------------+-------------+-------------+
|      3     | Logical NOT |   not ...   |
+------------+-------------+-------------+
|      2     | Logical AND | ... and ... |
+------------+-------------+-------------+
|      1     | Logical OR  | ... or ...  |
+------------+-------------+-------------+

Operator with larger precedence number precedes others with smaller numbers.

In the list-of-lists representation, each check inside the innermost
list is combined as with an "and" conjunction -- for that check to pass,
all the specified checks must pass.  These innermost lists are then
combined as with an "or" conjunction. As an example, take the following
rule, expressed in the list-of-lists representation::

    [["role:admin"], ["project_id:%(project_id)s", "role:projectadmin"]]

Finally, two special policy checks should be mentioned; the policy
check "@" will always accept an access, and the policy check "!" will
always reject an access.  (Note that if a rule is either the empty
list (``[]``) or the empty string (``""``), this is equivalent to the "@"
policy check.)  Of these, the "!" policy check is probably the most useful,
as it allows particular rules to be explicitly disabled.

Generic Checks
~~~~~~~~~~~~~~

A `generic` check is used to perform matching against attributes that are sent
along with the API calls.  These attributes can be used by the policy engine
(on the right side of the expression), by using the following syntax::

    <some_attribute>:%(user.id)s

The value on the right-hand side is either a string or resolves to a
string using regular Python string substitution.  The available attributes
and values are dependent on the program that is using the common policy
engine.

All of these attributes (related to users, API calls, and context) can be
checked against each other or against constants.  It is important to note
that these attributes are specific to the service that is conducting
policy enforcement.

Generic checks can be used to perform policy checks on the following user
attributes obtained through a token:

- user_id
- domain_id or project_id (depending on the token scope)
- list of roles held for the given token scope

.. note::
   Some resources which are exposed by the API do not support policy
   enforcement by user_id, and only support policy enforcement by project_id.
   Some global resources do not support policy enforcement by combination of
   user_id and project_id.

For example, a check on the user_id would be defined as::

    user_id:<some_value>

Together with the previously shown example, a complete generic check
would be::

    user_id:%(user.id)s

It is also possible to perform checks against other attributes that
represent the credentials.  This is done by adding additional values to
the ``creds`` dict that is passed to the
:meth:`~oslo_policy.policy.Enforcer.enforce` method.

Special Checks
~~~~~~~~~~~~~~

Special checks allow for more flexibility than is possible using generic
checks.  The built-in special check types are ``role``, ``rule``, and ``http``
checks.

Role Check
^^^^^^^^^^

A ``role`` check is used to check if a specific role is present in the supplied
credentials.  A role check is expressed as::

    "role:<role_name>"

Rule Check
^^^^^^^^^^

A :class:`rule check <oslo_policy.policy.RuleCheck>` is used to
reference another defined rule by its name.  This allows for common
checks to be defined once as a reusable rule, which is then referenced
within other rules.  It also allows one to define a set of checks as a
more descriptive name to aid in readability of policy.  A rule check is
expressed as::

    "rule:<rule_name>"

The following example shows a role check that is defined as a rule,
which is then used via a rule check::

    "admin_required": "role:admin"
    "<target>": "rule:admin_required"

HTTP Check
^^^^^^^^^^

An ``http`` check is used to make an HTTP request to a remote server to
determine the results of the check.  The target and credentials are passed to
the remote server for evaluation.  The action is authorized if the remote
server returns a response of ``True``. An http check is expressed as::

    "http:<target URI>"

It is expected that the target URI contains a string formatting keyword,
where the keyword is a key from the target dictionary.  An example of an
http check where the `name` key from the target is used to construct the
URL is would be defined as::

    "http://server.test/%(name)s"

Registering New Special Checks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible for additional special check types to be registered
using the :func:`~oslo_policy.policy.register` function.

The following classes can be used as parents for custom special check types:

* :class:`~oslo_policy.policy.AndCheck`
* :class:`~oslo_policy.policy.NotCheck`
* :class:`~oslo_policy.policy.OrCheck`
* :class:`~oslo_policy.policy.RuleCheck`

Default Rule
~~~~~~~~~~~~

A default rule can be defined, which will be enforced when a rule does
not exist for the target that is being checked.  By default, the rule
associated with the rule name of ``default`` will be used as the default
rule.  It is possible to use a different rule name as the default rule
by setting the ``policy_default_rule`` configuration setting to the
desired rule name.
"""

from collections.abc import MutableMapping, Sequence
import contextvars
import copy
import dataclasses
import errno
import hashlib
import logging
import os
import threading
from typing import Any, Self, TypeAlias, TypedDict
import warnings

from oslo_config import cfg
from oslo_context import context
from oslo_serialization import jsonutils
from oslo_utils import strutils
import yaml

from oslo_policy import _cache_handler
from oslo_policy import _checks
from oslo_policy._i18n import _
from oslo_policy import _parser
from oslo_policy import opts


LOG = logging.getLogger(__name__)

# NOTE: This context variable pins the rule set used by an in-flight
# enforcement. A reload can install a completely new rule set at any time, but
# every ``rule:`` reference followed during a single ``enforce()`` call must be
# resolved against the same version. The value is a tuple so that nested
# enforcers do not accidentally pin each other's rules.
_ACTIVE_RULES: contextvars.ContextVar[Any] = contextvars.ContextVar(
    'oslo_policy_active_rules', default=None
)


register = _checks.register
"""Register a function or :class:`.Check` class as a policy check.

:param name: Gives the name of the check type, e.g., "rule",
             "role", etc.  If name is ``None``, a default check type
             will be registered.
:param func: If given, provides the function or class to register.
             If not given, returns a function taking one argument
             to specify the function or class to register,
             allowing use as a decorator.
"""

Check = _checks.Check
"""A base class to allow for user-defined policy checks.

:param kind: The kind of the check, i.e., the field before the ``:``.
:param match: The match of the check, i.e., the field after the ``:``.

"""

AndCheck = _checks.AndCheck
"""Implements the "and" logical operator.

A policy check that requires that a list of other checks all return True.

:param list rules: rules that will be tested.

"""

NotCheck = _checks.NotCheck
"""Implements the "not" logical operator.

A policy check that inverts the result of another policy check.

:param rule: The rule to negate.

"""

OrCheck = _checks.OrCheck
"""Implements the "or" operator.

A policy check that requires that at least one of a list of other
checks returns ``True``.

:param rules: A list of rules that will be tested.

"""

RuleCheck = _checks.RuleCheck
"""Recursively checks credentials based on the defined rules."""


class PolicyNotAuthorized(Exception):
    """Default exception raised for policy enforcement failure."""

    def __init__(
        self,
        rule: _checks.BaseCheck | str,
        target: _checks.TargetT,
        creds: MutableMapping[str, Any],
    ) -> None:
        msg = _('%(rule)s is disallowed by policy') % {'rule': rule}
        super().__init__(msg)


class InvalidScope(Exception):
    """Raised when the scope of the request mismatches the policy scope."""

    def __init__(
        self,
        rule: '_checks.BaseCheck | RuleDefault',
        operation_scopes: list[str],
        token_scope: str,
    ) -> None:
        msg = (
            f'{rule} requires a scope of {operation_scopes}, request '
            f'was made with {token_scope} scope.'
        )
        super().__init__(msg)


class DuplicatePolicyError(Exception):
    def __init__(self, name: str) -> None:
        msg = _('Policy %(name)s is already registered') % {'name': name}
        super().__init__(msg)


class PolicyNotRegistered(Exception):
    def __init__(self, name: str) -> None:
        msg = _('Policy %(name)s has not been registered') % {'name': name}
        super().__init__(msg)


class InvalidDefinitionError(Exception):
    def __init__(
        self, names: list[str], errors: list[str] | None = None
    ) -> None:
        msg = _(
            'Policies %(names)s are not well defined. Check logs for '
            'more details.'
        ) % {'names': names}
        self.names = names
        self.errors = errors or []
        if self.errors:
            msg = f'{msg} {" ".join(self.errors)}'
        super().__init__(msg)


class InvalidRuleDefault(Exception):
    def __init__(self, error: str) -> None:
        msg = _('Invalid policy rule default: %(error)s.') % {'error': error}
        super().__init__(msg)


class InvalidContextObject(Exception):
    def __init__(self, error: str) -> None:
        msg = _('Invalid context object: %(error)s.') % {'error': error}
        super().__init__(msg)


def parse_file_contents(data: str | bytes) -> dict[str, str]:
    """Parse the raw contents of a policy file.

    Parses the contents of a policy file which currently can be in yaml format.
    Both can be parsed as yaml.

    :param data: A string containing the contents of a policy file.
    :returns: A dict of the form ``{'policy_name1': 'policy1',
        'policy_name2': 'policy2,...}``
    """
    try:
        parsed = yaml.safe_load(data)
    except yaml.YAMLError as e:
        # For backwards-compatibility, convert yaml error to ValueError,
        # which is what JSON loader raised.
        raise ValueError(str(e))
    return parsed or {}


def _rules_fingerprint(rules: MutableMapping[str, _checks.BaseCheck]) -> str:
    """Return a stable fingerprint for a set of parsed rules."""
    digest = hashlib.sha256()
    for name in sorted(rules):
        digest.update(str(name).encode('utf-8'))
        digest.update(b'\0')
        digest.update(str(rules[name]).encode('utf-8'))
        digest.update(b'\0')
    return digest.hexdigest()


class Rules(dict[str, _checks.BaseCheck]):
    """A store for rules. Handles the default_rule setting directly."""

    def __init__(
        self,
        rules: MutableMapping[str, _checks.BaseCheck] | None = None,
        default_rule: _checks.BaseCheck | str | None = None,
        generation: int = 0,
    ) -> None:
        """Initialize the Rules store."""

        super().__init__(dict(rules or {}))
        self.default_rule = default_rule
        self.generation = generation

    @property
    def fingerprint(self) -> str:
        """A stable digest of the effective rules in this collection."""
        return _rules_fingerprint(self)

    @classmethod
    def load(
        cls,
        data: str | bytes,
        default_rule: _checks.BaseCheck | str | None = None,
    ) -> Self:
        """Allow loading of YAML rule data.

        .. versionadded:: 1.5.0

        """
        parsed_file = parse_file_contents(data)

        # Parse the rules
        rules = {k: _parser.parse_rule(v) for k, v in parsed_file.items()}

        return cls(rules, default_rule)

    @classmethod
    def from_dict(
        cls,
        rules_dict: MutableMapping[str, str],
        default_rule: _checks.BaseCheck | str | None = None,
    ) -> Self:
        """Allow loading of rule data from a dictionary."""

        # Parse the rules stored in the dictionary
        rules = {k: _parser.parse_rule(v) for k, v in rules_dict.items()}

        return cls(rules, default_rule)

    def __missing__(self, key: str) -> _checks.BaseCheck | None:
        """Implements the default rule handling."""

        if isinstance(self.default_rule, dict):
            raise KeyError(key)

        # If the default rule isn't actually defined, do something
        # reasonably intelligent
        if not self.default_rule:
            raise KeyError(key)

        if isinstance(self.default_rule, _checks.BaseCheck):
            return self.default_rule

        # We need to check this or we can get infinite recursion
        if self.default_rule not in self:
            raise KeyError(key)

        elif isinstance(self.default_rule, str):
            return self[self.default_rule]

        return None

    def __str__(self) -> str:
        """Dumps a string representation of the rules."""

        # Start by building the canonical strings for the rules
        out_rules = {}
        for key, value in self.items():
            # Use empty string for singleton TrueCheck instances
            if isinstance(value, _checks.TrueCheck):
                out_rules[key] = ''
            else:
                out_rules[key] = str(value)

        # Dump a pretty-printed JSON representation
        return jsonutils.dumps(out_rules, indent=4)


class InvalidPolicyDefinitionError(InvalidDefinitionError):
    """Raised when a policy directory cannot be loaded as one version.

    The exception reports every problem found while staging the candidate
    policy set. No part of the candidate set is made active when this is
    raised.
    """


@dataclasses.dataclass(frozen=True)
class PolicyVersion:
    """Identifies the policy version currently active in an enforcer.

    :param generation: Monotonically increasing version number. It is only
        advanced when a reload successfully installs a new rule set.
    :param fingerprint: A stable digest of the effective rules, including
        rules from the main policy file, policy directories and registered
        defaults.
    :param path: The path of the main policy file, if one was found.
    :param files: The policy files that contributed rules to this version.
    """

    generation: int
    fingerprint: str
    path: str | None
    files: tuple[str, ...]

    @property
    def version(self) -> int:
        """Alias for :attr:`generation`."""
        return self.generation

    def as_dict(self) -> dict[str, Any]:
        """Return the version as a plain dictionary."""
        return dataclasses.asdict(self)

    def __str__(self) -> str:
        return (
            f'generation={self.generation} '
            f'fingerprint={self.fingerprint} '
            f'path={self.path}'
        )


class Enforcer:
    """Responsible for loading and enforcing rules.

    :param conf: A configuration object.
    :param policy_file: Custom policy file to use, if none is specified,
        ``conf.oslo_policy.policy_file`` will be used.
    :param rules: Default dictionary / Rules to use. It will be considered just
        in the first instantiation. If :meth:`load_rules` with
        ``force_reload=True``, :meth:`clear` or :meth:`set_rules` with
        ``overwrite=True`` is called this will be overwritten.
    :param default_rule: Default rule to use, conf.default_rule will be used if
        none is specified.
    :param use_conf: Whether to load rules from cache or config file.
    :param overwrite: Whether to overwrite existing rules when reload rules
        from config file.
    """

    default_rule: _checks.BaseCheck | str | None
    registered_rules: dict[str, 'RuleDefault']
    policy_path: str | None
    policy_file: str
    overwrite: bool

    _file_rules: dict[str, 'RuleDefault']
    _rules: Rules
    _generation: int
    _version: PolicyVersion
    _loaded_files: tuple[str, ...]
    _reload_lock: threading.RLock

    _need_check_rule: bool
    # FIXME(stephenfin): This is actually a simpler type since only the mtime
    # field is required. We could just use a dict of str to int
    _policy_dir_mtimes: _cache_handler.CacheT
    _file_cache: _cache_handler.CacheT

    def __init__(
        self,
        conf: cfg.ConfigOpts,
        policy_file: str | None = None,
        rules: MutableMapping[str, _checks.BaseCheck] | None = None,
        default_rule: _checks.BaseCheck | str | None = None,
        use_conf: bool = True,
        overwrite: bool = True,
        fallback_to_json_file: bool | None = None,
    ) -> None:
        if fallback_to_json_file is not None:
            warnings.warn(
                'fallback_to_json_file is deprecated and has no effect.',
                category=DeprecationWarning,
            )

        self.conf = conf
        opts._register(conf)

        self.default_rule = (
            default_rule or self.conf.oslo_policy.policy_default_rule
        )
        self._rules = Rules(rules, self.default_rule)
        self.registered_rules = {}
        self._file_rules = {}

        self.policy_path = None

        self.policy_file = policy_file or conf.oslo_policy.policy_file
        self.use_conf = use_conf
        self.overwrite = overwrite

        self._generation = 0
        self._loaded_files = ()
        self._version = self._make_version()
        self._reload_lock = threading.RLock()
        self._policy_dirs_override: tuple[str, ...] | None = None
        self._need_check_rule = True
        self._policy_dir_mtimes = {}
        self._file_cache = {}
        self._informed_no_policy_file = False
        # NOTE(gmann): This flag will suppress the warning for
        # policies changing their default check_str that have
        # not been overridden by operators. This does not affect the
        # warning for policy changed their name or deprecated
        # for removal.
        self.suppress_default_change_warnings = False
        # FOR TESTING ONLY
        self.suppress_deprecation_warnings = False
        # NOTE(tkajinam): Some components(eg. neutron-lib) build their own
        # enforcers to check only partial rules with the full policy rules, and
        # this sometimes causes a lot of undefined warnings
        self.skip_undefined_check = False

    @property
    def rules(self) -> Rules:
        """The rules visible to the current enforcement.

        During an enforcement this is the immutable snapshot pinned for that
        call. Outside an enforcement it is the currently active rule set.
        """
        return self._rules_for_enforcement

    @rules.setter
    def rules(self, rules: Rules) -> None:
        self._rules = rules

    @property
    def file_rules(self) -> dict[str, 'RuleDefault']:
        """The rules loaded from policy files for the active version."""
        return self._file_rules

    @file_rules.setter
    def file_rules(self, rules: dict[str, 'RuleDefault']) -> None:
        self._file_rules = rules

    @property
    def version(self) -> PolicyVersion:
        """The policy version currently active for new enforcements."""
        with self._reload_lock:
            return self._version

    def get_version(self) -> PolicyVersion:
        """Return the policy version currently in effect.

        This is equivalent to reading :attr:`version`. The returned object is
        immutable and can be retained to compare against a later reload.
        """
        return self.version

    @property
    def _rules_for_enforcement(self) -> Rules:
        """Rules to use while resolving a rule chain.

        During an enforcement this returns the snapshot pinned by
        :meth:`enforce`. Outside of an enforcement it returns the currently
        active version.
        """
        active = _ACTIVE_RULES.get()
        if active is not None:
            owner, rules = active
            if owner is self:
                return rules
        return self._rules

    def _make_version(self) -> PolicyVersion:
        return PolicyVersion(
            generation=self._generation,
            fingerprint=self._rules.fingerprint,
            path=self.policy_path,
            files=self._loaded_files,
        )

    def _pin_version(self) -> PolicyVersion:
        """Publish a new version for subsequent enforcements."""
        self._rules.generation = self._generation
        self._version = self._make_version()
        return self._version

    def _install_rules(
        self,
        rules: Rules,
        file_rules: dict[str, 'RuleDefault'] | None = None,
        files: Sequence[str] | None = None,
        policy_path: str | None = None,
    ) -> PolicyVersion:
        """Install a fully built rule set in one step.

        The swap only touches the active rule set reference, so an enforcement
        that has already pinned the previous ``Rules`` object keeps seeing a
        consistent view.
        """
        with self._reload_lock:
            changed = rules.fingerprint != self._rules.fingerprint
            self._rules = rules
            if file_rules is not None:
                self._file_rules = file_rules
            if files is not None:
                self._loaded_files = tuple(sorted(set(files)))
            if policy_path is not None:
                self.policy_path = policy_path
            if changed:
                self._generation += 1
            return self._pin_version()

    def set_rules(
        self,
        rules: MutableMapping[str, _checks.BaseCheck],
        overwrite: bool = True,
        use_conf: bool = False,
    ) -> None:
        """Create a new :class:`Rules` based on the provided dict of rules.

        :param rules: New rules to use.
        :param overwrite: Whether to overwrite current rules or update them
            with the new rules.
        :param use_conf: Whether to reload rules from cache or config file.
        """

        if not isinstance(rules, dict):
            raise TypeError(
                _('Rules must be an instance of dict or Rules, got %s instead')
                % type(rules)
            )
        with self._reload_lock:
            self.use_conf = use_conf
            self._need_check_rule = True
            if overwrite:
                new_rules = Rules(rules, self.default_rule)
            else:
                new_rules = Rules(self._rules, self.default_rule)
                new_rules.update(rules)
            self._install_rules(new_rules)

    def clear(self) -> None:
        """Clears :class:`Enforcer` contents.

        This will clear this instances rules, policy's cache, file cache
        and policy's path.
        """
        with self._reload_lock:
            self.set_rules({})
            self.default_rule = None
            self.policy_path = None
            self._policy_dir_mtimes = {}
            self._file_cache = {}
            self.registered_rules = {}
            self._file_rules = {}
            self._loaded_files = ()
            self._policy_dirs_override = None
            self._generation = 0
            self._pin_version()
            self._informed_no_policy_file = False
            self.suppress_default_change_warnings = False
            self.suppress_deprecation_warnings = False

    def load_rules(self, force_reload: bool = False) -> None:
        """Loads policy_path's rules.

        Policy file is cached and will be reloaded if modified. When a change
        is found, the complete rule set is rebuilt and installed only after
        the rebuild finished, so a failed load never exposes a partial policy.

        :param force_reload: Whether to reload rules from config file.
        """

        if force_reload:
            self.use_conf = force_reload

        if not self.use_conf:
            return

        with self._reload_lock:
            self._load_rules_locked(force_reload, strict=False)

    def reload_rules(
        self,
        policy_file: str | None = None,
        policy_dirs: Sequence[str] | None = None,
    ) -> PolicyVersion:
        """Reload all policy sources once and activate them atomically.

        Unlike :meth:`load_rules`, this method always rereads the policy file
        and every file in the selected policy directories. The candidate rule
        set is built and validated as a whole before it is made active. If any
        file cannot be parsed, references an undefined rule, or contains a
        cyclical reference, :class:`InvalidPolicyDefinitionError` is raised
        and the previously active version remains in effect.

        :param policy_file: Policy file to use for this and subsequent reloads.
            Defaults to the file configured on the enforcer.
        :param policy_dirs: Policy directories to use for this and subsequent
            reloads. Defaults to ``conf.oslo_policy.policy_dirs``.
        :returns: The :class:`PolicyVersion` now in effect.
        :raises InvalidPolicyDefinitionError: If the candidate rule set is not
            complete and well defined.
        """
        with self._reload_lock:
            if policy_file is not None:
                self.policy_file = policy_file
                self.policy_path = None
            if policy_dirs is not None:
                self._policy_dirs_override = tuple(policy_dirs)

            self._load_rules_locked(
                force_reload=True,
                strict=True,
                require_main=policy_file is not None,
                require_dirs=policy_dirs is not None,
            )
            return self.version

    def reload_policy(
        self,
        policy_file: str | None = None,
        policy_dirs: Sequence[str] | None = None,
    ) -> PolicyVersion:
        """Alias for :meth:`reload_rules`."""
        return self.reload_rules(
            policy_file=policy_file,
            policy_dirs=policy_dirs,
        )

    def _load_rules_locked(
        self,
        force_reload: bool,
        strict: bool,
        require_main: bool = False,
        require_dirs: bool = False,
    ) -> PolicyVersion:
        try:
            main_path = self._get_policy_path(self.policy_file)
        except cfg.ConfigFilesNotFoundError:
            main_path = None

        policy_dirs = self._selected_policy_dirs()
        existing_policy_dirs = []
        missing_policy_dirs = []
        for path in policy_dirs:
            try:
                absolute_path = self._get_policy_path(path)
                existing_policy_dirs.append(absolute_path)
            except cfg.ConfigFilesNotFoundError:
                missing_policy_dirs.append(path)
                continue

        if strict and require_dirs and missing_policy_dirs:
            raise cfg.ConfigFilesNotFoundError(missing_policy_dirs)
        if strict and require_main and main_path is None:
            raise cfg.ConfigFilesNotFoundError([self.policy_file])

        if main_path is None:
            if not self._informed_no_policy_file:
                LOG.debug(
                    'The policy file %s could not be found.',
                    self.policy_file,
                )
                self._informed_no_policy_file = True
        else:
            self._informed_no_policy_file = False

        changed = force_reload or self._policy_inputs_changed(
            main_path, existing_policy_dirs
        )
        missing_defaults = any(
            name not in self._rules for name in self.registered_rules
        )
        if not changed and not missing_defaults:
            if self._need_check_rule:
                self.check_rules()
                self._need_check_rule = False
            return self.version

        candidate, file_rules, files, errors = self._build_candidate(
            main_path, existing_policy_dirs, strict
        )

        if strict:
            # Report syntax problems and structural problems from the same
            # batch together, so operators can fix everything in one pass.
            problems = errors + self._candidate_problems(candidate)
            if problems:
                # Remember the rejected input so a later implicit load
                # through enforce() does not pick it up until the files
                # change again.
                self._record_input_caches(existing_policy_dirs)
                raise InvalidPolicyDefinitionError(
                    sorted({name for name, _ in problems}),
                    errors=[message for _, message in problems],
                )
        else:
            for _name, message in errors:
                LOG.warning('Ignoring invalid policy definition: %s', message)

        self.policy_path = main_path
        version = self._install_rules(candidate, file_rules, files)
        # Cache updates happen after the rule set is in place; the reload lock
        # keeps other loads from observing an inconsistent pair.
        self._commit_policy_caches(existing_policy_dirs)
        self._need_check_rule = False
        if not strict:
            self.check_rules()
        return version

    def _selected_policy_dirs(self) -> Sequence[str]:
        if self._policy_dirs_override is not None:
            return self._policy_dirs_override
        return self.conf.oslo_policy.policy_dirs

    def _policy_inputs_changed(
        self, main_path: str | None, policy_dirs: Sequence[str]
    ) -> bool:
        """Check whether any policy source differs from the active version.

        This is a cheap mtime based check used by the compatibility
        :meth:`load_rules` path. It never mutates the caches; those are only
        updated after a candidate has been successfully installed.
        """
        if not self._rules:
            return True

        if main_path is not None:
            try:
                mtime = os.path.getmtime(main_path)
            except OSError:
                return True
            cache_info = self._file_cache.get(main_path)
            if cache_info is None or mtime != cache_info.get('mtime'):
                return True

        for path in policy_dirs:
            mtime = self._directory_mtime(path)
            cache_info = self._policy_dir_mtimes.get(path)
            if cache_info is None or mtime != cache_info.get('mtime'):
                return True

        return False

    @staticmethod
    def _directory_mtime(path: str) -> float:
        if not os.path.isdir(path):
            raise ValueError(f'{path} is not a directory')
        files = [path] + [os.path.join(path, f) for f in os.listdir(path)]
        return os.path.getmtime(max(files, key=os.path.getmtime))

    def _read_policy_file(self, path: str) -> tuple[str, float]:
        try:
            mtime = os.path.getmtime(path)
            with open(path) as fap:
                return fap.read(), mtime
        except OSError as err:
            if err.errno == errno.EACCES:
                raise cfg.ConfigFilesPermissionDeniedError([path])
            raise cfg.ConfigFilesNotFoundError([path])

    def _parse_policy_file(
        self, path: str, strict: bool
    ) -> tuple[
        dict[str, _checks.BaseCheck],
        dict[str, 'RuleDefault'],
        list[tuple[str, str]],
    ]:
        """Parse one policy file into checks and file-rule records."""
        errors: list[tuple[str, str]] = []
        checks: dict[str, _checks.BaseCheck] = {}
        file_rules: dict[str, 'RuleDefault'] = {}
        redundant_file_rules: list[str] = []

        try:
            data, _mtime = self._read_policy_file(path)
        except (
            cfg.ConfigFilesNotFoundError,
            cfg.ConfigFilesPermissionDeniedError,
        ) as exc:
            if strict:
                return {}, {}, [(path, f'{path}: {exc}')]
            raise

        try:
            parsed = parse_file_contents(data)
        except ValueError as exc:
            if strict:
                return {}, {}, [(path, f'{path}: invalid policy file: {exc}')]
            raise

        if not isinstance(parsed, dict):
            message = f'{path}: policy file must contain a mapping'
            if strict:
                return {}, {}, [(path, message)]
            raise ValueError(message)

        for name, check_str in parsed.items():
            if not isinstance(name, str):
                message = f'{path}: policy name {name!r} is not a string'
                if strict:
                    errors.append((str(name), message))
                else:
                    LOG.warning(message)
                continue
            try:
                check = _parser.parse_rule(
                    check_str, raise_on_error=strict
                )
                file_rule = RuleDefault(name, check_str)
            except (TypeError, ValueError) as exc:
                errors.append((name, f'{path}: {name}: {exc}'))
                continue
            checks[name] = check
            file_rules[name] = file_rule
            reg_rule = self.registered_rules.get(name)
            if reg_rule and file_rule == reg_rule:
                redundant_file_rules.append(name)

        if redundant_file_rules:
            # NOTE(gmann): Log warning for redundant file rules which
            # can be detected via 'oslopolicy-list-redundant' tool too.
            LOG.warning(
                'Policy Rules %(names)s specified in policy files '
                'are the same as the defaults provided by the '
                'service. You can remove these rules from policy '
                'files which will make maintenance easier. You can '
                'detect these redundant rules by '
                '``oslopolicy-list-redundant`` tool also.',
                {'names': redundant_file_rules},
            )

        return checks, file_rules, errors

    def _build_candidate(
        self,
        main_path: str | None,
        policy_dirs: Sequence[str],
        strict: bool,
    ) -> tuple[
        Rules,
        dict[str, 'RuleDefault'],
        tuple[str, ...],
        list[tuple[str, str]],
    ]:
        """Build a complete candidate rule set without touching active state.

        All policy files are read and parsed, rules are merged in declaration
        order, and registered defaults are applied. The result is only
        installed by the caller once it has been validated.
        """
        if self.overwrite:
            candidate = Rules(default_rule=self.default_rule)
            file_rules: dict[str, 'RuleDefault'] = {}
        else:
            candidate = Rules(self._rules, self.default_rule)
            file_rules = dict(self._file_rules)

        files: list[str] = []
        errors: list[tuple[str, str]] = []

        sources: list[str] = []
        if main_path is not None:
            sources.append(main_path)
        for path in policy_dirs:
            if not os.path.isdir(path):
                raise ValueError(f'{path} is not a directory')
            policy_files = next(os.walk(path))[2]
            policy_files.sort()
            sources.extend(
                os.path.join(path, name)
                for name in policy_files
                if not name.startswith('.')
            )

        for path in sources:
            checks, parsed_file_rules, parsed_errors = self._parse_policy_file(
                path, strict
            )
            errors.extend(parsed_errors)
            candidate.update(checks)
            file_rules.update(parsed_file_rules)
            files.append(path)

        self._apply_registered_defaults(candidate, file_rules, strict, errors)
        return candidate, file_rules, tuple(files), errors

    def _apply_registered_defaults(
        self,
        rules: Rules,
        file_rules: dict[str, 'RuleDefault'],
        strict: bool,
        errors: list[tuple[str, str]],
    ) -> None:
        """Apply registered defaults on top of a staged rule set."""
        for default in self.registered_rules.values():
            if default.deprecated_for_removal:
                self._emit_deprecated_for_removal_warning(default, file_rules)

            if default.name in rules:
                continue

            if strict:
                try:
                    _parser.parse_rule(
                        default.check_str, raise_on_error=True
                    )
                except (TypeError, ValueError) as exc:
                    errors.append(
                        (
                            default.name,
                            f'registered default {default.name}: {exc}',
                        )
                    )
                    continue
            # NOTE: Resolve deprecations against the staged file rules so
            # the candidate is consistent with the version being installed.
            check = default.check
            if default.deprecated_rule:
                check = self._handle_deprecated_rule(default, file_rules)

            rules[default.name] = check

    def _candidate_problems(
        self, rules: MutableMapping[str, _checks.BaseCheck]
    ) -> list[tuple[str, str]]:
        """Return undefined and cyclical references in a candidate set."""
        problems: list[tuple[str, str]] = []
        for name, check in rules.items():
            if not self.skip_undefined_check and self._undefined_check(
                check, rules
            ):
                problems.append(
                    (
                        name,
                        f'{name}: references a rule that is not defined',
                    )
                )
            if self._cycle_check(check, rules=rules):
                problems.append(
                    (name, f'{name}: is part of a cyclical reference')
                )
        return problems

    def _record_input_caches(self, policy_dirs: Sequence[str]) -> None:
        """Record current input state without installing new rules.

        Used when a candidate is rejected. The active rule set is untouched,
        but a subsequent implicit load will not retry the same content until
        one of the files changes.
        """
        sources = set(self._loaded_files)
        if self.policy_path is not None:
            sources.add(self.policy_path)
        for path in policy_dirs:
            if not os.path.isdir(path):
                continue
            for name in next(os.walk(path))[2]:
                if not name.startswith('.'):
                    sources.add(os.path.join(path, name))

        for path in sources:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            self._file_cache[path] = {
                'data': '',
                'mtime': mtime,
            }
        for path in policy_dirs:
            if not os.path.isdir(path):
                continue
            self._policy_dir_mtimes[path] = {
                'data': '',
                'mtime': self._directory_mtime(path),
            }

    def _commit_policy_caches(self, policy_dirs: Sequence[str]) -> None:
        """Update mtime caches only after a candidate was installed."""
        active_files = set(self._loaded_files)
        self._file_cache = {
            path: info
            for path, info in self._file_cache.items()
            if path in active_files
        }
        for path in active_files:
            try:
                mtime = os.path.getmtime(path)
                with open(path) as fap:
                    data = fap.read()
            except OSError:
                continue
            self._file_cache[path] = {'data': data, 'mtime': mtime}

        self._policy_dir_mtimes = {
            path: info
            for path, info in self._policy_dir_mtimes.items()
            if path in policy_dirs
        }
        for path in policy_dirs:
            self._policy_dir_mtimes[path] = {
                'data': '',
                'mtime': self._directory_mtime(path),
            }

    def check_rules(self, raise_on_violation: bool = False) -> bool:
        """Look for rule definitions that are obviously incorrect."""
        undefined_checks = []
        cyclic_checks = []
        violation = False
        for name, check in self.rules.items():
            if not self.skip_undefined_check and self._undefined_check(check):
                undefined_checks.append(name)
                violation = True
            if self._cycle_check(check):
                cyclic_checks.append(name)
                violation = True

        if undefined_checks:
            LOG.warning(
                'Policies %(names)s reference a rule that is not defined.',
                {'names': undefined_checks},
            )
        if cyclic_checks:
            LOG.warning(
                'Policies %(names)s are part of a cyclical reference.',
                {'names': cyclic_checks},
            )

        if raise_on_violation and violation:
            raise InvalidDefinitionError(undefined_checks + cyclic_checks)

        return not violation

    def _emit_deprecated_for_removal_warning(
        self,
        default: 'RuleDefault',
        file_rules: dict[str, 'RuleDefault'] | None = None,
    ) -> None:
        if file_rules is None:
            file_rules = self.file_rules
        # If the policy is being removed completely, we need to let operators
        # know that the policy is going to be silently ignored in the future
        # and they can remove it from their overrides since it isn't being
        # replaced by another policy.
        if (
            not self.suppress_deprecation_warnings
            and default.name in file_rules
        ):
            warnings.warn(
                f'Policy "{default.name}":"{default.check_str}" was '
                f'deprecated for removal in {default.deprecated_since}. '
                f'Reason: {default.deprecated_reason}. Its value may be '
                f'silently ignored in the future.'
            )

    def _handle_deprecated_rule(
        self,
        default: 'RuleDefault',
        file_rules: dict[str, 'RuleDefault'] | None = None,
    ) -> _checks.BaseCheck:
        """Handle cases where a policy rule has been deprecated.

        :param default: an instance of RuleDefault that contains an instance of
            DeprecatedRule
        :param file_rules: The file rules of the candidate version. Defaults
            to the active version's file rules.
        """
        if file_rules is None:
            file_rules = self.file_rules
        deprecated_rule = default.deprecated_rule
        assert deprecated_rule is not None  # narrow type

        deprecated_reason = (
            deprecated_rule.deprecated_reason or default.deprecated_reason
        )
        deprecated_since = (
            deprecated_rule.deprecated_since or default.deprecated_since
        )

        deprecated_msg = (
            f'Policy "{deprecated_rule.name}":"{deprecated_rule.check_str}" '
            f'was deprecated in {deprecated_since} in favor of '
            f'"{default.name}":"{default.check_str}". Reason: '
            f'{deprecated_reason}. Either ensure your deployment is ready '
            f'for the new default or copy/paste the deprecated policy into '
            f'your policy file and maintain it manually.'
        )

        # Print a warning because the actual policy name is changing. If
        # operators are relying on an override for foo:bar and it's getting
        # renamed to foo:create_bar then they need to be able to see that
        # before they roll out the next release. If the policy name is in
        # self.file_rules, we know that it's being overridden.
        if (
            deprecated_rule.name != default.name
            and deprecated_rule.name in file_rules
        ):
            if not self.suppress_deprecation_warnings:
                warnings.warn(deprecated_msg)

            # If the deprecated policy is being overridden and doesn't match
            # the default deprecated policy, override the new policy's default
            # with the old check string. This should prevents unwanted exposure
            # to APIs on upgrade.
            # There's one exception to this: When we generate a sample policy,
            # we set the deprecated rule name to reference the new rule. If we
            # see that the deprecated override rule is just the new rule, then
            # we shouldn't mess with it.
            file_rule = file_rules[deprecated_rule.name]
            if (
                file_rule.check != deprecated_rule.check
                and str(file_rule.check) != f'rule:{default.name}'
                and default.name not in file_rules.keys()
            ):
                return file_rule.check

        # In this case, the default check string is changing. We need to let
        # operators know that this is going to change. If they don't want to
        # override it, they are going to have to make sure the right
        # infrastructure exists before they upgrade. This overrides the new
        # check with an OrCheck that combines the new and old check_str
        # attributes from the new and deprecated policies. This will make it so
        # that deployments don't break on upgrade, but they receive log
        # messages telling them stuff is going to change if they don't maintain
        # the policy manually or add infrastructure to their deployment to
        # support the new policy.
        # If the enforce_new_defaults flag is True, do not add OrCheck to the
        # old check_str and enforce only the new defaults.
        if (
            not self.conf.oslo_policy.enforce_new_defaults
            and deprecated_rule.check_str != default.check_str
            and default.name not in file_rules
        ):
            if not (
                self.suppress_deprecation_warnings
                or self.suppress_default_change_warnings
            ):
                warnings.warn(deprecated_msg)

            return OrCheck([default.check, deprecated_rule.check])

        return default.check

    def _undefined_check(
        self,
        check: _checks.BaseCheck,
        rules: MutableMapping[str, _checks.BaseCheck] | None = None,
    ) -> bool:
        """Check if a RuleCheck references an undefined rule."""
        if rules is None:
            rules = self.rules
        if isinstance(check, RuleCheck):
            if check.match not in rules:
                # Undefined rule
                return True

        # An AndCheck or OrCheck is composed of multiple rules so check
        # each of those.
        nested_rules = getattr(check, 'rules', None)
        if nested_rules:
            for rule in nested_rules:
                if self._undefined_check(rule, rules):
                    return True
        return False

    def _cycle_check(
        self,
        check: _checks.BaseCheck,
        seen: set[str] | None = None,
        rules: MutableMapping[str, _checks.BaseCheck] | None = None,
    ) -> bool:
        """Check if RuleChecks cycle.

        Looking for something like::

            "foo": "rule:bar"
            "bar": "rule:foo"

        :param check: The check to search for.
        :param seen: A set of previously seen rules, else None.
        :param rules: The rule set to resolve references against, else the
            active rules.
        """
        if seen is None:
            seen = set()

        if rules is None:
            rules = self.rules

        if isinstance(check, RuleCheck):
            if check.match in seen:
                # Cycle found
                return True
            seen.add(check.match)
            if check.match in rules:
                # There can only be a cycle if the referenced rule is defined.
                if self._cycle_check(rules[check.match], seen, rules):
                    return True

        # An AndCheck or OrCheck is composed of multiple rules so check
        # each of those.
        nested_rules = getattr(check, 'rules', None)
        if nested_rules:
            for rule in nested_rules:
                # As there being an OrCheck or AndCheck, a copy of the father's
                # seen should be called here. In order that the checks in
                # different branchs are separated.
                if self._cycle_check(rule, seen.copy(), rules):
                    return True
        return False

    def _get_policy_path(self, path: str) -> str:
        """Locate the policy YAML data file/path.

        :param path: It's value can be a full path or related path. When
            full path specified, this function just returns the full path. When
            related path specified, this function will search configuration
            directories to find one that exists.

        :returns: The policy path
        :raises: ConfigFilesNotFoundError if the file/path couldn't be located.
        """
        policy_path = self.conf.find_file(path)
        if policy_path:
            return policy_path

        raise cfg.ConfigFilesNotFoundError([path])

    def enforce(
        self,
        rule: _checks.BaseCheck | str,
        target: _checks.TargetT,
        creds: _checks.CredsT,
        do_raise: bool = False,
        exc: type[Exception] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """Checks authorization of a rule against the target and credentials.

        :param rule: The rule to evaluate as a string or :class:`BaseCheck`.
        :param target: As much information about the object being operated on
            as possible. The target argument should be a dict instance or an
            instance of a class that fully supports the Mapping abstract base
            class.
        :param creds: As much information about the user performing the action
            as possible. This parameter can also be an instance of
            ``oslo_context.context.RequestContext``.
        :param do_raise: Whether to raise an exception or not if check
            fails.
        :param exc: Class of the exception to raise if the check fails.
            Any remaining arguments passed to :meth:`enforce` (both positional
            and keyword arguments) will be passed to the exception class. If
            not specified, :class:`PolicyNotAuthorized` will be used.
        :return: ``False`` if the policy does not allow the action and ``exc``
            is not provided; otherwise, returns a value that evaluates to
            ``True``.  Note: for rules using the "case" expression, this
            ``True`` value will be the specified string from the expression.
        """
        # Resolve the whole rule chain against one version. A concurrent
        # reload may install a new rule set while this call is running, but
        # every ``rule:`` reference followed by this call keeps using the
        # snapshot pinned here.
        active = _ACTIVE_RULES.get()
        if active is not None and active[0] is self:
            # A check invoked nested enforcement on the same enforcer. Reuse
            # the already pinned snapshot instead of consulting a newer one.
            return self._enforce_loaded(
                rule, target, creds, do_raise, exc, *args, **kwargs
            )

        self.load_rules()
        token = _ACTIVE_RULES.set((self, self._rules_for_enforcement))
        try:
            return self._enforce_loaded(
                rule, target, creds, do_raise, exc, *args, **kwargs
            )
        finally:
            _ACTIVE_RULES.reset(token)

    def _enforce_loaded(
        self,
        rule: _checks.BaseCheck | str,
        target: _checks.TargetT,
        creds: _checks.CredsT,
        do_raise: bool = False,
        exc: type[Exception] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> bool:

        creds_dict: MutableMapping[str, Any]
        if isinstance(creds, context.RequestContext):
            creds_dict = self._map_context_attributes_into_creds(creds)
        elif isinstance(creds, MutableMapping):
            creds_dict = creds
        # NOTE(lbragstad): The oslo.context library exposes the ability to call
        # a method on RequestContext objects that converts attributes of the
        # context object to policy values. However, ``to_policy_values()``
        # doesn't actually return a dictionary, it's a subclass of
        # collections.abc.MutableMapping, which behaves like a dictionary but
        # doesn't pass the type check.
        elif not isinstance(creds, MutableMapping):
            msg = (
                f'Expected type oslo_context.context.RequestContext, dict, '
                f'or the output of '
                f'oslo_context.context.RequestContext.to_policy_values but '
                f'got {type(creds)} instead'
            )
            raise InvalidContextObject(msg)

        # NOTE(lbragstad): We unfortunately have to special case this
        # attribute. Originally when the system scope when into oslo.policy, we
        # checked for a key called 'system' in creds. The oslo.context library
        # uses `system_scope` instead, and the compatibility between
        # oslo.policy and oslo.context was an afterthought. We'll have to
        # support services who've been setting creds['system'], but we can do
        # that by making sure we populate it with what's in the context object
        # if it has a system_scope attribute.
        if creds_dict.get('system_scope'):
            creds_dict['system'] = creds_dict.get('system_scope')

        if LOG.isEnabledFor(logging.DEBUG):
            try:
                creds_msg = jsonutils.dumps(
                    strutils.mask_dict_password(creds_dict),
                    skipkeys=True,
                    sort_keys=True,
                )
            except Exception as e:
                creds_msg = f'cannot format data, exception: {e}'

            try:
                target_dict = strutils.mask_dict_password(target)
                target_msg = jsonutils.dumps(
                    target_dict, skipkeys=True, sort_keys=True
                )
            except Exception as e:
                target_msg = f'cannot format data, exception: {e}'

            LOG.debug(
                'enforce: rule=%s creds=%s target=%s',
                rule.__class__
                if isinstance(rule, _checks.BaseCheck)
                else f'"{rule}"',
                creds_msg,
                target_msg,
            )

        # Allow the rule to be a Check tree
        if isinstance(rule, _checks.BaseCheck):
            # If the thing we're given is a Check, we don't know the
            # name of the rule, so pass None for current_rule.
            scope_valid = self._enforce_scope(
                creds_dict, rule, do_raise=do_raise
            )
            if not scope_valid:
                return False
            result = _checks._check(
                rule=rule,
                target=target,
                creds=creds_dict,
                enforcer=self,
                current_rule=None,
            )
        elif not self.rules:
            # No rules to reference means we're going to fail closed
            result = False
        else:
            try:
                to_check = self.rules[rule]
            except KeyError:
                LOG.debug('Rule [%s] does not exist', rule)
                # If the rule doesn't exist, fail closed
                result = False
            else:
                # NOTE(moguimar): suppressing [B105:hardcoded_password_string]
                #                 as token_scope is not actually a hardcoded
                #                 token.

                registered_rule = self.registered_rules.get(rule)
                if registered_rule:
                    # FIXME(stephenfin): Is registered_rule a rule or check?
                    scope_valid = self._enforce_scope(
                        creds_dict, registered_rule, do_raise=do_raise
                    )
                    if not scope_valid:
                        return False
                result = _checks._check(
                    rule=to_check,
                    target=target,
                    creds=creds_dict,
                    enforcer=self,
                    current_rule=rule,
                )

        # If it is False, raise the exception if requested
        if do_raise and not result:
            if exc:
                raise exc(*args, **kwargs)

            raise PolicyNotAuthorized(rule, target, creds_dict)

        return result

    def _enforce_scope(
        self,
        creds: MutableMapping[str, Any],
        rule: '_checks.BaseCheck | RuleDefault',
        *,
        do_raise: bool,
    ) -> bool:
        if not rule.scope_types:
            return True

        # Check the scope of the operation against the possible scope
        # attributes provided in `creds`.
        if creds.get('system'):
            token_scope = 'system'  # noqa: S105
        elif creds.get('domain_id'):
            token_scope = 'domain'  # noqa: S105
        else:
            # If the token isn't system-scoped or domain-scoped then
            # we're dealing with a project-scoped token.
            token_scope = 'project'  # noqa: S105

        result = True
        if rule.scope_types and token_scope not in rule.scope_types:
            if do_raise:
                raise InvalidScope(rule, rule.scope_types, token_scope)
            result = False
        return result

    def _map_context_attributes_into_creds(
        self, ctx: context.RequestContext
    ) -> dict[str, Any]:
        creds = {}
        # port public context attributes into the creds dictionary so long as
        # the attribute isn't callable
        context_values = ctx.to_policy_values()
        for k, v in context_values.items():
            creds[k] = v

        return creds

    def register_default(self, default: 'RuleDefault') -> None:
        """Registers a RuleDefault.

        Adds a RuleDefault to the list of registered rules. Rules must be
        registered before using the Enforcer.authorize method.

        :param default: A RuleDefault object to register.
        """
        if default.name in self.registered_rules:
            raise DuplicatePolicyError(default.name)

        # NOTE Always make copy of registered rule because policy engine
        # update these rules in many places (one example is
        # self._handle_deprecated_rule() ). This will avoid any conflict
        # in rule object values when running tests in parallel.
        self.registered_rules[default.name] = copy.deepcopy(default)

    def register_defaults(self, defaults: Sequence['RuleDefault']) -> None:
        """Registers a list of RuleDefaults.

        Adds each RuleDefault to the list of registered rules. Rules must be
        registered before using the Enforcer.authorize method.

        :param default: A list of RuleDefault objects to register.
        """
        for default in defaults:
            self.register_default(default)

    def authorize(
        self,
        rule: str,
        target: _checks.TargetT,
        creds: _checks.CredsT,
        do_raise: bool = False,
        exc: type[Exception] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """A wrapper around 'enforce' that checks for policy registration.

        To ensure that a policy being checked has been registered this method
        should be used rather than enforce. By doing so a project can be sure
        that all of it's used policies are registered and therefore available
        for sample file generation.

        The parameters match the enforce method and a description of them can
        be found there.
        """
        if rule not in self.registered_rules:
            raise PolicyNotRegistered(rule)
        return self.enforce(
            rule, target, creds, do_raise, exc, *args, **kwargs
        )


class _BaseRule:
    def __init__(self, name: str, check_str: str):
        self._name = name
        self._check_str = check_str
        self._check = _parser.parse_rule(self.check_str)

    @property
    def name(self) -> str:
        return self._name

    @property
    def check_str(self) -> str:
        return self._check_str

    @property
    def check(self) -> _checks.BaseCheck:
        return self._check

    def __str__(self) -> str:
        return f'"{self.name}": "{self.check_str}"'


class RuleDefault(_BaseRule):
    """A class for holding policy definitions.

    It is required to supply a name and value at creation time. It is
    encouraged to also supply a description to assist operators.

    :param name: The name of the policy. This is used when referencing it
        from another rule or during policy enforcement.
    :param check_str: The policy. This is a string  defining a policy that
        conforms to the policy language outlined at the top of the file.
    :param description: A plain text description of the policy. This will be
        used to comment sample policy files for use by deployers.
    :param deprecated_rule: :class:`.DeprecatedRule`
    :param deprecated_for_removal: indicates whether the policy is planned for
        removal in a future release.
    :param deprecated_reason: indicates why this policy is planned for removal
        in a future release. Silently ignored if deprecated_for_removal is
        False.
    :param deprecated_since: indicates which release this policy was deprecated
        in. Accepts any string, though valid version strings are encouraged.
        Silently ignored if deprecated_for_removal is False.
    :param scope_types: A list containing the intended scopes of the operation
        being done.

    .. versionchanged:: 1.29
       Added *deprecated_rule* parameter.

    .. versionchanged:: 1.29
       Added *deprecated_for_removal* parameter.

    .. versionchanged:: 1.29
       Added *deprecated_reason* parameter.

    .. versionchanged:: 1.29
       Added *deprecated_since* parameter.

    .. versionchanged:: 1.31
       Added *scope_types* parameter.
    """

    def __init__(
        self,
        name: str,
        check_str: str,
        description: str | None = None,
        deprecated_rule: 'DeprecatedRule | None' = None,
        deprecated_for_removal: bool = False,
        deprecated_reason: str | None = None,
        deprecated_since: str | None = None,
        scope_types: list[str] | None = None,
    ) -> None:
        super().__init__(name, check_str)

        self._description = description
        self._deprecated_rule = copy.deepcopy(deprecated_rule) or None
        self._deprecated_for_removal = deprecated_for_removal
        self._deprecated_reason = deprecated_reason
        self._deprecated_since = deprecated_since

        if self.deprecated_rule:
            if not isinstance(self.deprecated_rule, DeprecatedRule):
                raise ValueError(
                    'deprecated_rule must be a DeprecatedRule object.'
                )

        # if this rule is being deprecated, we need to provide a deprecation
        # reason here, but if this rule is replacing another rule, then the
        # deprecation reason belongs on that other rule
        if deprecated_for_removal:
            if deprecated_reason is None or deprecated_since is None:
                raise ValueError(
                    f'{self.name} deprecated without deprecated_reason or '
                    'deprecated_since. Both must be supplied if deprecating a '
                    'policy'
                )
        elif deprecated_rule and (deprecated_reason or deprecated_since):
            warnings.warn(
                f'{name} should not configure deprecated_reason or '
                f'deprecated_since as these should be configured on the '
                f'DeprecatedRule indicated by deprecated_rule. '
                f'This will be an error in a future release',
                DeprecationWarning,
            )

        if scope_types:
            msg = 'scope_types must be a list of strings.'
            if not isinstance(scope_types, list):
                raise ValueError(msg)

            for scope_type in scope_types:
                if not isinstance(scope_type, str):
                    raise ValueError(msg)

                if scope_types.count(scope_type) > 1:
                    raise ValueError(
                        'scope_types must be a list of unique strings.'
                    )

        self.scope_types = scope_types

    @property
    def description(self) -> str | None:
        return self._description

    @property
    def deprecated_rule(self) -> 'DeprecatedRule | None':
        return self._deprecated_rule

    @property
    def deprecated_for_removal(self) -> bool:
        return self._deprecated_for_removal

    @property
    def deprecated_reason(self) -> str | None:
        return self._deprecated_reason

    @property
    def deprecated_since(self) -> str | None:
        return self._deprecated_since

    def __eq__(self, other: Any) -> bool:
        """Equality operator.

        All check objects have a stable string representation. It is used for
        comparison rather than check_str because multiple check_str's may parse
        to the same check object. For instance '' and '@' are equivalent and
        the parsed rule string representation for both is '@'.

        The description does not play a role in the meaning of the check so it
        is not considered for equality.
        """
        # Name should match, check should match, and class should be equivalent
        # or one should be a subclass of the other.
        if (
            self.name == other.name
            and str(self.check) == str(other.check)
            and (
                isinstance(self, other.__class__)
                or isinstance(other, self.__class__)
            )
        ):
            return True
        return False


class Operation(TypedDict):
    path: str
    method: str


OperationsT: TypeAlias = list[Operation]


class DocumentedRuleDefault(RuleDefault):
    """A class for holding policy-in-code policy objects definitions

    This class provides the same functionality as the RuleDefault class, but it
    also requires additional data about the policy rule being registered. This
    is necessary so that proper documentation can be rendered based on the
    attributes of this class. Eventually, all usage of RuleDefault should be
    converted to use DocumentedRuleDefault.

    :param operations: List of dicts containing each API URL and
        corresponding http request method.

        Example::

            operations = [
                {'path': '/foo', 'method': 'GET'},
                {'path': '/some', 'method': 'POST'},
            ]
    """

    _description: str

    def __init__(
        self,
        name: str,
        check_str: str,
        description: str,
        operations: OperationsT,
        deprecated_rule: 'DeprecatedRule | None' = None,
        deprecated_for_removal: bool = False,
        deprecated_reason: str | None = None,
        deprecated_since: str | None = None,
        scope_types: list[str] | None = None,
    ) -> None:
        super().__init__(
            name,
            check_str,
            description,
            deprecated_rule=deprecated_rule,
            deprecated_for_removal=deprecated_for_removal,
            deprecated_reason=deprecated_reason,
            deprecated_since=deprecated_since,
            scope_types=scope_types,
        )

        self._operations = operations

        if not self._description:
            raise InvalidRuleDefault('Description is required')

        if not isinstance(self._operations, list):
            raise InvalidRuleDefault('Operations must be a list')

        if not self._operations:
            raise InvalidRuleDefault('Operations list must not be empty')

        for op in self._operations:
            if 'path' not in op:
                raise InvalidRuleDefault('Operation must contain a path')
            if 'method' not in op:
                raise InvalidRuleDefault('Operation must contain a method')
            if len(op.keys()) > 2:
                raise InvalidRuleDefault('Operation contains > 2 keys')

    @property
    def description(self) -> str:
        return self._description

    @property
    def operations(self) -> OperationsT:
        return self._operations


class DeprecatedRule(_BaseRule):
    """Represents a Deprecated policy or rule.

    Here's how you can use it to change a policy's default role or rule. Assume
    the following policy exists in code::

        from oslo_policy import policy

        policy.DocumentedRuleDefault(
            name='foo:create_bar',
            check_str='role:fizz',
            description='Create a bar.',
            operations=[{'path': '/v1/bars', 'method': 'POST'}],
        )

    The next snippet will maintain the deprecated option, but allow
    ``foo:create_bar`` to default to ``role:bang`` instead of ``role:fizz``::

        deprecated_rule = policy.DeprecatedRule(
            name='foo:create_bar',
            check_str='role:fizz'
            deprecated_reason='role:bang is a better default',
            deprecated_since='N',
        )

        policy.DocumentedRuleDefault(
            name='foo:create_bar',
            check_str='role:bang',
            description='Create a bar.',
            operations=[{'path': '/v1/bars', 'method': 'POST'}],
            deprecated_rule=deprecated_rule,
        )

    DeprecatedRule can be used to change the policy name itself. Assume the
    following policy exists in code::

        from oslo_policy import policy

        policy.DocumentedRuleDefault(
            name='foo:post_bar',
            check_str='role:fizz',
            description='Create a bar.',
            operations=[{'path': '/v1/bars', 'method': 'POST'}],
        )

    For the sake of consistency, let's say we want to replace ``foo:post_bar``
    with ``foo:create_bar``, but keep the same ``check_str`` as the default. We
    can accomplish this by doing::

        deprecated_rule = policy.DeprecatedRule(
            name='foo:post_bar',
            check_str='role:fizz'
            deprecated_reason='foo:create_bar is more consistent',
            deprecated_since='N',
        )

        policy.DocumentedRuleDefault(
            name='foo:create_bar',
            check_str='role:fizz',
            description='Create a bar.',
            operations=[{'path': '/v1/bars', 'method': 'POST'}],
            deprecated_rule=deprecated_rule,
        )

    Finally, let's use DeprecatedRule to break a policy into more granular
    policies. Let's assume the following policy exists in code::

        policy.DocumentedRuleDefault(
            name='foo:bar',
            check_str='role:bazz',
            description='Create, read, update, or delete a bar.',
            operations=[
                {'path': '/v1/bars', 'method': 'POST'},
                {'path': '/v1/bars', 'method': 'GET'},
                {'path': '/v1/bars/{bar_id}', 'method': 'GET'},
                {'path': '/v1/bars/{bar_id}', 'method': 'PATCH'},
                {'path': '/v1/bars/{bar_id}', 'method': 'DELETE'},
            ],
        )

    Here we can see the same policy is used to protect multiple operations on
    bars. This prevents operators from being able to assign different roles to
    different actions that can be taken on bar. For example, what if an
    operator wanted to require a less restrictive role or rule to list bars but
    a more restrictive rule to delete them? The following will introduce a
    policy that helps achieve that and deprecate the original, overly-broad
    policy::

        deprecated_rule = policy.DeprecatedRule(
            name='foo:bar',
            check_str='role:bazz'
            deprecated_reason=(
                'foo:bar has been replaced by more granular policies'
            ),
            deprecated_since='N',
        )

        policy.DocumentedRuleDefault(
            name='foo:create_bar',
            check_str='role:bang',
            description='Create a bar.',
            operations=[{'path': '/v1/bars', 'method': 'POST'}],
            deprecated_rule=deprecated_rule,
        )
        policy.DocumentedRuleDefault(
            name='foo:list_bars',
            check_str='role:bazz',
            description='List bars.',
            operations=[{'path': '/v1/bars', 'method': 'GET'}],
            deprecated_rule=deprecated_rule,
        )
        policy.DocumentedRuleDefault(
            name='foo:get_bar',
            check_str='role:bazz',
            description='Get a bar.',
            operations=[{'path': '/v1/bars/{bar_id}', 'method': 'GET'}],
            deprecated_rule=deprecated_rule,
        )
        policy.DocumentedRuleDefault(
            name='foo:update_bar',
            check_str='role:bang',
            description='Update a bar.',
            operations=[{'path': '/v1/bars/{bar_id}', 'method': 'PATCH'}],
            deprecated_rule=deprecated_rule,
        )
        policy.DocumentedRuleDefault(
            name='foo:delete_bar',
            check_str='role:bang',
            description='Delete a bar.',
            operations=[{'path': '/v1/bars/{bar_id}', 'method': 'DELETE'}],
            deprecated_rule=deprecated_rule,
        )

    :param name: The name of the policy. This is used when referencing it
        from another rule or during policy enforcement.
    :param check_str: The policy. This is a string  defining a policy that
        conforms to the policy language outlined at the top of the file.
    :param deprecated_reason: indicates why this policy is planned for removal
        in a future release.
    :param deprecated_since: indicates which release this policy was deprecated
        in. Accepts any string, though valid version strings are encouraged.

    .. versionchanged:: 1.29
       Added *DeprecatedRule* object.

    .. versionchanged:: 3.4
       Added *deprecated_reason* parameter.

    .. versionchanged:: 3.4
       Added *deprecated_since* parameter.
    """

    def __init__(
        self,
        name: str,
        check_str: str,
        *,
        deprecated_reason: str | None = None,
        deprecated_since: str | None = None,
    ):
        super().__init__(name, check_str)

        self._deprecated_reason = deprecated_reason
        self._deprecated_since = deprecated_since

        if not deprecated_reason or not deprecated_since:
            warnings.warn(
                f'{name} deprecated without deprecated_reason or '
                f'deprecated_since. This will be an error in a future release',
                DeprecationWarning,
            )

    @property
    def deprecated_reason(self) -> str | None:
        return self._deprecated_reason

    @property
    def deprecated_since(self) -> str | None:
        return self._deprecated_since
