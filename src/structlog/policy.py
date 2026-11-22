# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Hot-swappable log-disclosure (redaction) policies.

This module provides a small contract for switching disclosure rules at
runtime -- e.g. when on-call has to urgently replace a redaction rule:

- `DisclosurePolicy` is an immutable, validated set of redaction rules.
- `PolicySwitch` holds the currently effective policy and swaps it
  atomically; a bad configuration is rejected and never displaces the
  effective one.
- `PolicyProcessor` is a structlog processor that snapshots the effective
  policy once per event, applies its rules, and stamps the event with the
  policy version, so every event records which configuration produced it.
- `effective_policy_version` lets an already-bound logger report which
  policy version its next events will use.

Because processors run lazily per event, loggers bound before a switch
follow the new rules for events emitted after it.
"""

from __future__ import annotations

import re
import threading

from dataclasses import dataclass, field
from typing import Any

from .typing import EventDict, WrappedLogger


__all__ = [
    "DisclosurePolicy",
    "InvalidPolicyError",
    "PolicyProcessor",
    "PolicySwitch",
    "RedactionRule",
    "effective_policy_version",
]


class InvalidPolicyError(ValueError):
    """
    A disclosure policy or rule failed validation.

    Raised before a `PolicySwitch` is mutated, so the previously effective
    policy stays in force.
    """


@dataclass(frozen=True)
class RedactionRule:
    """
    A single immutable disclosure rule for one event-dict key.

    If *pattern* is None, the whole value is replaced by *replacement*.
    Otherwise *pattern* must be a valid regular expression and only its
    matches within string values are replaced.
    """

    key: str
    pattern: str | None = None
    replacement: str = "***"
    _compiled: re.Pattern[str] | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise InvalidPolicyError(f"rule key must be a non-empty str: {self.key!r}")
        if not isinstance(self.replacement, str):
            raise InvalidPolicyError(
                f"replacement for {self.key!r} must be a str: {self.replacement!r}"
            )
        compiled = None
        if self.pattern is not None:
            if not isinstance(self.pattern, str):
                raise InvalidPolicyError(
                    f"pattern for {self.key!r} must be a str or None: {self.pattern!r}"
                )
            try:
                compiled = re.compile(self.pattern)
            except re.error as e:
                raise InvalidPolicyError(
                    f"invalid pattern for {self.key!r}: {e}"
                ) from None
        object.__setattr__(self, "_compiled", compiled)

    def apply(self, value: Any) -> Any:
        """
        Return *value* with this rule applied.
        """
        if self._compiled is None:
            return self.replacement
        if isinstance(value, str):
            return self._compiled.sub(self.replacement, value)
        return value


@dataclass(frozen=True)
class DisclosurePolicy:
    """
    An immutable, validated set of disclosure rules identified by *version*.
    """

    version: str
    rules: tuple[RedactionRule, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not self.version:
            raise InvalidPolicyError(
                f"policy version must be a non-empty str: {self.version!r}"
            )
        rules = tuple(self.rules)
        for rule in rules:
            if not isinstance(rule, RedactionRule):
                raise InvalidPolicyError(f"not a RedactionRule: {rule!r}")
        keys = [rule.key for rule in rules]
        if len(keys) != len(set(keys)):
            raise InvalidPolicyError(f"duplicate rule keys: {sorted(keys)!r}")
        object.__setattr__(self, "rules", rules)

    @classmethod
    def from_config(cls, version: str, config: Any) -> DisclosurePolicy:
        """
        Build and validate a policy from a raw config mapping of
        ``{key: rule}`` where *rule* is None (mask whole value), a regex
        str, or a mapping with ``pattern`` / ``replacement`` entries.

        Raises:
            InvalidPolicyError: If anything in the config is invalid.
        """
        if not isinstance(config, dict):
            raise InvalidPolicyError(f"policy config must be a mapping: {config!r}")
        rules = []
        for key, spec in config.items():
            if spec is None:
                rules.append(RedactionRule(key=key))
            elif isinstance(spec, str):
                rules.append(RedactionRule(key=key, pattern=spec))
            elif isinstance(spec, dict):
                unknown = set(spec) - {"pattern", "replacement"}
                if unknown:
                    raise InvalidPolicyError(
                        f"unknown rule options for {key!r}: {sorted(unknown)!r}"
                    )
                rules.append(
                    RedactionRule(
                        key=key,
                        pattern=spec.get("pattern"),
                        replacement=spec.get("replacement", "***"),
                    )
                )
            else:
                raise InvalidPolicyError(f"invalid rule for {key!r}: {spec!r}")
        return cls(version=version, rules=tuple(rules))

    def apply(self, event_dict: EventDict) -> EventDict:
        """
        Apply all rules to *event_dict* in place and return it.
        """
        for rule in self.rules:
            if rule.key in event_dict:
                event_dict[rule.key] = rule.apply(event_dict[rule.key])
        return event_dict


class PolicySwitch:
    """
    Holds the effective `DisclosurePolicy` and swaps it atomically.

    A policy is fully validated before it becomes effective, so a bad
    configuration can never displace the working one.
    """

    def __init__(self, initial: DisclosurePolicy) -> None:
        if not isinstance(initial, DisclosurePolicy):
            raise InvalidPolicyError(f"not a DisclosurePolicy: {initial!r}")
        self._lock = threading.Lock()
        self._current = initial

    def current(self) -> DisclosurePolicy:
        """
        Return the policy that is effective for new events right now.
        """
        with self._lock:
            return self._current

    @property
    def effective_version(self) -> str:
        """
        The version of the policy effective for new events.
        """
        return self.current().version

    def activate(self, policy: DisclosurePolicy) -> str:
        """
        Validate *policy* and make it effective for all subsequent events.

        Returns:
            The version that is now effective.

        Raises:
            InvalidPolicyError: If *policy* is not a valid
                `DisclosurePolicy`; the previous policy stays effective.
        """
        if not isinstance(policy, DisclosurePolicy):
            raise InvalidPolicyError(f"not a DisclosurePolicy: {policy!r}")
        with self._lock:
            self._current = policy
        return policy.version

    def processor(self, version_key: str = "policy_version") -> PolicyProcessor:
        """
        Return a `PolicyProcessor` that follows this switch.
        """
        return PolicyProcessor(self, version_key=version_key)


class PolicyProcessor:
    """
    A structlog processor that redacts events using the policy effective at
    event time and stamps each event with that policy's version.

    The policy is snapshotted once per event, so a single event always
    reflects exactly one configuration, even under concurrent switches.
    """

    def __init__(self, switch: PolicySwitch, version_key: str = "policy_version") -> None:
        self._switch = switch
        self._version_key = version_key

    @property
    def effective_version(self) -> str:
        """
        The policy version the next processed event will use.
        """
        return self._switch.effective_version

    def __call__(
        self, logger: WrappedLogger, method_name: str, event_dict: EventDict
    ) -> EventDict:
        policy = self._switch.current()
        policy.apply(event_dict)
        event_dict[self._version_key] = policy.version
        return event_dict


def effective_policy_version(logger: Any) -> str:
    """
    Return the policy version that *logger*'s next events will use.

    Works for any bound logger whose processor chain contains a
    `PolicyProcessor`.

    Raises:
        TypeError: If *logger* has no `PolicyProcessor` in its chain.
    """
    bind = getattr(logger, "bind", None)
    if bind is not None:
        logger = bind()
    for processor in getattr(logger, "_processors", None) or ():
        if isinstance(processor, PolicyProcessor):
            return processor.effective_version
    raise TypeError(f"{logger!r} has no PolicyProcessor in its processor chain")
