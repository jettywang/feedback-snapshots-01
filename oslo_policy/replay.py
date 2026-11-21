# Copyright (c) 2026 OpenStack Foundation.
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

"""Optional, minimal-evidence decision recording and replay.

This module answers an after-the-fact audit question ("why did the
policy engine take that decision yesterday?") without keeping the full
request payload.  A :class:`DecisionRecorder` observes a single
:meth:`Enforcer.enforce` call and persists only the evidence that is
useful inside a trusted environment:

* the policy rule text and a digest of the whole rule set in effect,
* digests (never the raw values) of the target and credentials,
* one trace node per evaluated leaf check, with its observed result,
* digests of the request/response exchanged with any remote
  (``http:``/``https:``) check.

A :class:`DecisionReplayer` then re-evaluates the recorded rule tree
against the *same* inputs (supplied from the trusted ticket archive) and
classifies every part of the decision as:

``reproduced``
    a deterministic check whose recomputed result matches the record,
``external``
    a remote check whose outcome cannot be recomputed offline and is
    only attested by digests,
``mismatch``
    something that no longer reproduces (rule or input drift).

The module never stores raw target/credentials values and never performs
a network call unless the caller explicitly selects the live mode.
"""

from __future__ import annotations

import hashlib
import hmac
import json as json_lib
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from oslo_policy import _checks
from oslo_policy import _parser

if TYPE_CHECKING:
    from oslo_policy.policy import Enforcer

# Version of the on-disk evidence format produced by this module.
RECORD_VERSION = '1.0'

# Replay verdicts.  Keep these stable: they are the contract consumed by
# audit tooling.
VERDICT_REPRODUCED = 'reproduced'
VERDICT_EXTERNAL = 'external'
VERDICT_MISMATCH = 'mismatch'
VERDICT_SKIPPED = 'skipped'
VERDICT_RULE_DRIFT = 'rule_drift'
VERDICT_INPUT_DRIFT = 'input_drift'
VERDICT_TAMPERED = 'tampered'

# Leaf check kinds whose result depends on a live remote system.  The
# shipped remote checks live in oslo_policy._external; third parties may
# register additional ones via mark_remote_kind().
_REMOTE_KINDS: set[str] = {'http', 'https'}


def mark_remote_kind(kind: str) -> None:
    """Register a check ``kind`` as depending on a live remote result.

    Services that ship their own remote check (registered through
    :func:`oslo_policy.policy.register`) call this so that the recorder
    treats those leaves as externally attested rather than replayable.
    """
    _REMOTE_KINDS.add(kind)


def _canonical_json(value: Any) -> bytes:
    """Stable byte representation used for all digests."""
    return json_lib.dumps(
        value, sort_keys=True, separators=(',', ':'), default=str
    ).encode('utf-8')


def digest(value: Any) -> str:
    """Return the SHA-256 hex digest of a canonicalized value."""
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _redact(
    mapping: Mapping[str, Any], allow: frozenset[str]
) -> dict[str, Any]:
    """Keep only allow-listed scalar keys; everything else is digested.

    The default allow list is empty, which means the recorded evidence
    contains no business values at all - only their digests.
    """
    safe: dict[str, Any] = {}
    for key, val in mapping.items():
        if key in allow and isinstance(val, str | int | float | bool):
            safe[key] = val
    return safe


@dataclass
class ExternalCall:
    """Digests of one remote check interaction (no bodies retained)."""

    node_id: str
    kind: str
    match: str
    url_template: str
    request_digest: str
    response_digest: str
    observed_result: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'node_id': self.node_id,
            'kind': self.kind,
            'match': self.match,
            'url_template': self.url_template,
            'request_digest': self.request_digest,
            'response_digest': self.response_digest,
            'observed_result': self.observed_result,
            'error': self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExternalCall:
        return cls(
            node_id=data['node_id'],
            kind=data['kind'],
            match=data['match'],
            url_template=data['url_template'],
            request_digest=data['request_digest'],
            response_digest=data['response_digest'],
            observed_result=data['observed_result'],
            error=data.get('error'),
        )


@dataclass
class TraceNode:
    """One evaluated leaf check and the result that was observed."""

    node_id: str
    kind: str
    match: str
    observed_result: bool
    remote: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            'node_id': self.node_id,
            'kind': self.kind,
            'match': self.match,
            'observed_result': self.observed_result,
            'remote': self.remote,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TraceNode:
        return cls(
            node_id=data['node_id'],
            kind=data['kind'],
            match=data['match'],
            observed_result=data['observed_result'],
            remote=data['remote'],
        )


@dataclass
class DecisionRecord:
    """Minimal, serializable evidence for a single decision.

    Raw target and credentials are intentionally absent.  Use
    :meth:`to_json` / :meth:`from_json` for persistence in the audit
    store.
    """

    record_version: str
    decision_id: str
    rule_name: str | None
    rule_text: str
    ruleset_digest: str
    target_digest: str
    creds_digest: str
    observed_decision: bool
    scope_result: bool
    trace: list[TraceNode]
    external_calls: list[ExternalCall]
    recorded_at: str
    input_preview: dict[str, Any] = field(default_factory=dict)
    seal: str | None = None

    def _sealed_payload(self) -> bytes:
        body = self.to_dict(seal=False)
        return _canonical_json(body)

    def seal_with(self, secret: bytes) -> None:
        """Attach an HMAC-SHA256 seal using a trusted-environment key."""
        self.seal = hmac.new(
            secret, self._sealed_payload(), hashlib.sha256
        ).hexdigest()

    def verify_seal(self, secret: bytes) -> bool:
        """Return True when the HMAC seal is present and valid."""
        if not self.seal:
            return False
        expected = hmac.new(
            secret, self._sealed_payload(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self.seal)

    def to_dict(self, seal: bool = True) -> dict[str, Any]:
        data = {
            'record_version': self.record_version,
            'decision_id': self.decision_id,
            'rule_name': self.rule_name,
            'rule_text': self.rule_text,
            'ruleset_digest': self.ruleset_digest,
            'target_digest': self.target_digest,
            'creds_digest': self.creds_digest,
            'observed_decision': self.observed_decision,
            'scope_result': self.scope_result,
            'trace': [node.to_dict() for node in self.trace],
            'external_calls': [call.to_dict() for call in self.external_calls],
            'recorded_at': self.recorded_at,
            'input_preview': self.input_preview,
        }
        if seal:
            data['seal'] = self.seal
        return data

    def to_json(self) -> str:
        return json_lib.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DecisionRecord:
        return cls(
            record_version=data['record_version'],
            decision_id=data['decision_id'],
            rule_name=data.get('rule_name'),
            rule_text=data['rule_text'],
            ruleset_digest=data['ruleset_digest'],
            target_digest=data['target_digest'],
            creds_digest=data['creds_digest'],
            observed_decision=data['observed_decision'],
            scope_result=data['scope_result'],
            trace=[TraceNode.from_dict(item) for item in data['trace']],
            external_calls=[
                ExternalCall.from_dict(item)
                for item in data.get('external_calls', [])
            ],
            recorded_at=data['recorded_at'],
            input_preview=dict(data.get('input_preview', {})),
            seal=data.get('seal'),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> DecisionRecord:
        return cls.from_dict(json_lib.loads(raw))


class _ObservedCheck(_checks.BaseCheck):
    """Wraps a leaf check to record its result without changing logic."""

    def __init__(
        self,
        inner: _checks.Check,
        node_id: str,
        recorder: DecisionRecorder,
    ) -> None:
        self.inner = inner
        self.node_id = node_id
        self.recorder = recorder
        self.scope_types = inner.scope_types

    def __str__(self) -> str:
        return str(self.inner)

    def __call__(
        self,
        target: _checks.TargetT,
        creds: MutableMapping[str, Any],
        enforcer: Any,
        current_rule: str | None = None,
    ) -> bool:
        remote = self.inner.kind in _REMOTE_KINDS
        external_call = None
        if remote:
            external_call = self.recorder._capture_remote(
                self.node_id,
                self.inner,
                target,
                creds,
                enforcer,
                current_rule,
            )
            result = external_call.observed_result
        else:
            result = _checks._check(
                rule=self.inner,
                target=target,
                creds=creds,
                enforcer=enforcer,
                current_rule=current_rule,
            )
        self.recorder._trace.append(
            TraceNode(
                node_id=self.node_id,
                kind=self.inner.kind,
                match=self.inner.match,
                observed_result=bool(result),
                remote=remote,
            )
        )
        if external_call is not None:
            self.recorder._external_calls.append(external_call)
        return result


def _instrument(
    node: _checks.BaseCheck,
    recorder: DecisionRecorder,
    prefix: str = 'n',
) -> tuple[_checks.BaseCheck, str]:
    """Return a recording copy of a check tree plus its structural id.

    Structural ids are paths through the tree, so a tree rebuilt later
    from the same rule text yields identical ids without any persisted
    node bookkeeping.
    """
    if isinstance(node, _checks.AndCheck):
        children = [
            _instrument(child, recorder, f'{prefix}.a{i}')[0]
            for i, child in enumerate(node.rules)
        ]
        return _checks.AndCheck(children), prefix
    if isinstance(node, _checks.OrCheck):
        children = [
            _instrument(child, recorder, f'{prefix}.o{i}')[0]
            for i, child in enumerate(node.rules)
        ]
        return _checks.OrCheck(children), prefix
    if isinstance(node, _checks.NotCheck):
        child, _ = _instrument(node.rule, recorder, f'{prefix}.not')
        # The parser only wraps leaf checks in NotCheck; the recursive
        # call preserves that leaf nature behind the BaseCheck type.
        return _checks.NotCheck(child), prefix  # type: ignore[arg-type]
    if isinstance(node, _checks.Check):
        node_id = f'{prefix}:{node.kind}:{node.match}'
        return _ObservedCheck(node, node_id, recorder), node_id
    # TrueCheck / FalseCheck singletons need no observation: their
    # result is fixed by the rule text itself.
    return node, prefix


class _RemoteCapture:
    """Single interception point for one remote check call.

    Installed as ``requests.post`` while one remote check runs. It
    delegates to the previously installed ``post`` (which may itself be
    a test double such as ``requests_mock`` or ``unittest.mock``) and
    retains only digests of the wire request and response.
    """

    def __init__(self, node_id: str, check: _checks.Check) -> None:
        self.node_id = node_id
        self.check = check
        self.url_template = f'{check.kind}:{check.match}'
        self.request_digest: str = digest(None)
        self.response_digest: str = digest(None)
        self.observed_result = False
        self.error: str | None = None
        self._previous_post: Callable[..., Any] | None = None

    def install(self) -> None:
        import requests

        self._previous_post = requests.post
        requests.post = self

    def restore(self) -> None:
        import requests

        if self._previous_post is not None:
            requests.post = self._previous_post
            self._previous_post = None

    def __call__(self, url: Any, **kwargs: Any) -> Any:
        request_view = {
            'url': url,
            'json': kwargs.get('json'),
            'data': kwargs.get('data'),
        }
        self.request_digest = digest(request_view)
        try:
            assert self._previous_post is not None
            response = self._previous_post(url, **kwargs)
        except Exception as exc:  # noqa: BLE001 - failure is evidence
            self.error = type(exc).__name__
            raise
        self.response_digest = digest(
            {'status': response.status_code, 'text': response.text}
        )
        self.observed_result = bool(
            response.text.lstrip('"').rstrip('"') == 'True'
        )
        return response


class _NormalizedEnforcer:
    """Enforcer view whose ``rules`` only contains parsed checks.

    Everything else is delegated to the wrapped enforcer. This keeps
    nested ``rule:`` look-ups working during recording/replay without
    mutating the caller's enforcer.
    """

    def __init__(
        self, enforcer: Any, rules: Mapping[str, _checks.BaseCheck]
    ) -> None:
        object.__setattr__(self, '_enforcer', enforcer)
        object.__setattr__(self, 'rules', dict(rules))

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, '_enforcer'), name)


class DecisionRecorder:
    """Observes one enforce call and builds a :class:`DecisionRecord`.

    The recorder is opt-in and self-contained: constructing one changes
    nothing until :meth:`record` is invoked, and nothing is written to
    disk by this class.
    """

    def __init__(
        self,
        decision_id: str,
        recorded_at: str,
        *,
        input_allowlist: Sequence[str] = (),
        secret: bytes | None = None,
    ) -> None:
        self.decision_id = decision_id
        self.recorded_at = recorded_at
        self.input_allowlist = frozenset(input_allowlist)
        self.secret = secret
        self._trace: list[TraceNode] = []
        self._external_calls: list[ExternalCall] = []

    def _capture_remote(
        self,
        node_id: str,
        check: _checks.Check,
        target: _checks.TargetT,
        creds: MutableMapping[str, Any],
        enforcer: Any,
        current_rule: str | None,
    ) -> ExternalCall:
        capture = _RemoteCapture(node_id, check)
        try:
            url = capture.url_template % target
        except Exception:  # noqa: BLE001 - malformed template is evidence
            url = capture.url_template
        capture.install()
        try:
            result = _checks._check(
                rule=check,
                target=target,
                creds=creds,
                enforcer=enforcer,
                current_rule=current_rule,
            )
        except Exception as exc:  # noqa: BLE001
            # Preserve the failure evidence, then propagate so the
            # recorder stays behaviourally identical to a raw enforce.
            self._external_calls.append(
                ExternalCall(
                    node_id=node_id,
                    kind=check.kind,
                    match=check.match,
                    url_template=url,
                    request_digest=capture.request_digest,
                    response_digest=capture.response_digest,
                    observed_result=False,
                    error=capture.error or type(exc).__name__,
                )
            )
            raise
        finally:
            capture.restore()
        return ExternalCall(
            node_id=node_id,
            kind=check.kind,
            match=check.match,
            url_template=url,
            request_digest=capture.request_digest,
            response_digest=capture.response_digest,
            observed_result=bool(result),
            error=capture.error,
        )

    def record(
        self,
        enforcer: Any,
        rule: _checks.BaseCheck | str,
        target: Mapping[str, Any],
        creds: MutableMapping[str, Any],
    ) -> tuple[bool, DecisionRecord]:
        """Run enforce under observation and return result plus evidence."""
        enforcer.load_rules()
        # Rules normally hold parsed BaseCheck objects (Rules.load,
        # RuleDefault); tolerate raw strings too so evidence is identical
        # regardless of how the caller populated the enforcer.
        normalized_rules = {
            name: (
                check
                if isinstance(check, _checks.BaseCheck)
                else _parser.parse_rule(check)
            )
            for name, check in enforcer.rules.items()
        }

        if isinstance(rule, _checks.BaseCheck):
            rule_name = None
            root = rule
            rule_text = str(rule)
        else:
            rule_name = rule
            if not normalized_rules:
                # Mirror Enforcer.enforce fail-closed behaviour.
                root = _checks.FalseCheck()
                rule_text = '!'
            else:
                try:
                    root = normalized_rules[rule]
                except KeyError:
                    # Unknown rule also fails closed in Enforcer.enforce.
                    root = _checks.FalseCheck()
                    rule_text = '!'
                else:
                    rule_text = str(root)

        ruleset_digest = digest(
            {name: str(check) for name, check in normalized_rules.items()}
        )

        instrumented, _ = _instrument(root, self)
        # Mirror Enforcer.enforce scope handling exactly: a named rule
        # is scoped by its registered default; a raw Check carries its
        # own scope_types.
        scope_rule = (
            enforcer.registered_rules.get(rule_name) if rule_name else root
        )
        if scope_rule is None:
            scope_rule = root
        view = _NormalizedEnforcer(enforcer, normalized_rules)
        scope_valid = enforcer._enforce_scope(
            creds, scope_rule, do_raise=False
        )
        if not scope_valid:
            observed = False
        else:
            observed = _checks._check(
                rule=instrumented,
                target=target,
                creds=creds,
                enforcer=cast('Enforcer', view),
                current_rule=rule_name,
            )

        record = DecisionRecord(
            record_version=RECORD_VERSION,
            decision_id=self.decision_id,
            rule_name=rule_name,
            rule_text=rule_text,
            ruleset_digest=ruleset_digest,
            target_digest=digest(target),
            creds_digest=digest(creds),
            observed_decision=bool(observed),
            scope_result=bool(scope_valid),
            trace=list(self._trace),
            external_calls=list(self._external_calls),
            recorded_at=self.recorded_at,
            input_preview={
                'target': _redact(target, self.input_allowlist),
                'creds': _redact(creds, self.input_allowlist),
            },
        )
        if self.secret is not None:
            record.seal_with(self.secret)
        return bool(observed), record


@dataclass
class LeafResult:
    """Replay outcome for one recorded leaf check."""

    node_id: str
    kind: str
    match: str
    remote: bool
    observed_result: bool
    recomputed_result: bool | None
    status: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'node_id': self.node_id,
            'kind': self.kind,
            'match': self.match,
            'remote': self.remote,
            'observed_result': self.observed_result,
            'recomputed_result': self.recomputed_result,
            'status': self.status,
            'detail': self.detail,
        }


@dataclass
class ReplayReport:
    """Structured answer separating the three evidence classes."""

    decision_id: str
    verdict: str
    observed_decision: bool
    recomputed_decision: bool | None
    seal_valid: bool | None
    inputs_match: bool
    ruleset_matches: bool
    leaves: list[LeafResult]
    external_calls: list[ExternalCall]
    reasons: list[str]

    @property
    def reproduced(self) -> list[LeafResult]:
        return [
            leaf for leaf in self.leaves if leaf.status == VERDICT_REPRODUCED
        ]

    @property
    def external(self) -> list[LeafResult]:
        return [
            leaf for leaf in self.leaves if leaf.status == VERDICT_EXTERNAL
        ]

    @property
    def mismatches(self) -> list[LeafResult]:
        return [
            leaf for leaf in self.leaves if leaf.status == VERDICT_MISMATCH
        ]

    @property
    def skipped(self) -> list[LeafResult]:
        return [leaf for leaf in self.leaves if leaf.status == VERDICT_SKIPPED]

    def to_dict(self) -> dict[str, Any]:
        leaf_dicts = [leaf.to_dict() for leaf in self.leaves]
        return {
            'decision_id': self.decision_id,
            'verdict': self.verdict,
            'observed_decision': self.observed_decision,
            'recomputed_decision': self.recomputed_decision,
            'seal_valid': self.seal_valid,
            'inputs_match': self.inputs_match,
            'ruleset_matches': self.ruleset_matches,
            'leaves': leaf_dicts,
            'external_calls': [call.to_dict() for call in self.external_calls],
            'reasons': self.reasons,
            # Explicit split requested by auditors: what was seen then,
            # what recomputes now, what cannot, and what short-circuiting
            # never evaluated.
            'seen_then': {
                'decision': self.observed_decision,
                'leaves': leaf_dicts,
                'external_calls': [
                    call.to_dict() for call in self.external_calls
                ],
            },
            'recomputable_now': [leaf.node_id for leaf in self.reproduced],
            'not_verifiable_offline': [leaf.node_id for leaf in self.external],
            'not_evaluated_then': [leaf.node_id for leaf in self.skipped],
        }


# A remote stand-in maps (check, target, creds, current_rule) to the
# boolean the remote service would return. It lets a trusted
# environment replay a live-dependent action without opening a socket,
# while still exercising the live code path.
RemoteProviderT = Callable[
    [_checks.Check, Mapping[str, Any], MutableMapping[str, Any], str | None],
    bool,
]


class DecisionReplayer:
    """Re-evaluates a :class:`DecisionRecord` inside a trusted env.

    Two modes are offered:

    ``offline`` (default)
        no network access; remote leaves are reported as
        ``external`` and their recorded outcomes are reused as
        attested inputs while the deterministic parts are recomputed.
    ``live``
        remote checks are invoked again through ``remote_provider``
        (or the real HTTP call when no provider is given); the new
        request/response digests are compared with the recorded ones.
    """

    def __init__(
        self,
        record: DecisionRecord,
        *,
        secret: bytes | None = None,
        mode: str = 'offline',
        remote_provider: RemoteProviderT | None = None,
    ) -> None:
        if mode not in ('offline', 'live'):
            raise ValueError("mode must be 'offline' or 'live'")
        self.record = record
        self.secret = secret
        self.mode = mode
        self.remote_provider = remote_provider
        self._trace_by_id = {node.node_id: node for node in record.trace}
        self._external_by_id = {
            call.node_id: call for call in record.external_calls
        }

    def replay(
        self,
        enforcer: Any,
        target: Mapping[str, Any],
        creds: MutableMapping[str, Any],
    ) -> ReplayReport:
        enforcer.load_rules()
        record = self.record
        reasons: list[str] = []

        seal_valid: bool | None = None
        if self.secret is not None:
            seal_valid = record.verify_seal(self.secret)
            if not seal_valid:
                reasons.append('HMAC seal verification failed')

        inputs_match = (
            digest(target) == record.target_digest
            and digest(creds) == record.creds_digest
        )
        if not inputs_match:
            reasons.append(
                'target/credentials digests differ from the recorded inputs'
            )

        normalized_rules = {
            name: (
                check
                if isinstance(check, _checks.BaseCheck)
                else _parser.parse_rule(check)
            )
            for name, check in enforcer.rules.items()
        }
        current_ruleset = digest(
            {name: str(check) for name, check in normalized_rules.items()}
        )
        ruleset_matches = current_ruleset == record.ruleset_digest
        if not ruleset_matches:
            reasons.append(
                'loaded rule set digest differs from the recorded one'
            )

        leaves: list[LeafResult] = []
        try:
            rebuilt = _parser.parse_rule(record.rule_text)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f'recorded rule text cannot be reparsed: {exc}'
            ) from exc

        view = _NormalizedEnforcer(enforcer, normalized_rules)
        recomputed_decision = self._evaluate(
            rebuilt,
            target,
            creds,
            view,
            record.rule_name,
            leaves,
        )

        verdict = self._verdict(
            leaves,
            inputs_match,
            ruleset_matches,
            seal_valid,
            recomputed_decision,
            reasons,
        )
        return ReplayReport(
            decision_id=record.decision_id,
            verdict=verdict,
            observed_decision=record.observed_decision,
            recomputed_decision=recomputed_decision,
            seal_valid=seal_valid,
            inputs_match=inputs_match,
            ruleset_matches=ruleset_matches,
            leaves=leaves,
            external_calls=list(record.external_calls),
            reasons=reasons,
        )

    def _evaluate(
        self,
        node: _checks.BaseCheck,
        target: Mapping[str, Any],
        creds: MutableMapping[str, Any],
        enforcer: Any,
        current_rule: str | None,
        leaves: list[LeafResult],
        prefix: str = 'n',
    ) -> bool:
        if isinstance(node, _checks.AndCheck):
            # Mirror AndCheck short-circuiting so leaves that were never
            # evaluated at record time are not force-replayed now.
            for i, child in enumerate(node.rules):
                if not self._evaluate(
                    child,
                    target,
                    creds,
                    enforcer,
                    current_rule,
                    leaves,
                    f'{prefix}.a{i}',
                ):
                    return False
            return True
        if isinstance(node, _checks.OrCheck):
            for i, child in enumerate(node.rules):
                if self._evaluate(
                    child,
                    target,
                    creds,
                    enforcer,
                    current_rule,
                    leaves,
                    f'{prefix}.o{i}',
                ):
                    return True
            return False
        if isinstance(node, _checks.NotCheck):
            return not self._evaluate(
                node.rule,
                target,
                creds,
                enforcer,
                current_rule,
                leaves,
                f'{prefix}.not',
            )
        if isinstance(node, _checks.TrueCheck):
            return True
        if isinstance(node, _checks.FalseCheck):
            return False
        if isinstance(node, _checks.Check):
            node_id = f'{prefix}:{node.kind}:{node.match}'
            return self._evaluate_leaf(
                node,
                node_id,
                target,
                creds,
                enforcer,
                current_rule,
                leaves,
            )
        # Unknown node type: fail closed and flag it.
        leaves.append(
            LeafResult(
                node_id=prefix,
                kind='?',
                match='?',
                remote=False,
                observed_result=False,
                recomputed_result=None,
                status=VERDICT_MISMATCH,
                detail='unrecognized check node during replay',
            )
        )
        return False

    def _evaluate_leaf(
        self,
        node: _checks.Check,
        node_id: str,
        target: Mapping[str, Any],
        creds: MutableMapping[str, Any],
        enforcer: Any,
        current_rule: str | None,
        leaves: list[LeafResult],
    ) -> bool:
        recorded = self._trace_by_id.get(node_id)
        if recorded is None:
            # The rebuilt tree reaches a leaf that was never evaluated
            # at record time. With matching rule text and inputs this
            # only happens when short-circuiting skipped it then but the
            # replayed prefixes now reach it; treat as skipped rather
            # than a false mismatch.
            leaves.append(
                LeafResult(
                    node_id=node_id,
                    kind=node.kind,
                    match=node.match,
                    remote=node.kind in _REMOTE_KINDS,
                    observed_result=False,
                    recomputed_result=None,
                    status=VERDICT_SKIPPED,
                    detail='not evaluated in the recorded decision '
                    '(short-circuited)',
                )
            )
            # Recompute the value so the surrounding And/Or semantics
            # stay faithful to the rule tree.
            return bool(
                _checks._check(
                    rule=node,
                    target=target,
                    creds=creds,
                    enforcer=enforcer,
                    current_rule=current_rule,
                )
            )

        is_remote = node.kind in _REMOTE_KINDS
        if is_remote and self.mode == 'offline':
            leaves.append(
                LeafResult(
                    node_id=node_id,
                    kind=node.kind,
                    match=node.match,
                    remote=True,
                    observed_result=recorded.observed_result,
                    recomputed_result=None,
                    status=VERDICT_EXTERNAL,
                    detail='remote result attested by digests only; '
                    'not recomputable offline',
                )
            )
            return recorded.observed_result

        if is_remote and self.mode == 'live':
            return self._evaluate_live_remote(
                node,
                node_id,
                target,
                creds,
                enforcer,
                current_rule,
                recorded,
                leaves,
            )

        recomputed = _checks._check(
            rule=node,
            target=target,
            creds=creds,
            enforcer=enforcer,
            current_rule=current_rule,
        )
        status = (
            VERDICT_REPRODUCED
            if bool(recomputed) == recorded.observed_result
            else VERDICT_MISMATCH
        )
        leaves.append(
            LeafResult(
                node_id=node_id,
                kind=node.kind,
                match=node.match,
                remote=False,
                observed_result=recorded.observed_result,
                recomputed_result=bool(recomputed),
                status=status,
            )
        )
        return bool(recomputed)

    def _evaluate_live_remote(
        self,
        node: _checks.Check,
        node_id: str,
        target: Mapping[str, Any],
        creds: MutableMapping[str, Any],
        enforcer: Any,
        current_rule: str | None,
        recorded: TraceNode,
        leaves: list[LeafResult],
    ) -> bool:
        recorded_call = self._external_by_id.get(node_id)
        if self.remote_provider is not None:
            fresh = self.remote_provider(node, target, creds, current_rule)
            detail = 're-invoked through injected remote provider'
        else:
            fresh = _checks._check(
                rule=node,
                target=target,
                creds=creds,
                enforcer=enforcer,
                current_rule=current_rule,
            )
            detail = 're-invoked over the network'

        status = (
            VERDICT_REPRODUCED
            if bool(fresh) == recorded.observed_result
            else VERDICT_MISMATCH
        )
        if recorded_call is not None and status == VERDICT_REPRODUCED:
            detail += (
                '; recorded request/response digests remain the only '
                'evidence of the original call'
            )
        leaves.append(
            LeafResult(
                node_id=node_id,
                kind=node.kind,
                match=node.match,
                remote=True,
                observed_result=recorded.observed_result,
                recomputed_result=bool(fresh),
                status=status,
                detail=detail,
            )
        )
        return bool(fresh)

    def _verdict(
        self,
        leaves: list[LeafResult],
        inputs_match: bool,
        ruleset_matches: bool,
        seal_valid: bool | None,
        recomputed_decision: bool | None,
        reasons: list[str],
    ) -> str:
        # A failed seal is the strongest signal: it proves the stored
        # evidence itself was modified, regardless of whether the same
        # inputs happen to reproduce a decision today.
        if seal_valid is False:
            return VERDICT_TAMPERED
        if not inputs_match:
            return VERDICT_INPUT_DRIFT
        if not ruleset_matches:
            return VERDICT_RULE_DRIFT
        if any(leaf.status == VERDICT_MISMATCH for leaf in leaves):
            return VERDICT_MISMATCH
        if any(leaf.status == VERDICT_EXTERNAL for leaf in leaves):
            # Deterministic parts reproduce; only remote attested parts
            # remain unverifiable offline.
            if (
                recomputed_decision is not None
                and recomputed_decision != self.record.observed_decision
            ):
                return VERDICT_MISMATCH
            return VERDICT_EXTERNAL
        if (
            recomputed_decision is not None
            and recomputed_decision != self.record.observed_decision
        ):
            reasons.append(
                'leaf results match but the combined decision differs'
            )
            return VERDICT_MISMATCH
        return VERDICT_REPRODUCED


def record_decision(
    enforcer: Any,
    rule: _checks.BaseCheck | str,
    target: Mapping[str, Any],
    creds: MutableMapping[str, Any],
    *,
    decision_id: str,
    recorded_at: str,
    input_allowlist: Sequence[str] = (),
    secret: bytes | None = None,
) -> tuple[bool, DecisionRecord]:
    """Convenience wrapper around :class:`DecisionRecorder`."""
    recorder = DecisionRecorder(
        decision_id=decision_id,
        recorded_at=recorded_at,
        input_allowlist=input_allowlist,
        secret=secret,
    )
    return recorder.record(enforcer, rule, target, creds)
