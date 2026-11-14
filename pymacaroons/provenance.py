from __future__ import unicode_literals

import binascii
from base64 import standard_b64encode

try:
    from hmac import compare_digest as constant_time_compare
except ImportError:
    from pymacaroons.utils import equals as constant_time_compare

from pymacaroons.macaroon import Macaroon
from pymacaroons.utils import (
    convert_to_bytes,
    convert_to_string,
    sign_first_party_caveat,
    sign_third_party_caveat,
)


STATUS_VALID_DESCENDANT = 'valid_descendant'
STATUS_UNCHANGED_PARENT = 'unchanged_parent'
STATUS_PREFIX_MISMATCH = 'prefix_mismatch'
STATUS_PSEUDO_DESCENDANT = 'pseudo_descendant'
STATUS_DIFFERENT_BRANCH = 'different_branch'
STATUS_INVALID_SIGNATURE = 'invalid_signature'
STATUS_FOREIGN_TOKEN = 'foreign_token'
STATUS_REQUEST_BOUND_DISCHARGE = 'request_bound_discharge'
STATUS_DISCHARGE_BINDING_UNVERIFIED = 'discharge_binding_unverified'
STATUS_INVALID_DISCHARGE_BINDING = 'invalid_discharge_binding'
STATUS_MALFORMED_TOKEN = 'malformed_token'


class Candidate(object):
    '''A token presented as a possible descendant of the trusted parent.

    ``kind`` may be ``auto`` (the default), ``child``, or ``discharge``.
    Discharges are always reported separately from ordinary child tokens.

    For a discharge, ``unbound`` may contain the original unbound discharge.
    It is used only to check that a request-bound copy is bound to the
    supplied parent; it is never treated as a child token.
    '''

    def __init__(self, macaroon, label=None, kind='auto', unbound=None):
        if kind not in ('auto', 'child', 'discharge'):
            raise ValueError(
                'kind must be one of auto, child or discharge'
            )
        self.macaroon = macaroon
        self.label = label
        self.kind = kind
        self.unbound = unbound


class ProvenanceReport(object):
    '''The result of checking one candidate against the trusted parent.'''

    def __init__(self,
                 label,
                 status,
                 reason,
                 anchor,
                 candidate,
                 common_prefix_length=0,
                 caveat_comparison=None,
                 appended_caveats=None,
                 proven_chain=None,
                 prefix_issue=None,
                 location_findings=None,
                 conditions_requiring_context=None,
                 discharge=None,
                 diagnostics=None):
        self.label = label
        self.status = status
        self.reason = reason
        self.anchor = anchor
        self.candidate = candidate
        self.common_prefix_length = common_prefix_length
        self.caveat_comparison = caveat_comparison or []
        self.appended_caveats = appended_caveats or []
        self.proven_chain = proven_chain or {
            'proven': False,
            'steps': [],
        }
        self.prefix_issue = prefix_issue
        self.location_findings = location_findings or []
        self.conditions_requiring_context = (
            conditions_requiring_context or []
        )
        self.discharge = discharge
        self.diagnostics = diagnostics or []

    @property
    def is_valid_attenuation(self):
        return self.status == STATUS_VALID_DESCENDANT

    @property
    def is_parent(self):
        return self.status == STATUS_UNCHANGED_PARENT

    @property
    def is_discharge(self):
        return self.status in (
            STATUS_REQUEST_BOUND_DISCHARGE,
            STATUS_DISCHARGE_BINDING_UNVERIFIED,
            STATUS_INVALID_DISCHARGE_BINDING,
        )

    @property
    def is_request_bound(self):
        return self.status == STATUS_REQUEST_BOUND_DISCHARGE

    @property
    def has_unsigned_location_changes(self):
        return any(
            finding.get('scope') in ('macaroon', 'caveat')
            and finding.get('from') != finding.get('to')
            for finding in self.location_findings
        )

    def to_dict(self):
        return {
            'label': self.label,
            'status': self.status,
            'reason': self.reason,
            'is_valid_attenuation': self.is_valid_attenuation,
            'is_parent': self.is_parent,
            'is_discharge': self.is_discharge,
            'is_request_bound': self.is_request_bound,
            'has_unsigned_location_changes': (
                self.has_unsigned_location_changes
            ),
            'anchor': self.anchor,
            'candidate': self.candidate,
            'common_prefix_length': self.common_prefix_length,
            'caveat_comparison': self.caveat_comparison,
            'appended_caveats': self.appended_caveats,
            'proven_chain': self.proven_chain,
            'prefix_issue': self.prefix_issue,
            'location_findings': self.location_findings,
            'conditions_requiring_context': (
                self.conditions_requiring_context
            ),
            'discharge': self.discharge,
            'diagnostics': self.diagnostics,
        }

    def explain(self):
        lines = [
            '{0}: {1}'.format(self.label or 'candidate', self.status),
        ]
        if self.reason:
            lines.append('  reason: {0}'.format(self.reason))
        lines.append(
            '  anchor: identifier={0!r} signature={1} caveats={2} '
            '(caller-supplied, assumed signature-verified)'.format(
                self.anchor['identifier'],
                self.anchor['signature'],
                self.anchor['caveat_count'],
            )
        )

        if self.proven_chain.get('proven'):
            steps = self.proven_chain.get('steps') or []
            if steps:
                rendered = ', '.join(
                    '[{0}] {1} {2}'.format(
                        step['index'],
                        step['type'],
                        step['caveat_id'],
                    )
                    for step in steps
                )
                lines.append(
                    '  proven: parent caveat prefix ({0} caveat(s)) is '
                    'unchanged; appended update chain: {1}; '
                    'final signature {2}'.format(
                        len(self.anchor.get('caveats', [])),
                        rendered,
                        self.proven_chain['final_signature'],
                    )
                )
            else:
                lines.append(
                    '  proven: candidate is the supplied parent itself; '
                    'no appended caveats'
                )
        else:
            lines.append(
                '  proven: no append-only chain from the supplied parent'
            )
            if self.prefix_issue:
                lines.append(
                    '  prefix: {0} at index {1} (evidence: {2})'.format(
                        self.prefix_issue['kind'],
                        self.prefix_issue['index'],
                        self.prefix_issue.get('evidence', 'none'),
                    )
                )

        chain = self.proven_chain
        if (
            not chain.get('proven')
            and chain.get('post_prefix_signature_matches')
        ):
            lines.append(
                '  diagnostic: post-prefix replay from the parent '
                'signature matches, but the altered parent prefix is not '
                'covered; final replay signature {0}'.format(
                    chain.get('final_signature')
                )
            )
        if chain.get('unproven_steps'):
            lines.append(
                '  diagnostic: {0} appended step(s) were replayed from '
                'the parent signature but did not reproduce the candidate '
                'signature'.format(len(chain['unproven_steps']))
            )

        if self.discharge is not None:
            lines.append(
                '  discharge: binding_verified={0}; {1}'.format(
                    self.discharge['binding_verified'],
                    self.discharge['reason'],
                )
            )

        pending = [
            condition for condition in self.conditions_requiring_context
            if condition['status'] == 'pending'
        ]
        if pending:
            lines.append(
                '  request context still required for {0} condition(s):'
                .format(len(pending))
            )
            for condition in pending:
                if condition['kind'] == 'first_party':
                    lines.append(
                        '    - [{0}] first_party {1!r}'.format(
                            condition['source'],
                            condition['predicate'],
                        )
                    )
                else:
                    lines.append(
                        '    - [{0}] third_party {1!r} at {2!r} '
                        '(location is unsigned)'.format(
                            condition['source'],
                            condition['caveat_id'],
                            condition.get('location'),
                        )
                    )

        for finding in self.location_findings:
            lines.append(
                '  unsigned location finding: {0}'.format(
                    finding['reason']
                )
            )
        for diagnostic in self.diagnostics:
            lines.append('  diagnostic: {0}'.format(diagnostic))
        return '\n'.join(lines)


class ProvenanceVerifier(object):
    '''Verify append-only attenuation from an authenticated parent object.

    The verifier never receives the root key.  The supplied ``parent`` is
    the trust anchor and its signature must already have been verified by
    the caller.  Candidates are checked by comparing the parent caveat
    prefix exactly and replaying signed caveat updates from the parent
    signature.

    ``satisfied_conditions`` may contain exact first-party predicates that
    the caller has already evaluated against the request.  It affects only
    reporting: provenance verification never claims that a business
    condition was met.
    '''

    def __init__(self, parent, satisfied_conditions=None):
        if not isinstance(parent, Macaroon):
            raise TypeError('parent must be a Macaroon')
        if not parent.identifier_bytes:
            raise ValueError('parent must have a non-empty identifier')
        parent_signature = _signature_hex(parent)
        if parent_signature is None:
            raise ValueError(
                'parent must carry a 32-byte hexadecimal signature'
            )
        self.parent = parent
        self.parent_signature = parent_signature
        self.satisfied_conditions = set(
            convert_to_bytes(condition)
            for condition in (satisfied_conditions or [])
        )
        self._parent_third_party_ids = set(
            caveat.caveat_id_bytes
            for caveat in parent.third_party_caveats()
        )

    def verify(self, candidate, label=None, kind='auto', unbound=None):
        if isinstance(candidate, Candidate):
            item = candidate
        else:
            item = Candidate(
                candidate,
                label=label,
                kind=kind,
                unbound=unbound,
            )

        if not isinstance(item.macaroon, Macaroon):
            raise TypeError('candidate must be a Macaroon')
        label = item.label or 'candidate'
        token = item.macaroon
        anchor = self._anchor()
        token_info = _token_info(token)

        if not token.identifier_bytes:
            return self._report(
                label,
                STATUS_MALFORMED_TOKEN,
                'candidate has no identifier',
                anchor,
                token_info,
                item,
            )
        candidate_signature = _signature_hex(token)
        if candidate_signature is None:
            return self._report(
                label,
                STATUS_MALFORMED_TOKEN,
                'candidate does not carry a 32-byte hexadecimal signature',
                anchor,
                token_info,
                item,
            )

        looks_like_discharge = (
            token.identifier_bytes in self._parent_third_party_ids
        )
        if item.kind == 'discharge' or looks_like_discharge:
            return self._verify_discharge(
                label, item, anchor, token_info, candidate_signature,
                looks_like_discharge,
            )

        if token.identifier_bytes != self.parent.identifier_bytes:
            conditions = self._conditions(token, source='token')
            return self._report(
                label,
                STATUS_FOREIGN_TOKEN,
                'candidate identifier does not match the authenticated '
                'parent identifier; no lineage can be proven',
                anchor,
                token_info,
                item,
                conditions=conditions,
            )

        (
            comparison,
            common_prefix,
            appended,
            prefix_issue,
        ) = self._compare_caveats(token)

        location_findings = self._location_findings(
            token, common_prefix, compare_root=True
        )
        conditions = self._conditions(
            token,
            parent_caveats=self.parent.caveats,
        )
        # Replay the caveat updates that follow the authenticated parent
        # prefix.  This is also useful for diagnosing a prefix mismatch:
        # a signature that is derivable from the parent over appended
        # caveats proves an attempted alteration of an old condition.
        chain = self._replay_chain(token, candidate_signature)

        if prefix_issue is not None:
            kind = prefix_issue['kind']
            structural = kind in (
                'parent_caveats_removed',
                'parent_caveats_reordered',
                'parent_caveats_reordered_or_removed',
            )
            same_signature = constant_time_compare(
                convert_to_bytes(candidate_signature),
                convert_to_bytes(self.parent_signature),
            )
            if same_signature or chain['proven']:
                status = STATUS_PSEUDO_DESCENDANT
                if same_signature:
                    evidence = 'signature_identical_to_parent'
                    detail = (
                        'reuses the authenticated parent signature, so '
                        'the altered prefix was never signed'
                    )
                else:
                    evidence = 'signature_derived_from_parent'
                    detail = (
                        'the post-prefix chain is derivable from the '
                        'authenticated parent signature, so the altered '
                        'old condition is outside the proven append chain'
                    )
                reason = (
                    'candidate altered an existing parent condition '
                    '({0} at index {1}) and {2}; this is a pseudo '
                    'descendant, not valid attenuation'.format(
                        kind,
                        prefix_issue['index'],
                        detail,
                    )
                )
                prefix_issue['evidence'] = evidence
            elif structural:
                status = STATUS_PREFIX_MISMATCH
                reason = (
                    'candidate moves or removes parent caveats relative '
                    'to the authenticated parent (detected at index '
                    '{0}); deleting or reordering existing conditions '
                    'cannot be produced by append-only attenuation. The '
                    'candidate signature is not derivable from the '
                    'parent, so it cannot be accepted as any descendant '
                    'of this parent.'.format(prefix_issue['index'])
                )
                prefix_issue['evidence'] = (
                    'prefix_is_a_subsequence_or_permutation'
                )
            else:
                status = STATUS_DIFFERENT_BRANCH
                reason = (
                    'candidate shares the root identifier but its caveat '
                    'prefix differs from the supplied authenticated '
                    'parent ({0} at index {1}) and no chain from that '
                    'parent signature can produce it; it is not a '
                    'descendant of this parent. It may be a same-root '
                    'sibling branch, but that cannot be proven without an '
                    'authenticated ancestor or root object.'.format(
                        kind,
                        prefix_issue['index'],
                    )
                )
                prefix_issue['evidence'] = (
                    'no_parent_derived_chain'
                )
            lineage = dict(chain)
            lineage['post_prefix_signature_matches'] = chain['proven']
            lineage['proven'] = False
            lineage['steps'] = []
            return self._report(
                label,
                status,
                reason,
                anchor,
                token_info,
                item,
                common_prefix_length=common_prefix,
                comparison=comparison,
                appended=appended,
                chain=lineage,
                prefix_issue=prefix_issue,
                location_findings=location_findings,
                conditions=conditions,
            )

        if not chain['proven']:
            return self._report(
                label,
                STATUS_INVALID_SIGNATURE,
                'the caveat prefix is unchanged, but the candidate '
                'signature does not match the signature derived from the '
                'authenticated parent signature',
                anchor,
                token_info,
                item,
                common_prefix_length=common_prefix,
                comparison=comparison,
                appended=appended,
                chain=chain,
                location_findings=location_findings,
                conditions=conditions,
            )

        if not appended:
            status = STATUS_UNCHANGED_PARENT
            reason = (
                'candidate is the supplied authenticated parent; it adds '
                'no caveats and is not a new attenuated token'
            )
        else:
            status = STATUS_VALID_DESCENDANT
            reason = (
                'parent caveat prefix is preserved exactly and every '
                'appended first-party/third-party caveat is signed by the '
                'chain derived from the authenticated parent signature'
            )

        return self._report(
            label,
            status,
            reason,
            anchor,
            token_info,
            item,
            common_prefix_length=common_prefix,
            comparison=comparison,
            appended=appended,
            chain=chain,
            location_findings=location_findings,
            conditions=conditions,
        )

    def verify_all(self, candidates):
        return [self.verify(candidate) for candidate in candidates]

    def _verify_discharge(self,
                          label,
                          item,
                          anchor,
                          token_info,
                          candidate_signature,
                          looks_like_discharge):
        token = item.macaroon
        diagnostics = []
        if not looks_like_discharge:
            diagnostics.append(
                'discharge identifier does not match a third-party caveat '
                'identifier in the supplied parent'
            )
        if item.kind == 'child' and looks_like_discharge:
            diagnostics.append(
                'declared as a child, but its identifier matches a '
                'third-party caveat in the parent; kept separate as a '
                'discharge'
            )

        conditions = self._conditions(token, source='discharge')
        location_findings = self._location_findings(
            token, common_prefix=None, compare_root=False
        )
        binding = self._check_request_binding(item, candidate_signature)

        if binding['binding_verified']:
            status = STATUS_REQUEST_BOUND_DISCHARGE
            reason = (
                'token is a discharge macaroon request-bound to the '
                'supplied parent, not an ordinary attenuated child'
            )
        elif binding['checked']:
            status = STATUS_INVALID_DISCHARGE_BINDING
            reason = (
                'discharge binding does not match the supplied parent; '
                'it is not an ordinary child and cannot be accepted as a '
                'request-bound discharge for this parent'
            )
        else:
            status = STATUS_DISCHARGE_BINDING_UNVERIFIED
            reason = (
                'token looks like a discharge macaroon and is kept '
                'separate from child tokens; request binding cannot be '
                'proven without its unbound original'
            )

        return self._report(
            label,
            status,
            reason,
            anchor,
            token_info,
            item,
            location_findings=location_findings,
            conditions=conditions,
            discharge=binding,
            diagnostics=diagnostics,
        )

    def _check_request_binding(self, item, candidate_signature):
        if item.unbound is None:
            return {
                'checked': False,
                'binding_verified': False,
                'bound_to_parent_signature': self.parent_signature,
                'reason': (
                    'unbound discharge not supplied; binding cannot be '
                    'checked'
                ),
            }
        if not isinstance(item.unbound, Macaroon):
            raise TypeError('unbound must be a Macaroon')

        try:
            expected = self.parent.prepare_for_request(item.unbound)
            expected_signature = _signature_hex(expected)
        except Exception as exc:
            return {
                'checked': False,
                'binding_verified': False,
                'bound_to_parent_signature': self.parent_signature,
                'reason': 'could not compute the bound signature: {0}'
                          .format(exc),
            }

        caveats_match = (
            _caveat_fingerprints(item.macaroon)
            == _caveat_fingerprints(item.unbound)
        )
        identifiers_match = (
            item.macaroon.identifier_bytes == item.unbound.identifier_bytes
        )
        verified = (
            expected_signature is not None
            and caveats_match
            and identifiers_match
            and constant_time_compare(
                convert_to_bytes(candidate_signature),
                convert_to_bytes(expected_signature),
            )
        )
        binding = {
            'checked': True,
            'binding_verified': verified,
            'bound_to_parent_signature': self.parent_signature,
            'expected_signature': expected_signature,
            'actual_signature': candidate_signature,
            'reason': (
                'signature matches the hash binding over the parent '
                'signature and the unbound discharge signature'
                if verified else
                'candidate signature is not the request binding of the '
                'supplied unbound discharge to this parent'
            ),
        }
        if expected_signature is None:
            binding['reason'] = (
                'the unbound discharge does not carry a usable '
                'hexadecimal signature'
            )
        elif not identifiers_match:
            binding['reason'] = (
                'candidate identifier differs from the supplied unbound '
                'discharge; it is not that bound discharge'
            )
        elif not caveats_match:
            binding['reason'] = (
                'candidate caveats differ from the supplied unbound '
                'discharge; it is not that bound discharge'
            )
        return binding

    def _compare_caveats(self, token):
        parent_caveats = self.parent.caveats
        candidate_caveats = token.caveats
        comparison = []
        common_prefix = 0
        first_divergence = None

        # Compare the candidate's whole caveat list against the parent
        # list so moves and deletions are visible even when the candidate
        # happens to end with extra caveats.
        length = max(len(parent_caveats), len(candidate_caveats))
        for index in range(length):
            if index < len(parent_caveats) and index < len(candidate_caveats):
                parent_caveat = parent_caveats[index]
                candidate_caveat = candidate_caveats[index]
                same = (
                    _caveat_fingerprint(parent_caveat)
                    == _caveat_fingerprint(candidate_caveat)
                )
                relation = 'same' if same else 'changed'
                if same and first_divergence is None:
                    common_prefix += 1
                elif not same and first_divergence is None:
                    first_divergence = index
                entry = _comparison_entry(
                    index, relation, parent_caveat, candidate_caveat
                )
            elif index < len(parent_caveats):
                entry = _comparison_entry(
                    index, 'missing', parent_caveats[index], None
                )
                if first_divergence is None:
                    first_divergence = index
            else:
                entry = _comparison_entry(
                    index, 'appended', None, candidate_caveats[index]
                )
            comparison.append(entry)

        appended = []
        if (
            len(candidate_caveats) > len(parent_caveats)
            and first_divergence is not None
        ):
            for offset, caveat in enumerate(
                    candidate_caveats[len(parent_caveats):]):
                info = _caveat_info(caveat)
                info['index'] = len(parent_caveats) + offset
                appended.append(info)
        if first_divergence is None:
            for offset, caveat in enumerate(
                    candidate_caveats[len(parent_caveats):]):
                info = _caveat_info(caveat)
                info['index'] = len(parent_caveats) + offset
                appended.append(info)

        prefix_issue = None
        if first_divergence is not None:
            prefix_issue = {
                'index': first_divergence,
                'kind': _prefix_issue_kind(
                    parent_caveats, candidate_caveats, first_divergence
                ),
                'evidence': 'pending',
                'parent_caveat': (
                    _caveat_info(parent_caveats[first_divergence])
                    if first_divergence < len(parent_caveats) else None
                ),
                'candidate_caveat': (
                    _caveat_info(candidate_caveats[first_divergence])
                    if first_divergence < len(candidate_caveats) else None
                ),
            }

        return comparison, common_prefix, appended, prefix_issue

    def _replay_chain(self, token, candidate_signature):
        steps = []
        signature = binascii.unhexlify(self.parent_signature)
        for offset, caveat in enumerate(
                token.caveats[len(self.parent.caveats):]):
            index = len(self.parent.caveats) + offset
            before = binascii.hexlify(signature).decode('ascii')
            if caveat.first_party():
                next_signature = sign_first_party_caveat(
                    signature, caveat.caveat_id_bytes
                )
                caveat_type = 'first_party'
            else:
                next_signature = sign_third_party_caveat(
                    signature,
                    caveat.verification_key_id,
                    caveat.caveat_id_bytes,
                )
                caveat_type = 'third_party'
            signature = binascii.unhexlify(next_signature)
            after = binascii.hexlify(signature).decode('ascii')
            steps.append({
                'index': index,
                'type': caveat_type,
                'caveat_id': _bytes_repr(caveat.caveat_id_bytes),
                'signature_before': before,
                'signature_after': after,
            })

        computed = binascii.hexlify(signature).decode('ascii')
        proven = constant_time_compare(
            convert_to_bytes(computed),
            convert_to_bytes(candidate_signature),
        )
        return {
            'proven': proven,
            'from_signature': self.parent_signature,
            'final_signature': computed,
            'candidate_signature': candidate_signature,
            'steps': steps if proven else [],
            'unproven_steps': steps if not proven else [],
        }

    def _conditions(self, token, parent_caveats=None, source='token'):
        conditions = []
        for index, caveat in enumerate(token.caveats):
            if parent_caveats is not None:
                if index >= len(parent_caveats):
                    condition_source = 'appended'
                elif (
                    _caveat_fingerprint(caveat)
                    == _caveat_fingerprint(parent_caveats[index])
                ):
                    condition_source = 'parent'
                else:
                    condition_source = 'changed_parent'
            else:
                condition_source = source

            if caveat.first_party():
                predicate_bytes = caveat.caveat_id_bytes
                satisfied = predicate_bytes in self.satisfied_conditions
                conditions.append({
                    'kind': 'first_party',
                    'index': index,
                    'source': condition_source,
                    'predicate': _bytes_repr(predicate_bytes),
                    'status': (
                        'satisfied_by_supplied_fact'
                        if satisfied else 'pending'
                    ),
                    'reason': (
                        'caller supplied this exact predicate as a fact'
                        if satisfied else
                        'first-party predicate must be evaluated against '
                        'the actual request context'
                    ),
                })
            else:
                conditions.append({
                    'kind': 'third_party',
                    'index': index,
                    'source': condition_source,
                    'caveat_id': _bytes_repr(caveat.caveat_id_bytes),
                    'location': caveat.location,
                    'location_authenticated': False,
                    'status': 'pending',
                    'reason': (
                        'a discharge macaroon must be verified and its '
                        'business conditions evaluated; the caveat '
                        'location is not signed and is not authorization'
                    ),
                })
        return conditions

    def _location_findings(self, token, common_prefix, compare_root):
        findings = []
        if compare_root and token.location != self.parent.location:
            findings.append({
                'scope': 'macaroon',
                'index': None,
                'field': 'location',
                'from': self.parent.location,
                'to': token.location,
                'authenticated': False,
                'treated_as_authorization': False,
                'reason': (
                    'macaroon location changed from {0!r} to {1!r}; '
                    'location is not covered by the signature'.format(
                        self.parent.location, token.location
                    )
                ),
            })

        if common_prefix is not None:
            for index in range(
                    min(common_prefix, len(token.caveats))):
                parent_caveat = self.parent.caveats[index]
                candidate_caveat = token.caveats[index]
                if parent_caveat.location != candidate_caveat.location:
                    findings.append({
                        'scope': 'caveat',
                        'index': index,
                        'field': 'location',
                        'from': parent_caveat.location,
                        'to': candidate_caveat.location,
                        'authenticated': False,
                        'treated_as_authorization': False,
                        'reason': (
                            'existing caveat location at index {0} '
                            'changed from {1!r} to {2!r}; location is '
                            'not signed'.format(
                                index,
                                parent_caveat.location,
                                candidate_caveat.location,
                            )
                        ),
                    })

        if not compare_root and token.location:
            findings.append({
                'scope': 'macaroon',
                'index': None,
                'field': 'location',
                'from': None,
                'to': token.location,
                'authenticated': False,
                'treated_as_authorization': False,
                'reason': (
                    'discharge location {0!r} is an unsigned routing '
                    'hint, not authorization'.format(token.location)
                ),
            })

        for index, caveat in enumerate(token.caveats):
            if caveat.first_party() and caveat.location:
                findings.append({
                    'scope': 'caveat',
                    'index': index,
                    'field': 'location',
                    'from': None,
                    'to': caveat.location,
                    'authenticated': False,
                    'treated_as_authorization': False,
                    'reason': (
                        'first-party caveat at index {0} carries an '
                        'unsigned location {1!r}; locations are not '
                        'authorization'.format(index, caveat.location)
                    ),
                })
            if (
                caveat.third_party()
                and caveat.location
                and (
                    common_prefix is None
                    or index >= len(self.parent.caveats)
                )
            ):
                findings.append({
                    'scope': 'caveat',
                    'index': index,
                    'field': 'location',
                    'from': None,
                    'to': caveat.location,
                    'authenticated': False,
                    'treated_as_authorization': False,
                    'reason': (
                        'appended third-party caveat {0!r} advertises '
                        'unsigned location {1!r}; it is a routing hint, '
                        'not an authenticated authorization basis'
                        .format(
                            _bytes_repr(caveat.caveat_id_bytes),
                            caveat.location,
                        )
                    ),
                })
        return findings

    def _anchor(self):
        return {
            'identifier': _bytes_repr(self.parent.identifier_bytes),
            'signature': self.parent_signature,
            'caveat_count': len(self.parent.caveats),
            'caveats': [
                _caveat_info(caveat) for caveat in self.parent.caveats
            ],
            'source': 'caller-supplied parent macaroon, assumed verified',
        }

    def _report(self,
                label,
                status,
                reason,
                anchor,
                token_info,
                item,
                common_prefix_length=0,
                comparison=None,
                appended=None,
                chain=None,
                prefix_issue=None,
                location_findings=None,
                conditions=None,
                discharge=None,
                diagnostics=None):
        return ProvenanceReport(
            label=label,
            status=status,
            reason=reason,
            anchor=anchor,
            candidate=token_info,
            common_prefix_length=common_prefix_length,
            caveat_comparison=comparison,
            appended_caveats=appended,
            proven_chain=chain,
            prefix_issue=prefix_issue,
            location_findings=location_findings,
            conditions_requiring_context=conditions,
            discharge=discharge,
            diagnostics=diagnostics,
        )


def verify_provenance(parent,
                      candidate,
                      label=None,
                      kind='auto',
                      unbound=None,
                      satisfied_conditions=None):
    '''Convenience wrapper around :class:`ProvenanceVerifier`.'''
    verifier = ProvenanceVerifier(
        parent, satisfied_conditions=satisfied_conditions
    )
    return verifier.verify(
        candidate, label=label, kind=kind, unbound=unbound
    )


def _signature_hex(macaroon):
    try:
        signature = convert_to_string(macaroon.signature_bytes)
    except (TypeError, UnicodeDecodeError):
        return None
    if signature is None:
        return None
    signature = signature.strip().lower()
    if len(signature) != 64:
        return None
    try:
        binascii.unhexlify(signature)
    except (TypeError, binascii.Error):
        return None
    return signature


def _caveat_fingerprints(macaroon):
    return [
        _caveat_fingerprint(caveat) for caveat in macaroon.caveats
    ]


def _caveat_fingerprint(caveat):
    if caveat.first_party():
        return (b'first_party', caveat.caveat_id_bytes)
    return (
        b'third_party',
        caveat.caveat_id_bytes,
        caveat.verification_key_id,
    )


def _caveat_info(caveat):
    if caveat is None:
        return None
    info = {
        'type': 'first_party' if caveat.first_party() else 'third_party',
        'caveat_id': _bytes_repr(caveat.caveat_id_bytes),
        'location': caveat.location,
        'location_authenticated': False,
    }
    if caveat.third_party():
        info['verification_key_id'] = _bytes_repr(
            caveat.verification_key_id
        )
    return info


def _token_info(macaroon):
    return {
        'identifier': _bytes_repr(macaroon.identifier_bytes),
        'location': macaroon.location,
        'location_authenticated': False,
        'signature': _signature_hex(macaroon),
        'caveat_count': len(macaroon.caveats),
    }


def _comparison_entry(index, relation, parent_caveat, candidate_caveat):
    return {
        'index': index,
        'relation': relation,
        'parent': _caveat_info(parent_caveat),
        'candidate': _caveat_info(candidate_caveat),
        'location_changed': (
            parent_caveat is not None
            and candidate_caveat is not None
            and parent_caveat.location != candidate_caveat.location
        ),
    }


def _prefix_issue_kind(parent_caveats, candidate_caveats, index):
    parent_fingerprints = [
        _caveat_fingerprint(caveat) for caveat in parent_caveats
    ]
    candidate_fingerprints = [
        _caveat_fingerprint(caveat) for caveat in candidate_caveats
    ]

    if _is_ordered_subsequence(
            candidate_fingerprints, parent_fingerprints):
        return 'parent_caveats_removed'
    if (
        len(candidate_fingerprints) == len(parent_fingerprints)
        and sorted(candidate_fingerprints) == sorted(parent_fingerprints)
    ):
        return 'parent_caveats_reordered'

    if _contains_all(parent_fingerprints, candidate_fingerprints):
        return 'parent_caveats_reordered'

    if index < len(parent_caveats) and index < len(candidate_caveats):
        if (
            _caveat_fingerprint(candidate_caveats[index])
            in parent_fingerprints
        ):
            return 'parent_caveats_reordered_or_removed'
        return 'parent_caveat_replaced'
    return 'parent_caveats_removed'


def _is_ordered_subsequence(candidate, parent):
    if not candidate or len(candidate) > len(parent):
        return False
    position = 0
    for item in parent:
        if position < len(candidate) and candidate[position] == item:
            position += 1
    return position == len(candidate)


def _contains_all(required, available):
    if len(required) > len(available):
        return False
    remaining = list(available)
    for item in required:
        if item not in remaining:
            return False
        remaining.remove(item)
    return True


def _bytes_repr(value):
    if value is None:
        return None
    try:
        return value.decode('utf-8')
    except UnicodeDecodeError:
        return 'base64:' + standard_b64encode(value).decode('ascii')
