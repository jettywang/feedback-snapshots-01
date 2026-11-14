from __future__ import unicode_literals

import pytest

from pymacaroons import Macaroon
from pymacaroons.provenance import (
    Candidate,
    ProvenanceVerifier,
    STATUS_DIFFERENT_BRANCH,
    STATUS_DISCHARGE_BINDING_UNVERIFIED,
    STATUS_FOREIGN_TOKEN,
    STATUS_INVALID_DISCHARGE_BINDING,
    STATUS_INVALID_SIGNATURE,
    STATUS_MALFORMED_TOKEN,
    STATUS_PREFIX_MISMATCH,
    STATUS_PSEUDO_DESCENDANT,
    STATUS_REQUEST_BOUND_DISCHARGE,
    STATUS_UNCHANGED_PARENT,
    STATUS_VALID_DESCENDANT,
    verify_provenance,
)


ROOT_KEY = 'root-key-only-known-to-issuer'
IDENTIFIER = 'root-key-id'


def parent_macaroon():
    macaroon = Macaroon(
        location='https://bank.example',
        identifier=IDENTIFIER,
        key=ROOT_KEY,
    )
    macaroon.add_first_party_caveat('account = alice')
    macaroon.add_first_party_caveat('role = reader')
    macaroon.add_third_party_caveat(
        'https://auth.example',
        'discharge-key',
        'authz-step-up',
    )
    return macaroon


def verify(parent, token, **kwargs):
    satisfied = kwargs.pop('satisfied_conditions', None)
    return ProvenanceVerifier(
        parent, satisfied_conditions=satisfied
    ).verify(token, **kwargs)


def test_valid_descendant_proves_appended_first_and_third_party_chain():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')
    child.add_third_party_caveat(
        'https://auth.example', 'second-key', 'second-authz'
    )

    report = verify(parent, child, label='child')

    assert report.status == STATUS_VALID_DESCENDANT
    assert report.is_valid_attenuation
    assert not report.is_parent
    assert report.common_prefix_length == len(parent.caveats)
    assert [caveat['type'] for caveat in report.appended_caveats] == [
        'first_party',
        'third_party',
    ]
    assert report.proven_chain['proven']
    assert [
        step['index'] for step in report.proven_chain['steps']
    ] == [3, 4]
    assert report.proven_chain['from_signature'] == parent.signature
    assert (
        report.proven_chain['final_signature'] == child.signature
    )
    assert report.anchor['signature'] == parent.signature
    assert report.anchor['identifier'] == IDENTIFIER
    assert 'assumed verified' in report.anchor['source']


def test_parent_itself_is_reported_as_anchor_not_as_new_child():
    parent = parent_macaroon()

    report = verify(parent, parent)

    assert report.status == STATUS_UNCHANGED_PARENT
    assert not report.is_valid_attenuation
    assert report.proven_chain['proven']
    assert report.proven_chain['steps'] == []


def test_deleting_parent_caveat_is_rejected():
    parent = parent_macaroon()
    forged = parent.copy()
    del forged.caveats[0]
    forged.signature = parent.signature

    report = verify(parent, forged)

    assert not report.is_valid_attenuation
    assert report.status in (
        STATUS_PSEUDO_DESCENDANT, STATUS_PREFIX_MISMATCH
    )
    assert report.prefix_issue['kind'] == 'parent_caveats_removed'


def test_reordering_parent_caveats_is_rejected():
    parent = parent_macaroon()
    forged = parent.copy()
    forged.caveats[0], forged.caveats[1] = (
        forged.caveats[1], forged.caveats[0]
    )
    forged.signature = parent.signature

    report = verify(parent, forged)

    assert not report.is_valid_attenuation
    assert report.status in (
        STATUS_PSEUDO_DESCENDANT, STATUS_PREFIX_MISMATCH
    )
    assert report.prefix_issue['kind'] in (
        'parent_caveats_reordered',
        'parent_caveats_reordered_or_removed',
    )


def test_reordering_old_caveat_into_appended_region_is_rejected():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')
    forged = child.copy()
    forged.caveats[0], forged.caveats[3] = (
        forged.caveats[3], forged.caveats[0]
    )

    report = verify(parent, forged)

    assert report.status == STATUS_PREFIX_MISMATCH
    assert not report.is_valid_attenuation
    assert report.prefix_issue['kind'] == 'parent_caveats_reordered'


def test_replaced_old_caveat_is_reported_as_pseudo_descendant():
    parent = parent_macaroon()
    forged = parent.copy()
    forged.caveats[1].caveat_id = 'role = administrator'
    forged.add_first_party_caveat('scope = invoices:write')

    report = verify(parent, forged)

    assert report.status == STATUS_PSEUDO_DESCENDANT
    assert not report.is_valid_attenuation
    assert not report.proven_chain['proven']
    assert (
        report.prefix_issue['evidence']
        == 'signature_derived_from_parent'
    )
    assert (
        report.prefix_issue['parent_caveat']['caveat_id']
        == 'role = reader'
    )
    assert (
        report.prefix_issue['candidate_caveat']['caveat_id']
        == 'role = administrator'
    )


def test_replaced_old_caveat_with_unchanged_parent_signature_is_rejected():
    parent = parent_macaroon()
    forged = parent.copy()
    forged.caveats[0].caveat_id = 'account = bob'

    report = verify(parent, forged)

    assert report.status == STATUS_PSEUDO_DESCENDANT
    assert (
        report.prefix_issue['evidence']
        == 'signature_identical_to_parent'
    )
    assert not report.is_valid_attenuation


def test_replaced_old_caveat_inside_a_real_child_is_rejected():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')
    forged = child.copy()
    forged.caveats[0].caveat_id = 'account = mallory'

    report = verify(parent, forged)

    assert report.status == STATUS_PSEUDO_DESCENDANT
    assert not report.is_valid_attenuation
    assert (
        report.prefix_issue['evidence']
        == 'signature_derived_from_parent'
    )


def test_tampered_appended_caveat_fails_signature_replay():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')
    child.caveats[-1].caveat_id = 'scope = invoices:write'

    report = verify(parent, child)

    assert report.status == STATUS_INVALID_SIGNATURE
    assert not report.is_valid_attenuation
    assert report.common_prefix_length == len(parent.caveats)


def test_tampered_third_party_verification_key_fails_prefix_match():
    parent = parent_macaroon()
    forged = parent.copy()
    forged.caveats[-1].verification_key_id = b'not-the-original-vid'
    forged.add_first_party_caveat('scope = invoices:read')

    report = verify(parent, forged)

    assert not report.is_valid_attenuation
    assert report.prefix_issue is not None
    assert report.prefix_issue['index'] == len(parent.caveats) - 1


def test_same_root_different_branch_is_not_a_descendant():
    parent = parent_macaroon()
    sibling = Macaroon(
        location='https://bank.example',
        identifier=IDENTIFIER,
        key=ROOT_KEY,
    )
    sibling.add_first_party_caveat('account = alice')
    sibling.add_first_party_caveat('role = approver')
    sibling.add_first_party_caveat('scope = reports:read')

    report = verify(parent, sibling)

    assert report.status == STATUS_DIFFERENT_BRANCH
    assert not report.is_valid_attenuation
    assert not report.proven_chain['proven']
    assert report.prefix_issue['evidence'] == 'no_parent_derived_chain'
    assert 'sibling' in report.reason


def test_foreign_identifier_cannot_be_attributed_to_parent():
    parent = parent_macaroon()
    foreign = Macaroon(
        location='https://bank.example',
        identifier='another-root-id',
        key=ROOT_KEY,
    )

    report = verify(parent, foreign)

    assert report.status == STATUS_FOREIGN_TOKEN
    assert not report.is_valid_attenuation


def test_unsigned_macaroon_location_change_is_not_authorization():
    parent = parent_macaroon()
    child = parent.copy()
    child.location = 'https://evil.example'
    child.add_first_party_caveat('scope = invoices:read')

    report = verify(parent, child)

    assert report.status == STATUS_VALID_DESCENDANT
    assert any(
        finding['scope'] == 'macaroon'
        and finding['to'] == 'https://evil.example'
        and finding['treated_as_authorization'] is False
        for finding in report.location_findings
    )
    assert 'not covered by the signature' in report.explain()


def test_unsigned_third_party_caveat_location_change_is_not_authorization():
    parent = parent_macaroon()
    child = parent.copy()
    child.caveats[-1].location = 'https://evil.example'
    child.add_first_party_caveat('scope = invoices:read')

    report = verify(parent, child)

    assert report.status == STATUS_VALID_DESCENDANT
    finding = report.location_findings[0]
    assert finding['scope'] == 'caveat'
    assert finding['index'] == len(parent.caveats) - 1
    assert finding['from'] == 'https://auth.example'
    assert finding['to'] == 'https://evil.example'
    assert finding['authenticated'] is False
    assert finding['treated_as_authorization'] is False


def test_unchanged_first_party_predicate_is_still_pending_without_context():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')

    report = verify(parent, child)

    pending = [
        condition
        for condition in report.conditions_requiring_context
        if condition['status'] == 'pending'
    ]
    first_party_predicates = {
        condition['predicate']
        for condition in pending
        if condition['kind'] == 'first_party'
    }
    assert first_party_predicates >= {
        'account = alice',
        'role = reader',
        'scope = invoices:read',
    }
    assert any(
        condition['kind'] == 'third_party'
        and condition['caveat_id'] == 'authz-step-up'
        for condition in pending
    )


def test_satisfied_fact_is_reported_but_does_not_change_provenance():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')

    report = verify(
        parent,
        child,
        satisfied_conditions=['role = reader'],
    )

    conditions = {
        condition['predicate']: condition
        for condition in report.conditions_requiring_context
        if condition['kind'] == 'first_party'
    }
    assert conditions['role = reader']['status'] == (
        'satisfied_by_supplied_fact'
    )
    assert conditions['scope = invoices:read']['status'] == 'pending'
    assert report.status == STATUS_VALID_DESCENDANT


def make_discharge():
    discharge = Macaroon(
        location='https://auth.example',
        identifier='authz-step-up',
        key='discharge-key',
    )
    discharge.add_first_party_caveat('user = alice')
    return discharge


def test_request_bound_discharge_is_reported_separately():
    parent = parent_macaroon()
    discharge = make_discharge()
    bound = parent.prepare_for_request(discharge)

    report = verify(
        parent,
        Candidate(
            bound,
            'bound discharge',
            kind='discharge',
            unbound=discharge,
        ),
    )

    assert report.status == STATUS_REQUEST_BOUND_DISCHARGE
    assert report.is_discharge
    assert report.is_request_bound
    assert not report.is_valid_attenuation
    assert report.discharge['binding_verified'] is True
    assert report.discharge['bound_to_parent_signature'] == parent.signature
    assert "not an ordinary attenuated child" in report.reason


def test_discharge_is_detected_even_when_caller_omits_kind():
    parent = parent_macaroon()
    discharge = make_discharge()
    bound = parent.prepare_for_request(discharge)

    report = verify(parent, bound, unbound=discharge)

    assert report.status == STATUS_REQUEST_BOUND_DISCHARGE
    assert report.is_request_bound


def test_discharge_without_unbound_original_is_not_called_a_child():
    parent = parent_macaroon()
    discharge = make_discharge()
    bound = parent.prepare_for_request(discharge)

    report = verify(parent, bound)

    assert report.status == STATUS_DISCHARGE_BINDING_UNVERIFIED
    assert report.is_discharge
    assert not report.is_valid_attenuation
    assert report.discharge['checked'] is False


def test_discharge_bound_to_a_different_parent_is_rejected():
    parent = parent_macaroon()
    other_parent = parent.copy()
    other_parent.add_first_party_caveat('role = approver')
    discharge = make_discharge()
    bound_to_other = other_parent.prepare_for_request(discharge)

    report = verify(
        parent,
        Candidate(
            bound_to_other,
            'misbound discharge',
            kind='discharge',
            unbound=discharge,
        ),
    )

    assert report.status == STATUS_INVALID_DISCHARGE_BINDING
    assert not report.is_request_bound
    assert report.discharge['binding_verified'] is False


def test_discharge_is_not_treated_as_ordinary_child_with_extra_caveats():
    parent = parent_macaroon()
    discharge = make_discharge()
    discharge.add_first_party_caveat('scope = nothing')
    bound = parent.prepare_for_request(discharge)

    report = verify(
        parent,
        Candidate(bound, 'bound discharge', unbound=discharge),
    )

    assert report.is_request_bound
    assert not report.is_valid_attenuation
    assert report.status == STATUS_REQUEST_BOUND_DISCHARGE


def test_report_to_dict_and_explain_include_anchor_chain_and_context():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')

    report = verify(parent, child, label='legal child')
    data = report.to_dict()
    explanation = report.explain()

    assert data['status'] == STATUS_VALID_DESCENDANT
    assert data['anchor']['signature'] == parent.signature
    assert data['proven_chain']['proven'] is True
    assert 'legal child: valid_descendant' in explanation
    assert 'anchor:' in explanation
    assert 'proven:' in explanation
    assert 'request context still required' in explanation


def test_malformed_candidate_signature_is_rejected():
    parent = parent_macaroon()
    broken = parent.copy()
    broken.signature = 'not-a-valid-signature'

    report = verify(parent, broken)

    assert report.status == STATUS_MALFORMED_TOKEN
    assert not report.is_valid_attenuation


def test_parent_requires_non_empty_identifier():
    bad_parent = Macaroon(location='x', identifier='', key='k')
    with pytest.raises(ValueError):
        ProvenanceVerifier(bad_parent)


def test_candidate_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Candidate(parent_macaroon(), kind='root')


def test_verify_provenance_wrapper_matches_verifier():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')

    report = verify_provenance(parent, child, label='child')

    assert report.status == STATUS_VALID_DESCENDANT
    assert report.label == 'child'


def test_parent_signature_is_not_required_by_verifier():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')

    verifier = ProvenanceVerifier(parent)
    assert not hasattr(verifier, 'key')
    assert verifier.verify(child).is_valid_attenuation


def test_appended_caveat_reusing_parent_signature_is_rejected():
    parent = parent_macaroon()
    child = parent.copy()
    child.add_first_party_caveat('scope = invoices:read')
    child.signature = parent.signature

    report = verify(parent, child)

    assert report.status == STATUS_INVALID_SIGNATURE
    assert not report.is_valid_attenuation
    assert (
        report.proven_chain['candidate_signature']
        != report.proven_chain['final_signature']
    )
