"""Demonstrate root-key-free provenance checks for child macaroons.

The parent macaroon below stands in for a token whose signature has already
been verified by the relying party.  No root key is passed to the provenance
verifier.
"""

from __future__ import print_function

from pymacaroons import Macaroon, Verifier
from pymacaroons.provenance import (
    Candidate,
    ProvenanceVerifier,
    STATUS_DIFFERENT_BRANCH,
    STATUS_PSEUDO_DESCENDANT,
    STATUS_REQUEST_BOUND_DISCHARGE,
    STATUS_VALID_DESCENDANT,
)


def build_tokens():
    parent = Macaroon(
        location='https://bank.example',
        identifier='root-key-id',
        key='root-key-not-given-to-verifier',
    )
    parent.add_first_party_caveat('account = alice')
    parent.add_first_party_caveat('role = reader')
    parent.add_third_party_caveat(
        'https://auth.example',
        'discharge-key',
        'authz-step-up',
    )

    # Ordinary append-only child of the supplied parent.
    legitimate = parent.copy()
    legitimate.add_first_party_caveat('scope = invoices:read')

    # Same root and identifier, but a different branch from the same
    # signing key.  It diverges at the first caveat, so it is not a
    # descendant of the supplied parent.
    sibling = Macaroon(
        location='https://bank.example',
        identifier='root-key-id',
        key='root-key-not-given-to-verifier',
    )
    sibling.add_first_party_caveat('account = alice')
    sibling.add_first_party_caveat('role = approver')
    sibling.add_first_party_caveat('scope = reports:read')

    # Fabricated descendant: changes an existing caveat while keeping the
    # authenticated parent signature.  Its claimed new caveat is unsigned.
    forged = parent.copy()
    forged.caveats[1].caveat_id = 'role = administrator'
    forged.add_first_party_caveat('scope = invoices:write')

    # Same signed caveats, but the third-party caveat's unsigned
    # location was rewritten after issuance.
    relocated = parent.copy()
    relocated.caveats[-1].location = 'https://attacker.example'
    relocated.add_first_party_caveat('scope = invoices:read')

    discharge = Macaroon(
        location='https://auth.example',
        identifier='authz-step-up',
        key='discharge-key',
    )
    discharge.add_first_party_caveat('user = alice')
    bound = parent.prepare_for_request(discharge)
    return {
        'parent': parent,
        'legitimate': legitimate,
        'sibling': sibling,
        'forged': forged,
        'relocated': relocated,
        'discharge': discharge,
        'bound': bound,
    }


def main():
    tokens = build_tokens()
    parent = tokens['parent']

    # Establish that the anchor is genuinely authenticated, then discard
    # the key before provenance checks.  The verifier itself never sees it.
    anchor_verifier = Verifier()
    anchor_verifier = Verifier(
        discharge_macaroons=[parent.prepare_for_request(tokens['discharge'])]
    )
    anchor_verifier.satisfy_exact('account = alice')
    anchor_verifier.satisfy_exact('role = reader')
    anchor_verifier.satisfy_exact('user = alice')
    assert anchor_verifier.verify(
        parent, 'root-key-not-given-to-verifier'
    )
    del tokens['parent']
    parent = parent.copy()

    verifier = ProvenanceVerifier(
        parent,
        satisfied_conditions=['role = reader'],
    )
    candidates = [
        Candidate(tokens['legitimate'], 'legitimate descendant'),
        Candidate(tokens['sibling'], 'same-root sibling branch'),
        Candidate(tokens['forged'], 'pseudo descendant'),
        Candidate(tokens['relocated'], 'relocated third-party caveat'),
        Candidate(
            tokens['bound'],
            'request-bound discharge',
            kind='discharge',
            unbound=tokens['discharge'],
        ),
    ]

    print('Trusted parent (assumed already signature-verified):')
    print('  identifier: {0}'.format(parent.identifier))
    print('  signature:  {0}'.format(parent.signature))
    print('  caveats:    {0}'.format(', '.join(
        caveat.caveat_id for caveat in parent.caveats
    )))
    print()

    results = verifier.verify_all(candidates)
    for result in results:
        print('=' * 78)
        print(result.explain())

    print()
    print('=' * 78)
    print('Summary')
    for result in results:
        print('  {0:<32} {1}'.format(result.label, result.status))

    expected = [
        STATUS_VALID_DESCENDANT,
        STATUS_DIFFERENT_BRANCH,
        STATUS_PSEUDO_DESCENDANT,
        STATUS_VALID_DESCENDANT,
        STATUS_REQUEST_BOUND_DISCHARGE,
    ]
    assert [result.status for result in results] == expected
    print()
    print('For the relocated third-party caveat, the signed caveat update '
          'chain is still valid because location is not signed. The changed '
          'location is reported as unsigned and is not treated as an '
          'authorization basis.')


if __name__ == '__main__':
    main()
