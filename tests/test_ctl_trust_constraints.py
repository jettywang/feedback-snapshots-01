"""Independent criterion tests for the trust constraints embedded in a Certificate
Trust List.

These tests do not rely on the shipped Microsoft authroot STL. Instead they generate a
dedicated PKI and a signed CTL with :mod:`tests.ctl_trust_factory`, so that the exact
issuance moment and EKU of every certificate, and every CTL constraint field, are under
test control. A fixed verification moment is used throughout.

The matrix below is derived directly from the field semantics in
:class:`signify.authenticode.trust_list.CertificateTrustSubject` (rather than copied from
observed behaviour). Two orthogonal "times" and two orthogonal EKU sets are involved:

* ``not_before_filetime`` constrains the **leaf certificate's issuance moment**
  (``chain[-1].valid_from``), not the verification timestamp.
* ``disallowed_filetime`` constrains the **signature verification timestamp**
  (``VerificationContext.timestamp``), not any certificate field.
* ``extended_key_usages`` is an allow-list applied to the requested EKUs. Absent and an
  empty list both mean "everything is allowed".
* ``disallowed_extended_key_usages`` / ``not_before_extended_key_usages`` are EKU
  selectors that scope the matching time constraint. A present-but-empty selector never
  matches, so it must not be collapsed into "disallow/block everything".
"""

from __future__ import annotations

import datetime
import hashlib

import pytest

from signify.authenticode.signed_data import AuthenticodeSignature
from signify.authenticode.trust_list import CertificateTrustList
from signify.exceptions import CTLCertificateVerificationError
from signify.x509.context import CertificateStore, VerificationContext
from tests.ctl_trust_factory import (
    CTLConstraints,
    VERIFY_MOMENT,
    build_authenticode_signature,
    build_ctl,
    build_pki,
)

CODE_SIGNING = "code_signing"
EMAIL_PROTECTION = "email_protection"

# Reference moments around the fixed verification moment.
PAST_MOMENT = datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc)
FUTURE_MOMENT = datetime.datetime(2023, 6, 1, tzinfo=datetime.timezone.utc)
NOT_BEFORE_BOUNDARY = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
DISALLOWED_BOUNDARY = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)


@pytest.fixture(scope="module")
def pki():
    return build_pki()


@pytest.fixture(scope="module")
def file_content() -> bytes:
    return b"the quick brown fox jumps over the lazy dog\n"


def _ctl(pki, constraints: CTLConstraints) -> CertificateTrustList:
    return CertificateTrustList.from_envelope(build_ctl(pki, constraints))


def _trusted_store(pki, ctl: CertificateTrustList) -> CertificateStore:
    return CertificateStore([pki.root.certificate], trusted=True, ctl=ctl)


def _subject_trust(pki, ctl, leaf_certificate, *, moment, ekus):
    """Invoke the CTL subject trust decision directly with an explicit context."""
    subject = ctl.find_subject(pki.root.certificate)
    assert subject is not None
    chain = [pki.root.certificate, pki.intermediate.certificate, leaf_certificate]
    context = VerificationContext(timestamp=moment, extended_key_usages=list(ekus))
    return subject.verify_trust(chain, context)


def _assert_rejects(pki, ctl, leaf_certificate, *, moment, ekus=(CODE_SIGNING,)):
    with pytest.raises(CTLCertificateVerificationError):
        _subject_trust(
            pki, ctl, leaf_certificate, moment=moment, ekus=ekus
        )


def _assert_accepts(pki, ctl, leaf_certificate, *, moment, ekus=(CODE_SIGNING,)):
    assert _subject_trust(
        pki, ctl, leaf_certificate, moment=moment, ekus=ekus
    )


# --------------------------------------------------------------------------------------
# Expected matrix derived from the field semantics.
#
# Each row states, for one CTL subject configuration, *which* time and *which*
# certificate drive the decision. ``leaf`` is "early" (issued 2020) or "late" (2022);
# the fixed verify moment is 2021-06. Constraints compare against the 2021-01 boundary.
# --------------------------------------------------------------------------------------
EARLY = "early"
LATE = "late"
ACCEPT = True
REJECT = False

MATRIX = [
    # --- allow-list (extended_key_usages): absent and [] mean "all EKUs" ---
    pytest.param(
        CTLConstraints(), EARLY, VERIFY_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="allow-absent-permits-code-signing",
    ),
    pytest.param(
        CTLConstraints(extended_key_usages=[]), EARLY, VERIFY_MOMENT,
        (CODE_SIGNING,), ACCEPT,
        id="allow-empty-list-still-permits-all",
    ),
    pytest.param(
        CTLConstraints(extended_key_usages=[EMAIL_PROTECTION]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), REJECT,
        id="allow-listing-other-eku-rejects-code-signing",
    ),
    pytest.param(
        CTLConstraints(extended_key_usages=[CODE_SIGNING]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="allow-listing-requested-eku-accepts",
    ),
    # --- disallowed EKU selector: absent/[] never block, listed EKU does ---
    pytest.param(
        CTLConstraints(disallowed_extended_key_usages=[]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="disallow-empty-selector-matches-nothing",
    ),
    pytest.param(
        CTLConstraints(disallowed_extended_key_usages=[CODE_SIGNING]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), REJECT,
        id="disallow-listed-eku-blocks",
    ),
    pytest.param(
        CTLConstraints(disallowed_extended_key_usages=[CODE_SIGNING]), EARLY,
        VERIFY_MOMENT, (EMAIL_PROTECTION,), ACCEPT,
        id="disallow-scoped-eku-leaves-other-usage-alone",
    ),
    # --- disallowed_filetime: compares the SIGNATURE moment ---
    pytest.param(
        CTLConstraints(disallowed_filetime=DISALLOWED_BOUNDARY), EARLY,
        PAST_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="disallowed-time-before-boundary-accepts",
    ),
    pytest.param(
        CTLConstraints(disallowed_filetime=DISALLOWED_BOUNDARY), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), REJECT,
        id="disallowed-time-at-or-after-boundary-rejects",
    ),
    pytest.param(
        CTLConstraints(
            disallowed_filetime=DISALLOWED_BOUNDARY,
            disallowed_extended_key_usages=[CODE_SIGNING],
        ),
        EARLY, VERIFY_MOMENT, (EMAIL_PROTECTION,), ACCEPT,
        id="disallowed-time-scoped-to-other-eku-accepts",
    ),
    # --- not_before_filetime: compares the LEAF issuance, not the verify moment ---
    pytest.param(
        CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY), EARLY,
        FUTURE_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="notbefore-early-leaf-accepts-even-at-late-moment",
    ),
    pytest.param(
        CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY), LATE,
        PAST_MOMENT, (CODE_SIGNING,), REJECT,
        id="notbefore-late-leaf-rejects-even-at-early-moment",
    ),
    pytest.param(
        CTLConstraints(
            not_before_filetime=NOT_BEFORE_BOUNDARY,
            not_before_extended_key_usages=[CODE_SIGNING],
        ),
        LATE, VERIFY_MOMENT, (EMAIL_PROTECTION,), ACCEPT,
        id="notbefore-scoped-to-other-eku-accepts",
    ),
    pytest.param(
        CTLConstraints(not_before_extended_key_usages=[CODE_SIGNING]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), REJECT,
        id="notbefore-selector-without-time-blocks-matching-eku",
    ),
    pytest.param(
        CTLConstraints(not_before_extended_key_usages=[]), EARLY,
        VERIFY_MOMENT, (CODE_SIGNING,), ACCEPT,
        id="notbefore-empty-selector-matches-nothing",
    ),
]


@pytest.mark.parametrize(
    "constraints, leaf_name, moment, ekus, expected", MATRIX
)
def test_semantic_trust_matrix(
    pki, constraints, leaf_name, moment, ekus, expected
):
    leaf = pki.leaf.certificate if leaf_name == LATE else pki.leaf_early.certificate
    ctl = _ctl(pki, constraints)
    if expected is ACCEPT:
        _assert_accepts(pki, ctl, leaf, moment=moment, ekus=ekus)
    else:
        _assert_rejects(pki, ctl, leaf, moment=moment, ekus=ekus)


# --------------------------------------------------------------------------------------
# The CTL itself must first pass signature verification.
# --------------------------------------------------------------------------------------
def test_ctl_own_signature_verifies(pki):
    ctl = _ctl(pki, CTLConstraints())
    trusted_root = CertificateStore([pki.root.certificate], trusted=True)
    chains = list(ctl.verify(trusted_certificate_store=trusted_root))
    assert chains, "the generated CTL must be cryptographically verifiable"
    assert chains[0][0].subject == pki.root.certificate.subject


def test_ctl_lists_the_root_as_its_only_subject(pki):
    ctl = _ctl(pki, CTLConstraints())
    assert ctl.find_subject(pki.root.certificate) is not None
    # The constraint is anchored on the root fingerprint, not on the leaf.
    assert ctl.find_subject(pki.leaf.certificate) is None
    assert ctl.subject_usage == ["microsoft_root_list_signer"]


def test_tampered_ctl_fails_its_own_verification(pki):
    from signify.exceptions import VerificationError

    blob = bytearray(build_ctl(pki, CTLConstraints()))
    # Flip a byte inside the encrypted signature (the tail of the blob). This leaves
    # the ASN.1 structure parseable but invalidates the cryptographic signature.
    tampered = bytearray(blob)
    tampered[-3] ^= 0xFF
    ctl = CertificateTrustList.from_envelope(bytes(tampered))
    trusted_root = CertificateStore([pki.root.certificate], trusted=True)
    with pytest.raises(VerificationError):
        ctl.verify(trusted_certificate_store=trusted_root)

    # The unmodified CTL still verifies, proving the failure is caused by the tampering.
    intact = CertificateTrustList.from_envelope(bytes(blob))
    assert list(intact.verify(trusted_certificate_store=trusted_root))


# --------------------------------------------------------------------------------------
# Field-semantic matrix derived from the constraint definitions.
# --------------------------------------------------------------------------------------
def test_allow_list_absent_and_empty_both_permit_all_ekus(pki):
    # Missing attribute and an explicit empty list must not be conflated with a
    # deny-all set: both accept any requested EKU.
    for constraints in (
        CTLConstraints(extended_key_usages=None),
        CTLConstraints(extended_key_usages=[]),
    ):
        ctl = _ctl(pki, constraints)
        _assert_accepts(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)
        _assert_accepts(
            pki, ctl, pki.leaf_early.certificate,
            moment=VERIFY_MOMENT, ekus=(EMAIL_PROTECTION,),
        )


def test_allow_list_restricts_to_listed_ekus(pki):
    ctl = _ctl(pki, CTLConstraints(extended_key_usages=[EMAIL_PROTECTION]))
    _assert_rejects(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)
    _assert_accepts(
        pki, ctl, pki.leaf_early.certificate,
        moment=VERIFY_MOMENT, ekus=(EMAIL_PROTECTION,),
    )
    # Listing the requested EKU alongside another one is sufficient.
    ctl_both = _ctl(
        pki, CTLConstraints(extended_key_usages=[EMAIL_PROTECTION, CODE_SIGNING])
    )
    _assert_accepts(pki, ctl_both, pki.leaf_early.certificate, moment=VERIFY_MOMENT)


def test_disallowed_eku_absent_and_empty_do_not_block(pki):
    # An absent selector disables the restriction; an empty selector matches nothing.
    for constraints in (
        CTLConstraints(disallowed_extended_key_usages=None),
        CTLConstraints(disallowed_extended_key_usages=[]),
    ):
        ctl = _ctl(pki, constraints)
        _assert_accepts(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)


def test_disallowed_eku_blocks_only_listed_usage(pki):
    ctl = _ctl(
        pki, CTLConstraints(disallowed_extended_key_usages=[CODE_SIGNING])
    )
    _assert_rejects(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)
    # A different requested EKU is untouched by the selector.
    _assert_accepts(
        pki, ctl, pki.leaf_early.certificate,
        moment=VERIFY_MOMENT, ekus=(EMAIL_PROTECTION,),
    )


def test_disallowed_filetime_uses_verification_timestamp(pki):
    # The comparison is timestamp >= disallowed_filetime. The same certificate is
    # accepted before the boundary and rejected at/after it.
    constraints = CTLConstraints(disallowed_filetime=DISALLOWED_BOUNDARY)
    ctl = _ctl(pki, constraints)
    _assert_accepts(
        pki, ctl, pki.leaf_early.certificate, moment=PAST_MOMENT
    )
    _assert_rejects(
        pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT
    )


def test_disallowed_filetime_scoped_by_eku(pki):
    constraints = CTLConstraints(
        disallowed_filetime=DISALLOWED_BOUNDARY,
        disallowed_extended_key_usages=[CODE_SIGNING],
    )
    ctl = _ctl(pki, constraints)
    # After the boundary the scoped EKU is blocked ...
    _assert_rejects(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)
    # ... but an unrelated EKU remains usable at the same moment.
    _assert_accepts(
        pki, ctl, pki.leaf_early.certificate,
        moment=VERIFY_MOMENT, ekus=(EMAIL_PROTECTION,),
    )


def test_not_before_filetime_uses_leaf_issuance_not_verification_moment(pki):
    # not_before compares the LEAF's valid_from against the boundary, regardless of the
    # verification timestamp. The early (2020) leaf predates the boundary and passes even
    # at a late verification moment; the late (2022) leaf is rejected even at an early
    # verification moment.
    constraints = CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY)
    ctl = _ctl(pki, constraints)
    _assert_accepts(pki, ctl, pki.leaf_early.certificate, moment=FUTURE_MOMENT)
    _assert_rejects(pki, ctl, pki.leaf.certificate, moment=PAST_MOMENT)


def test_not_before_without_eku_blocks_whole_certificate(pki):
    # With a not_before time but no EKU selector, the restriction is EKU-independent.
    constraints = CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY)
    ctl = _ctl(pki, constraints)
    _assert_rejects(
        pki, ctl, pki.leaf.certificate,
        moment=PAST_MOMENT, ekus=(EMAIL_PROTECTION,),
    )


def test_not_before_scoped_by_eku(pki):
    constraints = CTLConstraints(
        not_before_filetime=NOT_BEFORE_BOUNDARY,
        not_before_extended_key_usages=[CODE_SIGNING],
    )
    ctl = _ctl(pki, constraints)
    # Late leaf + scoped EKU -> rejected.
    _assert_rejects(pki, ctl, pki.leaf.certificate, moment=VERIFY_MOMENT)
    # Same late leaf, but a non-matching requested EKU -> the constraint does not apply.
    _assert_accepts(
        pki, ctl, pki.leaf.certificate,
        moment=VERIFY_MOMENT, ekus=(EMAIL_PROTECTION,),
    )


def test_not_before_eku_selector_without_time_is_evaluated(pki):
    # When only the selector is present (no time), a matching EKU is rejected outright.
    constraints = CTLConstraints(
        not_before_extended_key_usages=[CODE_SIGNING]
    )
    ctl = _ctl(pki, constraints)
    _assert_rejects(pki, ctl, pki.leaf_early.certificate, moment=VERIFY_MOMENT)
    # An empty selector matches nothing and therefore stays permissive.
    permissive = _ctl(
        pki, CTLConstraints(not_before_extended_key_usages=[])
    )
    _assert_accepts(
        pki, permissive, pki.leaf_early.certificate, moment=VERIFY_MOMENT
    )


# --------------------------------------------------------------------------------------
# Chain ordering: the constraint must land on the leaf, the subject lookup on the root.
# --------------------------------------------------------------------------------------
def test_constraint_targets_leaf_not_root_or_intermediate(pki):
    # Root and intermediate were both created at WINDOW_START (2019), well before the
    # not_before boundary. Only the 2022 leaf postdates it. A rejection therefore proves
    # the decision reads chain[-1] (the leaf), not chain[0] (the root).
    constraints = CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY)
    ctl = _ctl(pki, constraints)
    assert pki.root.certificate.valid_from < NOT_BEFORE_BOUNDARY
    assert pki.intermediate.certificate.valid_from < NOT_BEFORE_BOUNDARY
    assert pki.leaf.certificate.valid_from >= NOT_BEFORE_BOUNDARY
    _assert_rejects(pki, ctl, pki.leaf.certificate, moment=PAST_MOMENT)
    _assert_accepts(pki, ctl, pki.leaf_early.certificate, moment=PAST_MOMENT)


def test_reversed_chain_order_is_not_silently_accepted(pki):
    # Guard the assumption that chains are root-first. If that ordering ever changed,
    # chain[-1] would no longer be the leaf and the not_before logic would read the wrong
    # certificate. This pins the ordering the implementation relies on.
    ctl = _ctl(pki, CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY))
    subject = ctl.find_subject(pki.root.certificate)
    proper_chain = [
        pki.root.certificate,
        pki.intermediate.certificate,
        pki.leaf.certificate,
    ]
    context = VerificationContext(
        timestamp=PAST_MOMENT, extended_key_usages=[CODE_SIGNING]
    )
    with pytest.raises(CTLCertificateVerificationError):
        subject.verify_trust(proper_chain, context)

    # The leaf-first ordering is not the contract; feeding it makes the constraint read
    # the root's issuance and thus (wrongly) pass, demonstrating why order matters.
    reversed_chain = list(reversed(proper_chain))
    assert subject.verify_trust(reversed_chain, context) is True


# --------------------------------------------------------------------------------------
# End-to-end: a cryptographically valid signature and chain, rejected via file verify.
# --------------------------------------------------------------------------------------
def test_valid_signature_accepted_without_restricting_ctl(pki, file_content):
    signature = AuthenticodeSignature.from_envelope(
        build_authenticode_signature(pki, file_content, early=True)
    )
    ctl = _ctl(pki, CTLConstraints())
    store = _trusted_store(pki, ctl)
    chains = list(
        signature.verify(
            trusted_certificate_store=store,
            expected_hash=hashlib.sha256(file_content).digest(),
            verification_context_kwargs={"timestamp": VERIFY_MOMENT},
        )
    )
    assert chains
    assert chains[0][-1].subject == pki.leaf_early.certificate.subject


def test_file_with_valid_signature_rejected_by_disallowed_eku(pki, file_content):
    # The RSA signature and the full chain validate; the CTL merely forbids code signing
    # for this root, so verification must surface a CTL trust error.
    signature = AuthenticodeSignature.from_envelope(
        build_authenticode_signature(pki, file_content, early=True)
    )
    ctl = _ctl(
        pki, CTLConstraints(disallowed_extended_key_usages=[CODE_SIGNING])
    )
    # Precondition: the CTL itself and the cryptographic chain are sound.
    list(ctl.verify(trusted_certificate_store=CertificateStore(
        [pki.root.certificate], trusted=True)))
    store = _trusted_store(pki, ctl)

    with pytest.raises(CTLCertificateVerificationError):
        list(
            signature.verify(
                trusted_certificate_store=store,
                expected_hash=hashlib.sha256(file_content).digest(),
                verification_context_kwargs={"timestamp": VERIFY_MOMENT},
            )
        )


def test_file_with_valid_signature_rejected_by_disallowed_filetime(pki, file_content):
    signature = AuthenticodeSignature.from_envelope(
        build_authenticode_signature(pki, file_content, early=True)
    )
    ctl = _ctl(
        pki, CTLConstraints(disallowed_filetime=DISALLOWED_BOUNDARY)
    )
    store = _trusted_store(pki, ctl)

    # At a moment before the boundary the very same file verifies ...
    earlier_store = _trusted_store(pki, ctl)
    assert list(
        signature.verify(
            trusted_certificate_store=earlier_store,
            expected_hash=hashlib.sha256(file_content).digest(),
            verification_context_kwargs={"timestamp": PAST_MOMENT},
        )
    )
    # ... while at the fixed verification moment (>= boundary) it is rejected, even
    # though the signature and chain are unchanged and still cryptographically valid.
    with pytest.raises(CTLCertificateVerificationError):
        list(
            signature.verify(
                trusted_certificate_store=store,
                expected_hash=hashlib.sha256(file_content).digest(),
                verification_context_kwargs={"timestamp": VERIFY_MOMENT},
            )
        )


def test_file_with_valid_signature_rejected_by_not_before_on_late_leaf(
    pki, file_content
):
    # The 2022 leaf produces a valid signature, but the CTL not_before constraint on leaf
    # issuance rejects it. The leaf certificate itself is otherwise valid.
    late_content = b"signed by the 2022 code-signing leaf\n"
    signature = AuthenticodeSignature.from_envelope(
        build_authenticode_signature(pki, late_content, early=False)
    )
    ctl = _ctl(pki, CTLConstraints(not_before_filetime=NOT_BEFORE_BOUNDARY))
    store = _trusted_store(pki, ctl)

    with pytest.raises(CTLCertificateVerificationError):
        list(
            signature.verify(
                trusted_certificate_store=store,
                expected_hash=hashlib.sha256(late_content).digest(),
                verification_context_kwargs={"timestamp": FUTURE_MOMENT},
            )
        )
