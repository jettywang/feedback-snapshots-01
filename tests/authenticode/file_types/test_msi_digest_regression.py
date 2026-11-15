"""MSI digest and signature regression tests.

The expected values in this module are derived from
:mod:`tests.authenticode.file_types._msi_regression`, which implements the
walking and metadata encoding rules independently of the Signify code under
test.  No expected digest is obtained by calling ``SignedMsiFile``.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import io
import pathlib

import pytest

from signify.authenticode import AuthenticodeVerificationResult
from signify.exceptions import (
    AuthenticodeInvalidDigestError,
    AuthenticodeInvalidExtendedDigestError,
)
from tests.authenticode.file_types import _msi_regression as reference

olefile = pytest.importorskip("olefile")

from signify.authenticode.signed_file import SignedMsiFile  # noqa: E402

TIMESTAMP = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

# Pinned once from reference_digests(canonical_model()), as a guard against
# accidental changes to the independent reference itself.
CANONICAL_TRADITIONAL = bytes.fromhex(
    "adbfdcc29d2a6bbabd08b9fd25f14ff0583d0923724822dc2e653760fa9726f9"
)
CANONICAL_PREHASH = bytes.fromhex(
    "4e28b0fc6bbad87f4f07508623f15aa8b5f8ffef1dbddd72e4ef307fc3af4997"
)
CANONICAL_EXTENDED = bytes.fromhex(
    "6f0ec5e778a095ca96a316bab2f2d5584771ad021e0d54d0f174a2569f77e5dd"
)


def _msi(data: bytes) -> SignedMsiFile:
    return SignedMsiFile(io.BytesIO(data))


def _verify(data: bytes):
    return _msi(data).explain_verify(
        trusted_certificate_store=reference.trusted_store(),
        verification_context_kwargs={"timestamp": TIMESTAMP},
    )


def _assert_ok(data: bytes) -> None:
    result, error = _verify(data)
    assert (result, error) == (AuthenticodeVerificationResult.OK, None)


def _assert_invalid_digest(data: bytes) -> None:
    result, error = _verify(data)
    assert result == AuthenticodeVerificationResult.INVALID_DIGEST
    assert isinstance(error, AuthenticodeInvalidDigestError)


def _assert_invalid_extended_digest(data: bytes) -> None:
    result, error = _verify(data)
    assert result == AuthenticodeVerificationResult.INVALID_ADDITIONAL_HASH
    assert isinstance(error, AuthenticodeInvalidExtendedDigestError)


def test_reference_values_are_stable():
    digests = reference.reference_digests(reference.canonical_model())
    assert digests.traditional == CANONICAL_TRADITIONAL
    assert digests.prehash == CANONICAL_PREHASH
    assert digests.extended == CANONICAL_EXTENDED


def test_traversal_order_uses_raw_utf16_bytes():
    model = reference.canonical_model()
    order = [path for path, _content in reference.reference_stream_order(model)]

    expected_order = [
        ("\x05SummaryInformation",),
        ("Data", "inner", "leaf"),
        ("Data", "m"),
        ("aĀ",),
        ("aÿ",),
        ("empty",),
        ("top",),
        ("z_storage", "X"),
        ("z_storage", "Y"),
        ("目录", "流"),
    ]
    assert order == expected_order

    # Python's default code-point ordering puts aÿ (U+00FF) before aĀ (U+0100);
    # the raw little-endian UTF-16 bytes put aĀ (00 01) before aÿ (ff 00).
    physical = [child.name for child in model.children]
    assert physical.index("aÿ") < physical.index("aĀ")

    # The traversal skips the signature streams and includes the empty stream.
    assert all(reference.DIGITAL_SIGNATURE not in path for path in order)
    assert all(reference.EXTENDED_DIGITAL_SIGNATURE not in path for path in order)


def test_ole_directory_shape_matches_the_sample_requirements():
    data, _digests = reference.signed_canonical_msi(extended=True)
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        assert ole.exists(["Data", "inner", "leaf"])
        assert ole.get_type(["Data", "inner"]) == olefile.STGTY_STORAGE
        assert ole.get_type(["Data", "inner", "leaf"]) == olefile.STGTY_STREAM
        assert ole.get_size(["empty"]) == 0

        names = {child.name: child for child in ole.root.kids}
        assert names["aĀ"].name_utf16 == "aĀ".encode("utf-16le")
        assert names["aÿ"].name_utf16 == "aÿ".encode("utf-16le")
        assert names["目录"].name_utf16 == "目录".encode("utf-16le")

        # The physical sibling order is the reverse of the traversal order for
        # the two adjacent entries.
        root_names = [child.name for child in ole.root.kids]
        assert root_names.index("aÿ") < root_names.index("aĀ")
    finally:
        ole.close()


def test_canonical_traditional_digest_matches_independent_reference():
    data, digests = reference.signed_canonical_msi(extended=False)
    msi = _msi(data)
    assert not msi.has_prehash
    assert msi.get_fingerprint(hashlib.sha256) == digests.traditional
    assert digests.traditional == hashlib.sha256(digests.stream_content).digest()
    _assert_ok(data)


def test_canonical_extended_digest_matches_independent_reference():
    data, digests = reference.signed_canonical_msi(extended=True)
    msi = _msi(data)
    assert msi.has_prehash
    assert msi.get_fingerprint(hashlib.sha256) == digests.extended
    assert msi._calculate_prehash(hashlib.sha256) == digests.prehash

    digest_stream = msi._ole_file.openstream(
        reference.EXTENDED_DIGITAL_SIGNATURE
    ).read()
    assert digest_stream == digests.prehash

    # The extended digest is hash(prehash_digest + content), not
    # hash(prehash_encoding + content).
    assert digests.extended == hashlib.sha256(
        digests.prehash + digests.stream_content
    ).digest()
    assert digests.extended != hashlib.sha256(
        digests.prehash_encoding + digests.stream_content
    ).digest()
    _assert_ok(data)


def test_traditional_reference_ignores_metadata_but_sees_nonempty_moves():
    model = reference.canonical_model()
    digests = reference.reference_digests(model)

    for mutate in (
        reference.with_renamed_storage,
        reference.with_empty_stream_moved_into_storage,
        reference.with_stream_timestamp,
        reference.with_storage_timestamp,
        reference.with_storage_flags,
        reference.with_root_timestamp,
        reference.with_stream_clsid,
        reference.with_reversed_physical_order,
    ):
        mutated = reference.reference_digests(mutate(model))
        assert mutated.stream_content == digests.stream_content
        assert mutated.traditional == digests.traditional

    # Moving a non-empty stream changes where its bytes occur in the
    # concatenation.  The traditional digest is content-order sensitive even
    # though it ignores the metadata of that stream.
    moved = reference.reference_digests(
        reference.with_leaf_moved_to_parent_storage(model)
    )
    assert moved.stream_content != digests.stream_content
    assert moved.traditional != digests.traditional
    assert moved.prehash == digests.prehash


def test_extended_reference_ignores_documented_non_covered_fields():
    model = reference.canonical_model()
    digests = reference.reference_digests(model)

    for mutate in (
        reference.with_root_timestamp,
        reference.with_stream_clsid,
        reference.with_reversed_physical_order,
    ):
        mutated = reference.reference_digests(mutate(model))
        assert mutated.prehash == digests.prehash
        assert mutated.extended == digests.extended

    # The root name is also outside the metadata encoding.  The serializer does
    # write it into the CFB header/directory as-is, but neither reference digest
    # reads it.
    renamed_root = reference.clone_model(model)
    renamed_root.name = "Renamed Root Entry"
    root_digests = reference.reference_digests(renamed_root)
    assert root_digests.prehash == digests.prehash

    # A storage size is not encoded in the prehash either (storages normally
    # carry zero anyway).
    resized_storage = reference.clone_model(model)
    reference.find_node(resized_storage, "Data").size = 1234
    storage_digests = reference.reference_digests(resized_storage)
    assert storage_digests.prehash == digests.prehash


@pytest.mark.parametrize("extended", [False, True], ids=["traditional", "extended"])
def test_uncovered_fields_do_not_break_either_signature(extended):
    data, digests = reference.signed_canonical_msi(extended=extended)
    mutated = reference.with_root_timestamp(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)
    assert mutated_digests.traditional == digests.traditional
    assert mutated_digests.prehash == digests.prehash

    signed = reference.build_signed_msi(
        mutated,
        extended=extended,
        signed_digest=digests.extended if extended else digests.traditional,
        prehash_digest=digests.prehash,
    )
    _assert_ok(signed)


@pytest.mark.parametrize(
    "mutate",
    [
        reference.with_renamed_storage,
        reference.with_empty_stream_moved_into_storage,
        reference.with_stream_timestamp,
        reference.with_storage_timestamp,
        reference.with_storage_flags,
    ],
    ids=[
        "storage-rename",
        "empty-stream-move",
        "stream-time",
        "storage-time",
        "storage-flags",
    ],
)
def test_extended_signature_rejects_metadata_that_traditional_ignores(mutate):
    data, digests = reference.signed_canonical_msi(extended=True)
    mutated = mutate(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)

    # The content part and the traditional digest are unchanged, so this is
    # metadata-only.  The extended digest is the layer that notices it.
    assert mutated_digests.stream_content == digests.stream_content
    assert mutated_digests.traditional == digests.traditional
    assert mutated_digests.prehash != digests.prehash
    assert mutated_digests.extended != digests.extended

    # Sign the mutated tree with the canonical digests, as an attacker
    # rewriting the directory without the private key would.
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=digests.extended,
        prehash_digest=digests.prehash,
    )
    _assert_invalid_digest(signed)

    # If the content-side extended digest is made to match the mutated tree,
    # but the EX stream still contains the canonical prehash, only the
    # extended-digest layer can catch the change.
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=mutated_digests.extended,
        prehash_digest=digests.prehash,
    )
    _assert_invalid_extended_digest(signed)


def test_metadata_change_is_rejected_only_by_the_extended_hash_layer():
    data, digests = reference.signed_canonical_msi(extended=True)
    mutated = reference.with_renamed_storage(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=mutated_digests.extended,
        prehash_digest=digests.prehash,
    )

    msi = _msi(signed)
    kwargs = {
        "trusted_certificate_store": reference.trusted_store(),
        "verification_context_kwargs": {"timestamp": TIMESTAMP},
    }
    # With the additional hash disabled, the traditional content layer is
    # satisfied.  The metadata change is visible only to the extended digest.
    assert msi.explain_verify(**kwargs, verify_additional_hashes=False) == (
        AuthenticodeVerificationResult.OK,
        None,
    )
    with pytest.raises(AuthenticodeInvalidExtendedDigestError):
        msi.verify(**kwargs)


def test_stream_content_change_still_fails_without_additional_hash_check():
    data, digests = reference.signed_canonical_msi(extended=True)
    mutated = reference.with_changed_stream_content(reference.canonical_model())
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=digests.extended,
        prehash_digest=digests.prehash,
    )
    # Disabling the extended-digest check must not rescue changed stream bytes.
    result, error = _msi(signed).explain_verify(
        trusted_certificate_store=reference.trusted_store(),
        verification_context_kwargs={"timestamp": TIMESTAMP},
        verify_additional_hashes=False,
    )
    assert result == AuthenticodeVerificationResult.INVALID_DIGEST
    assert isinstance(error, AuthenticodeInvalidDigestError)


def test_traditional_signature_accepts_metadata_only_change():
    data, digests = reference.signed_canonical_msi(extended=False)
    mutated = reference.with_renamed_storage(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)

    assert mutated_digests.traditional == digests.traditional
    signed = reference.build_signed_msi(
        mutated, extended=False, signed_digest=digests.traditional
    )

    # A traditional-only signature makes no promise about the storage name.
    _assert_ok(signed)


def test_mutated_extended_digest_with_stale_ex_stream_is_rejected():
    data, digests = reference.signed_canonical_msi(extended=True)
    mutated = reference.with_renamed_storage(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)

    # Sign the mutated extended digest (which matches the mutated content), but
    # leave the canonical EX stream in place.  The content digest now matches,
    # so the mismatching extended prehash is the layer that must reject it.
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=mutated_digests.extended,
        prehash_digest=digests.prehash,
    )
    _assert_invalid_extended_digest(signed)


@pytest.mark.parametrize("extended", [False, True], ids=["traditional", "extended"])
def test_stream_content_change_fails_both_signature_layers(extended):
    data, digests = reference.signed_canonical_msi(extended=extended)
    mutated = reference.with_changed_stream_content(reference.canonical_model())
    mutated_digests = reference.reference_digests(mutated)

    assert mutated_digests.stream_content != digests.stream_content
    assert mutated_digests.traditional != digests.traditional
    # A content change does not change the prehash encoding at all; the
    # extended hash changes only because the traditional content is prepended.
    assert mutated_digests.prehash == digests.prehash
    assert mutated_digests.extended != digests.extended

    signed = reference.build_signed_msi(
        mutated,
        extended=extended,
        signed_digest=digests.extended if extended else digests.traditional,
        prehash_digest=digests.prehash,
    )
    _assert_invalid_digest(signed)


def test_content_change_cannot_be_hidden_by_matching_extended_stream():
    data, digests = reference.signed_canonical_msi(extended=True)
    mutated = reference.with_changed_stream_content(reference.canonical_model())

    # Keep the canonical EX stream (whose prehash still matches the untouched
    # metadata) and sign the canonical extended digest.  The content digest
    # cannot match, so this must not verify.
    signed = reference.build_signed_msi(
        mutated,
        extended=True,
        signed_digest=digests.extended,
        prehash_digest=digests.prehash,
    )
    _assert_invalid_digest(signed)


def test_signature_streams_are_excluded_from_both_digests():
    data, digests = reference.signed_canonical_msi(extended=True)
    msi = _msi(data)
    assert msi._ole_file.exists(reference.DIGITAL_SIGNATURE)
    assert msi._ole_file.exists(reference.EXTENDED_DIGITAL_SIGNATURE)

    # Compare with a traditional-only signature over the same directory tree:
    # neither the presence of the signature streams nor their bytes enters
    # either digest, so this still hashes to the pinned traditional value.
    without_extended = reference.build_signed_msi(
        reference.canonical_model(),
        extended=False,
        signed_digest=digests.traditional,
    )
    traditional_only = _msi(without_extended)
    assert not traditional_only.has_prehash
    assert traditional_only.get_fingerprint(hashlib.sha256) == digests.traditional
    _assert_ok(without_extended)


def test_root_clsid_and_storage_clsid_change_both_digests():
    model = reference.canonical_model()
    digests = reference.reference_digests(model)

    mutated = reference.with_changed_storage_clsid(model)
    mutated_digests = reference.reference_digests(mutated)
    assert mutated_digests.stream_content != digests.stream_content
    assert mutated_digests.traditional != digests.traditional
    assert mutated_digests.prehash != digests.prehash

    root_mutated = copy.deepcopy(model)
    root_mutated.clsid = "99999999-9999-9999-9999-999999999999"
    root_digests = reference.reference_digests(root_mutated)
    assert root_digests.stream_content != digests.stream_content
    assert root_digests.prehash != digests.prehash


def test_expected_values_are_not_generated_by_the_code_under_test():
    """Guard the regression's provenance: the reference module stays independent."""
    source = pathlib.Path(reference.__file__).read_text(encoding="utf-8")
    assert "SignedMsiFile" not in source
    assert "get_fingerprint" not in source
    assert "_calculate_prehash" not in source

    digests = reference.reference_digests(reference.canonical_model())
    assert digests.stream_content.startswith(b"summary")
    assert b"PAIR-FIRST" in digests.stream_content
    assert b"PAIR-SECOND" in digests.stream_content
    assert b"unicode" in digests.stream_content
