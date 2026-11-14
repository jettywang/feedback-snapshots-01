"""EXPERIMENTAL Ed25519 + ML-DSA-65 composite signer.

.. warning::

    The ``CompositeKey`` and ``CompositeSigner`` types, their on-the-wire
    signature container and the key serialization format described in this
    module are **experimental and custom to securesystemslib**. They are not
    an interoperability standard, have no stable format guarantee and may
    change or be removed without notice. Do not rely on signatures produced
    here being verifiable by any other implementation.

A composite signature proves possession of *both* an Ed25519 private key and
an ML-DSA-65 private key. The two component signatures are not independent:
both are created over a single, unambiguous binding of

* the composite scheme identifier (domain separation),
* the two public keys in a fixed order (Ed25519 first, ML-DSA-65 second), and
* the signed message.

Consequently, dropping a component, swapping the component order, replacing
one of the keys, or trying to verify only one of the (faster) algorithms
cannot succeed. See ``docs/EXPERIMENTAL_COMPOSITE_SIGNER.md`` for the format
specification and a failure matrix.

The types reuse the existing pyca/cryptography backend (through
``CryptoSigner`` and ``SSlibKey``) and the standard ``Signer``/``Key``
extension mechanism. They are intentionally *not* registered by default:
an application opts in with :func:`register_composite_signer`.
"""

from __future__ import annotations

import logging
import os
import struct
import warnings
from typing import Any
from urllib import parse

from securesystemslib.exceptions import (
    KeyMismatchError,
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._constants import (
    ED25519,
    KEY_TYPE_ED25519,
    KEY_TYPE_MLDSA,
    MLDSA_65_1,
)
from securesystemslib.signer._crypto_signer import CryptoSigner
from securesystemslib.signer._key import (
    KEY_FOR_TYPE_AND_SCHEME,
    MLDSA_IMPORT_ERROR,
    Key,
    SSlibKey,
)
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    SecretsHandler,
    Signer,
)
from securesystemslib.signer._utils import compute_default_keyid

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )
except ImportError:  # pragma: no cover - import guarded like the other signers
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"

logger = logging.getLogger(__name__)

#: Experimental composite key type. The ``experimental-`` prefix makes the
#: non-standard, unstable nature visible in every serialized key.
KEY_TYPE_COMPOSITE = "experimental-composite"

#: Experimental composite scheme: Ed25519 and ML-DSA-65, both required.
COMPOSITE_ED25519_MLDSA65 = "experimental-ed25519-mldsa65"

#: Fixed component order: Ed25519 first, ML-DSA-65 second.
ED25519_LABEL = "ed25519"
MLDSA65_LABEL = "ml-dsa-65"

#: Raw public key and component signature sizes (bytes).
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
MLDSA65_PUBLIC_KEY_SIZE = 1952
MLDSA65_SIGNATURE_SIZE = 3309

#: Domain separator and container magic. Both are fixed length strings so that
#: every length-prefixed field in the formats below is unambiguous.
_DOMAIN_SEPARATOR = b"securesystemslib-experimental-composite-v1"
_CONTAINER_MAGIC = b"SSLIB-COMPOSIG-V1"

_EXPERIMENTAL_WARNING = (
    "CompositeKey/CompositeSigner use an experimental, custom format that is "
    "not an interoperability standard and may change without notice"
)


def _length_prefixed(data: bytes) -> bytes:
    """Prefix a byte string with its 4-byte big-endian unsigned length."""
    return struct.pack(">I", len(data)) + data


def _read_length_prefixed(
    buffer: bytes, offset: int, expected_size: int | None = None
) -> tuple[bytes, int]:
    """Read one length-prefixed field and validate its size.

    Raises ``VerificationError`` if the buffer is truncated or the field size
    does not match ``expected_size`` (when given).
    """
    if len(buffer) < offset + 4:
        raise VerificationError("truncated composite container: missing length")
    (size,) = struct.unpack(">I", buffer[offset : offset + 4])
    offset += 4
    if expected_size is not None and size != expected_size:
        raise VerificationError(
            f"unexpected component size {size}, expected {expected_size}"
        )
    if len(buffer) < offset + size:
        raise VerificationError("truncated composite container: missing component")
    return buffer[offset : offset + size], offset + size


def _composite_binding(
    ed25519_public: bytes, mldsa65_public: bytes, data: bytes
) -> bytes:
    """Return the canonical byte string both component keys sign.

    Layout (all lengths 4-byte big-endian unsigned)::

        domain-separator (fixed)
        len(scheme)      scheme
        len(ed25519-pub) ed25519-pub   (32 bytes, first position)
        len(mldsa65-pub) mldsa65-pub   (1952 bytes, second position)
        len(message)     message

    The fixed order and length prefixes make the binding unambiguous:
    reordering components, replacing a key, or altering the message changes it.
    """
    return b"".join(
        [
            _length_prefixed(_DOMAIN_SEPARATOR),
            _length_prefixed(COMPOSITE_ED25519_MLDSA65.encode("utf-8")),
            _length_prefixed(ed25519_public),
            _length_prefixed(mldsa65_public),
            _length_prefixed(data),
        ]
    )


def _raw_public_key(key: SSlibKey, expected_size: int) -> bytes:
    """Return the raw (uncompressed) public-key bytes of an SSlibKey."""
    crypto_key = key._crypto_key()
    raw = crypto_key.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    if len(raw) != expected_size:
        raise VerificationError(
            f"public key size {len(raw)} does not match expected {expected_size}"
        )
    return raw


class CompositeKey(Key):
    """Verifier for the experimental Ed25519 + ML-DSA-65 composite scheme.

    A ``CompositeKey`` bundles exactly two public keys, an Ed25519 key and an
    ML-DSA-65 key, in that fixed order. Verification only succeeds if *both*
    component signatures inside a composite signature container are valid over
    the composite binding of the message, the scheme identifier and the two
    public keys. There is no fallback to verifying a single component
    signature and no downgrade to an ordinary single-signature key.

    .. warning::
        Experimental, custom format. Not an interoperability standard; see the
        module docstring and ``docs/EXPERIMENTAL_COMPOSITE_SIGNER.md``.

    Args:
        keyid: Key identifier unique within the metadata the key is used in.
        ed25519_key: Public Ed25519 key (``keytype`` ``ed25519``).
        mldsa65_key: Public ML-DSA-65 key (``keytype`` ``ml-dsa``,
            scheme ``ml-dsa-65/1``).
        unrecognized_fields: Attributes not managed by securesystemslib.

    Raises:
        ValueError: One of the component keys has the wrong type or scheme.
        UnsupportedLibraryError: pyca/cryptography or its ML-DSA support is
            missing.
    """

    def __init__(
        self,
        keyid: str,
        ed25519_key: SSlibKey,
        mldsa65_key: SSlibKey,
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        warnings.warn(_EXPERIMENTAL_WARNING, FutureWarning, stacklevel=2)

        if MLDSA_IMPORT_ERROR:
            raise UnsupportedLibraryError(MLDSA_IMPORT_ERROR)
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if not (
            ed25519_key.keytype == KEY_TYPE_ED25519
            and ed25519_key.scheme == ED25519
        ):
            raise ValueError(
                "first component must be an ed25519 key "
                f"(got {ed25519_key.keytype}/{ed25519_key.scheme})"
            )
        if not (
            mldsa65_key.keytype == KEY_TYPE_MLDSA
            and mldsa65_key.scheme == MLDSA_65_1
        ):
            raise ValueError(
                "second component must be an ml-dsa-65/1 key "
                f"(got {mldsa65_key.keytype}/{mldsa65_key.scheme})"
            )

        # Validate raw sizes up front; raises VerificationError on mismatch.
        _raw_public_key(ed25519_key, ED25519_PUBLIC_KEY_SIZE)
        _raw_public_key(mldsa65_key, MLDSA65_PUBLIC_KEY_SIZE)

        self.ed25519_key = ed25519_key
        self.mldsa65_key = mldsa65_key
        keyval = {
            ED25519_LABEL: ed25519_key.to_dict(),
            MLDSA65_LABEL: mldsa65_key.to_dict(),
        }
        super().__init__(
            keyid,
            KEY_TYPE_COMPOSITE,
            COMPOSITE_ED25519_MLDSA65,
            keyval,
            unrecognized_fields,
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> CompositeKey:
        """Deserialize a composite key, strictly checking algorithm and size.

        Raises:
            ValueError: The keytype/scheme is not the experimental composite
                one, a component is missing, has the wrong algorithm, or its
                encoded public key has the wrong size.
            UnsupportedLibraryError: pyca/cryptography ML-DSA support missing.
        """
        keytype, scheme, keyval = cls._from_dict(dict(key_dict))

        if keytype != KEY_TYPE_COMPOSITE or scheme != COMPOSITE_ED25519_MLDSA65:
            raise ValueError(
                f"unsupported composite key {keytype}/{scheme}; refusing to "
                "downgrade to a single-signature key"
            )
        if not isinstance(keyval, dict) or set(keyval) != {
            ED25519_LABEL,
            MLDSA65_LABEL,
        }:
            raise ValueError(
                "composite keyval must contain exactly "
                f"'{ED25519_LABEL}' and '{MLDSA65_LABEL}' components"
            )

        ed25519_key = cls._load_component(
            keyval[ED25519_LABEL],
            KEY_TYPE_ED25519,
            ED25519,
            ED25519_PUBLIC_KEY_SIZE,
        )
        mldsa65_key = cls._load_component(
            keyval[MLDSA65_LABEL],
            KEY_TYPE_MLDSA,
            MLDSA_65_1,
            MLDSA65_PUBLIC_KEY_SIZE,
        )

        # Any fields beyond the base fields are treated as unrecognized.
        unrecognized = {
            k: v
            for k, v in key_dict.items()
            if k not in ("keytype", "scheme", "keyval")
        }
        return cls(keyid, ed25519_key, mldsa65_key, unrecognized)

    @staticmethod
    def _load_component(
        component: Any,
        keytype: str,
        scheme: str,
        expected_size: int,
    ) -> SSlibKey:
        """Load and strictly validate one component key."""
        if not isinstance(component, dict):
            raise ValueError(f"component {keytype} must be a key dict")

        if component.get("keytype") != keytype or component.get("scheme") != scheme:
            raise ValueError(
                f"expected component {keytype}/{scheme}, got "
                f"{component.get('keytype')}/{component.get('scheme')}"
            )

        component_keyval = component.get("keyval")
        if not isinstance(component_keyval, dict) or not isinstance(
            component_keyval.get("public"), str
        ):
            raise ValueError(f"component {keytype} is missing a string 'public'")

        sub_keyid = component.get("keyid")
        if not isinstance(sub_keyid, str) or not sub_keyid:
            # Synthesize the canonical default keyid so the stored key dict is
            # self-contained and round-trips.
            sub_keyid = compute_default_keyid(
                keytype, scheme, {"public": component_keyval["public"]}
            )

        key = SSlibKey.from_dict(
            sub_keyid,
            {
                "keytype": keytype,
                "scheme": scheme,
                "keyval": dict(component_keyval),
            },
        )
        # Size/algorithm check against the actual decoded key material.
        _raw_public_key(key, expected_size)
        return key

    def to_dict(self) -> dict[str, Any]:
        """Return the serialization dict (component keys in fixed order)."""
        return self._to_dict()

    def _component_public_bytes(self) -> tuple[bytes, bytes]:
        ed25519_public = _raw_public_key(self.ed25519_key, ED25519_PUBLIC_KEY_SIZE)
        mldsa65_public = _raw_public_key(self.mldsa65_key, MLDSA65_PUBLIC_KEY_SIZE)
        return ed25519_public, mldsa65_public

    def pack_signature(
        self, ed25519_signature: bytes, mldsa65_signature: bytes
    ) -> bytes:
        """Serialize two component signatures into the composite container.

        Layout (all lengths 4-byte big-endian unsigned)::

            magic (fixed)
            len(ed25519-sig) ed25519-sig   (64 bytes, first position)
            len(mldsa65-sig) mldsa65-sig   (3309 bytes, second position)
        """
        return b"".join(
            [
                _length_prefixed(_CONTAINER_MAGIC),
                _length_prefixed(ed25519_signature),
                _length_prefixed(mldsa65_signature),
            ]
        )

    def unpack_signature(self, signature: bytes) -> tuple[bytes, bytes]:
        """Parse the composite container, validating magic and component sizes.

        Raises:
            VerificationError: The container is malformed, truncated, has the
                wrong magic, or a component of unexpected size.
        """
        magic, offset = _read_length_prefixed(signature, 0)
        if magic != _CONTAINER_MAGIC:
            raise VerificationError("not a composite signature container")
        ed25519_signature, offset = _read_length_prefixed(
            signature, offset, ED25519_SIGNATURE_SIZE
        )
        mldsa65_signature, offset = _read_length_prefixed(
            signature, offset, MLDSA65_SIGNATURE_SIZE
        )
        if offset != len(signature):
            raise VerificationError("trailing bytes in composite container")
        return ed25519_signature, mldsa65_signature

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Verify both component signatures; raise if either one fails.

        A bare Ed25519 or ML-DSA-65 signature is rejected because it is not a
        composite container, so verification can never silently downgrade to
        the faster single algorithm.

        Raises:
            UnverifiedSignatureError: At least one component signature is
                invalid or the container does not match this key.
            VerificationError: The signature container is malformed.
        """
        try:
            if signature.keyid != self.keyid:
                raise VerificationError(
                    f"keyid mismatch: key id {self.keyid} != signature keyid "
                    f"{signature.keyid}"
                )

            ed25519_signature, mldsa65_signature = self.unpack_signature(
                bytes.fromhex(signature.signature)
            )

            ed25519_public, mldsa65_public = self._component_public_bytes()
            binding = _composite_binding(ed25519_public, mldsa65_public, data)

            # Both components must verify against the same binding. Reuse the
            # existing backend via SSlibKey, including ML-DSA TAP 21 pre-hashing.
            self.ed25519_key.verify_signature(
                Signature(self.ed25519_key.keyid, ed25519_signature.hex()),
                binding,
            )
            self.mldsa65_key.verify_signature(
                Signature(self.mldsa65_key.keyid, mldsa65_signature.hex()),
                binding,
            )

        except UnverifiedSignatureError as e:
            raise UnverifiedSignatureError(
                f"Failed to verify composite signature by {self.keyid}"
            ) from e

        except Exception as e:
            logger.info("Composite key %s failed to verify: %s", self.keyid, e)
            raise VerificationError(
                f"Unknown failure to verify composite signature by {self.keyid}"
            ) from e


class CompositeSigner(Signer):
    """Signer for the experimental Ed25519 + ML-DSA-65 composite scheme.

    Holds two :class:`CryptoSigner` instances and signs the composite binding
    with both private keys on every :meth:`sign` call.

    .. warning::
        Experimental, custom format. Not an interoperability standard.

    The private key URI scheme is
    ``composite2:?ed25519=<PATH>&ml-dsa-65=<PATH>`` where both paths point to
    PEM-encoded PKCS#8 private key files (resolved like ``CryptoSigner``'s
    ``file2:`` URIs, including ``CRYPTO_SIGNER_PATH_PREFIX``).
    """

    SCHEME = "composite2"

    def __init__(
        self,
        ed25519_signer: CryptoSigner,
        mldsa65_signer: CryptoSigner,
        public_key: CompositeKey | None = None,
    ):
        warnings.warn(_EXPERIMENTAL_WARNING, FutureWarning, stacklevel=2)

        if MLDSA_IMPORT_ERROR:
            raise UnsupportedLibraryError(MLDSA_IMPORT_ERROR)

        if not (
            ed25519_signer.public_key.keytype == KEY_TYPE_ED25519
            and ed25519_signer.public_key.scheme == ED25519
        ):
            raise ValueError("first signer must be an ed25519 CryptoSigner")
        if not (
            mldsa65_signer.public_key.keytype == KEY_TYPE_MLDSA
            and mldsa65_signer.public_key.scheme == MLDSA_65_1
        ):
            raise ValueError("second signer must be an ml-dsa-65/1 CryptoSigner")

        if public_key is None:
            public_key = CompositeKey(
                compute_default_keyid(
                    KEY_TYPE_COMPOSITE,
                    COMPOSITE_ED25519_MLDSA65,
                    {
                        ED25519_LABEL: ed25519_signer.public_key.to_dict(),
                        MLDSA65_LABEL: mldsa65_signer.public_key.to_dict(),
                    },
                ),
                ed25519_signer.public_key,
                mldsa65_signer.public_key,
            )
        elif (
            public_key.ed25519_key != ed25519_signer.public_key
            or public_key.mldsa65_key != mldsa65_signer.public_key
        ):
            raise KeyMismatchError(
                "CompositeSigner private keys do not match the public composite key"
            )

        self._ed25519_signer = ed25519_signer
        self._mldsa65_signer = mldsa65_signer
        self._public_key = public_key

    @property
    def public_key(self) -> CompositeKey:
        return self._public_key

    @classmethod
    def generate(cls) -> CompositeSigner:
        """Generate a fresh Ed25519 + ML-DSA-65 composite signer."""
        if MLDSA_IMPORT_ERROR:
            raise UnsupportedLibraryError(MLDSA_IMPORT_ERROR)
        return cls(CryptoSigner.generate_ed25519(), CryptoSigner.generate_mldsa())

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> CompositeSigner:
        """Load both component private keys from a ``composite2:`` URI.

        Raises:
            ValueError: The URI scheme or query parameters are invalid or the
                public key is not a :class:`CompositeKey`.
            UnsupportedLibraryError: pyca/cryptography ML-DSA support missing.
        """
        if MLDSA_IMPORT_ERROR:
            raise UnsupportedLibraryError(MLDSA_IMPORT_ERROR)
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)
        if not isinstance(public_key, CompositeKey):
            raise ValueError(
                f"expected CompositeKey for {priv_key_uri}, got {type(public_key)}"
            )

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"CompositeSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))
        if set(params) != {ED25519_LABEL, MLDSA65_LABEL}:
            raise ValueError(
                f"URI must provide exactly '{ED25519_LABEL}' and "
                f"'{MLDSA65_LABEL}' path parameters"
            )

        prefix = os.environ.get(CryptoSigner.PREFIX_ENV_VAR)
        component_keys = [
            (params[ED25519_LABEL], public_key.ed25519_key),
            (params[MLDSA65_LABEL], public_key.mldsa65_key),
        ]
        component_signers: list[CryptoSigner] = []
        for path, component_key in component_keys:
            resolved = os.path.join(prefix, path) if prefix else path
            with open(resolved, "rb") as f:
                private_pem = f.read()
            private_key = load_pem_private_key(private_pem, None)
            component_signers.append(CryptoSigner(private_key, component_key))

        return cls(
            component_signers[0],
            component_signers[1],
            public_key,
        )

    def sign(self, payload: bytes) -> Signature:
        """Sign the composite binding with both component keys.

        Returns a :class:`Signature` whose ``signature`` field is the hex
        encoded composite container and whose ``keyid`` is the composite
        key's identifier.
        """
        ed25519_public, mldsa65_public = self._public_key._component_public_bytes()
        binding = _composite_binding(ed25519_public, mldsa65_public, payload)

        ed25519_signature = bytes.fromhex(
            self._ed25519_signer.sign(binding).signature
        )
        mldsa65_signature = bytes.fromhex(
            self._mldsa65_signer.sign(binding).signature
        )

        container = self._public_key.pack_signature(
            ed25519_signature, mldsa65_signature
        )
        return Signature(self._public_key.keyid, container.hex())


def register_composite_signer() -> None:
    """Opt in to the experimental composite key and signer.

    Registers :class:`CompositeKey` in
    ``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME`` (so
    ``Key.from_dict`` can load it) and :class:`CompositeSigner` in
    ``SIGNER_FOR_URI_SCHEME`` (so ``Signer.from_priv_key_uri`` resolves
    ``composite2:`` URIs). Registration is idempotent.

    The types are intentionally not registered on package import: the format
    is experimental and its strict, self-describing validation must not be
    confused with the stable built-in key types.
    """
    KEY_FOR_TYPE_AND_SCHEME[
        (KEY_TYPE_COMPOSITE, COMPOSITE_ED25519_MLDSA65)
    ] = CompositeKey
    SIGNER_FOR_URI_SCHEME[CompositeSigner.SCHEME] = CompositeSigner
