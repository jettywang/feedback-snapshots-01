# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Observation packages and their offline verification.

An :class:`ObservationPackage` bundles everything a forensics analyst needs to
judge one piece of metadata without any network access:

* the observed envelope bytes (traditional ``Metadata`` JSON or a DSSE
  ``SimpleEnvelope``),
* the trusted root bytes that the analysis must start from,
* every intermediate root version between the trust anchor and the root that
  actually authorizes the observed role,
* the delegated targets metadata needed to follow a delegation chain.

Verification deliberately mirrors the two signature semantics of python-tuf:

* traditional metadata signs the canonical JSON serialization of the payload
  (:attr:`tuf.api.metadata.Metadata.signed_bytes`),
* a SimpleEnvelope signs its pre-auth encoding
  (:meth:`tuf.api.dsse.SimpleEnvelope.pae`).

A failed verification never raises: it is recorded on the returned verdict so
that "no usable evidence" stays separate from "fork refuted" and "fork proven".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from tuf.api._payload import Root, Signed, Targets, VerificationResult
from tuf.api.dsse import SimpleEnvelope
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import Metadata
from tuf.api.serialization import DeserializationError
from tuf.api.serialization.json import CanonicalJSONSerializer
from tuf.forensics.evidence import (
    AuthorizationHop,
    AuthorizationPath,
    EvidenceSummary,
    ObservationVerdict,
    RootChainHop,
    SignatureEvidence,
)
from tuf.forensics.exceptions import ObservationError
from tuf.ngclient.config import EnvelopeType

if TYPE_CHECKING:
    from securesystemslib.signer import Signature

    from tuf.api._payload import _DelegatorMixin


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ParsedEnvelope:
    """Deserialized envelope and its signature-relevant byte strings.

    Attributes:
        envelope_type: Metadata or SimpleEnvelope semantics.
        signed: Deserialized payload.
        payload_bytes: Raw embedded JSON payload bytes.
        signed_bytes: Bytes that are actually signed (canonical JSON or PAE).
        signatures: Keyid to signature mapping from the envelope.
        raw: Original envelope bytes.
    """

    envelope_type: EnvelopeType
    signed: Signed
    payload_bytes: bytes
    signed_bytes: bytes
    signatures: dict[str, Signature]
    raw: bytes

    @property
    def role(self) -> str:
        return self.signed.type

    @property
    def version(self) -> int:
        return self.signed.version


def parse_envelope(data: bytes, envelope_type: EnvelopeType) -> ParsedEnvelope:
    """Deserialize one envelope according to the configured signature model."""
    if envelope_type is EnvelopeType.SIMPLE:
        try:
            envelope = SimpleEnvelope[Signed].from_bytes(data)
        except DeserializationError as e:
            raise ObservationError(
                "Could not parse SimpleEnvelope bytes"
            ) from e
        if envelope.payload_type != SimpleEnvelope.DEFAULT_PAYLOAD_TYPE:
            raise ObservationError(
                f"Unexpected payload type '{envelope.payload_type}', expected "
                f"'{SimpleEnvelope.DEFAULT_PAYLOAD_TYPE}'"
            )
        try:
            signed = envelope.get_signed()
        except DeserializationError as e:
            raise ObservationError(
                "Could not parse SimpleEnvelope payload"
            ) from e
        return ParsedEnvelope(
            envelope_type,
            signed,
            envelope.payload,
            envelope.pae(),
            dict(envelope.signatures),
            data,
        )

    try:
        metadata = Metadata[Signed].from_bytes(data)
    except DeserializationError as e:
        raise ObservationError("Could not parse Metadata bytes") from e
    return ParsedEnvelope(
        envelope_type,
        metadata.signed,
        metadata.signed_bytes,
        metadata.signed_bytes,
        dict(metadata.signatures),
        data,
    )


class ObservationPackage:
    """Self-contained evidence for one observed metadata envelope.

    Args:
        envelope: Raw observed metadata bytes, either traditional Metadata JSON
            or a DSSE SimpleEnvelope according to ``envelope_type``.
        trust_anchor: Trusted root bytes that are the explicit starting point
            of trust. The anchor is only verified against itself.
        role_name: Name of the observed role. Defaults to the payload
            ``_type``, which is correct for root, timestamp, snapshot and the
            top-level targets role. A delegated targets role must be named
            explicitly because targets payloads do not embed their role name.
        envelope_type: Signature semantics of the package's envelopes.
        root_chain: Additional root bytes in ascending version order. Each
            entry must be one version newer than the previous root; the last
            entry is the root that authorizes the observed role. May be empty
            when the trust anchor is also the authorizing root.
        delegations: Raw delegated targets bytes keyed by role name, needed to
            reach a delegated targets role.
        delegation_chain: Role names on the delegation path from top-level
            targets to (but excluding) the observed role, in order.
    """

    def __init__(
        self,
        envelope: bytes,
        trust_anchor: bytes,
        *,
        role_name: str | None = None,
        envelope_type: EnvelopeType = EnvelopeType.METADATA,
        root_chain: list[bytes] | None = None,
        delegations: dict[str, bytes] | None = None,
        delegation_chain: list[str] | None = None,
    ):
        """Initialize the observation package.

        Args:
            envelope: Raw observed metadata bytes.
            trust_anchor: Trusted root bytes forming the starting trust root.
            role_name: Name of the observed role. Defaults to the payload
                ``_type``, which is correct for root, timestamp, snapshot and
                the top-level targets role. A delegated targets role must be
                named explicitly because targets payloads do not embed their
                own role name.
            envelope_type: Signature semantics of every envelope in the
                package.
            root_chain: Intermediate root bytes in ascending version order;
                the last entry is the root authorizing the observed role.
            delegations: Raw delegated targets bytes keyed by role name.
            delegation_chain: Role names on the delegation path from the
                top-level targets role to (but excluding) the observed role,
                in order.
        """
        self.envelope_type = envelope_type
        self._anchor_raw = trust_anchor
        self._chain_raw = list(root_chain or [])
        self._delegation_raw = dict(delegations or {})
        self.delegation_chain = list(delegation_chain or [])

        self.trust_anchor = self._parse_root(trust_anchor)
        self.root_chain = [self._parse_root(data) for data in self._chain_raw]
        self.delegations: dict[str, Targets] = {}
        for delegated_name, data in self._delegation_raw.items():
            parsed = parse_envelope(data, envelope_type)
            if not isinstance(parsed.signed, Targets):
                raise ObservationError(
                    f"Delegation material for '{delegated_name}' is not "
                    "Targets"
                )
            self.delegations[delegated_name] = parsed.signed

        self._parsed = parse_envelope(envelope, envelope_type)
        self._role_name = role_name or self._parsed.role
        self._validate_delegation_material()

    def _parse_root(self, data: bytes) -> Root:
        parsed = parse_envelope(data, self.envelope_type)
        if not isinstance(parsed.signed, Root):
            raise ObservationError("Root material does not contain a Root")
        return parsed.signed

    @property
    def role(self) -> str:
        """Role name of the observed metadata."""
        return self._role_name

    @property
    def version(self) -> int:
        """Version of the observed metadata."""
        return self._parsed.version

    @property
    def final_root(self) -> Root:
        """Newest available root, which authorizes the observed role."""
        if self.root_chain:
            return self.root_chain[-1]
        return self.trust_anchor

    @property
    def raw_envelope(self) -> bytes:
        """Original bytes of the observed envelope."""
        return self._parsed.raw

    def canonical_payload(self) -> bytes:
        """Canonical JSON bytes of the signed payload.

        The same canonical bytes are produced regardless of envelope type,
        JSON whitespace or signature ordering, which makes them the basis
        for deciding whether two observations carry the same content.
        """
        serializer = CanonicalJSONSerializer()
        return serializer.serialize(self._parsed.signed)

    def payload_dict(self) -> dict[str, Any]:
        """Dictionary form of the signed payload, for field-level diffing."""
        return self._parsed.signed.to_dict()

    def summary(self) -> EvidenceSummary:
        """Compute the raw evidence summary of the observed envelope."""
        parsed = self._parsed
        return EvidenceSummary(
            envelope_type=parsed.envelope_type,
            role=self._role_name,
            version=parsed.version,
            envelope_sha256=_sha256(parsed.raw),
            signed_bytes_sha256=_sha256(parsed.signed_bytes),
            payload_sha256=_sha256(parsed.payload_bytes),
            payload_length=len(parsed.payload_bytes),
            signature_keyids=list(parsed.signatures),
        )

    def verify(self) -> ObservationVerdict:
        """Authenticate the package and reconstruct its authorization path.

        Returns a verdict that always carries the evidence summary and the
        most complete authorization path the material supports. Verification
        failures are accumulated in ``verdict.errors`` instead of raising.
        """
        errors: list[str] = []
        root_hops = self._verify_root_chain(errors)
        role_path = self._verify_role_path(errors)
        return ObservationVerdict(
            summary=self.summary(),
            authorization_path=AuthorizationPath(root_hops, role_path),
            errors=errors,
        )

    def _verify_root_chain(
        self, errors: list[str]
    ) -> list[RootChainHop]:
        hops: list[RootChainHop] = []
        raws = [self._anchor_raw, *self._chain_raw]
        roots = [self.trust_anchor, *self.root_chain]

        previous: Root | None = None
        previous_raw: bytes | None = None
        for root, raw in zip(roots, raws, strict=True):
            if previous is None or previous_raw is None:
                expected_previous = root
                previous_version = root.version
            else:
                expected_previous = previous
                previous_version = previous.version
                if root.version != previous.version + 1:
                    errors.append(
                        f"Non-sequential root chain: v{previous_version} is "
                        f"not followed by v{previous_version + 1} "
                        f"(got v{root.version})"
                    )

            parsed = parse_envelope(raw, self.envelope_type)
            previous_hop = self._hop(
                expected_previous,
                Root.type,
                Root.type,
                expected_previous.version,
                parsed.signed_bytes,
                parsed.signatures,
                errors,
            )
            self_hop = self._hop(
                root,
                Root.type,
                Root.type,
                root.version,
                parsed.signed_bytes,
                parsed.signatures,
                errors,
            )
            hops.append(
                RootChainHop(
                    root_version=root.version,
                    previous_version=previous_version,
                    signed_by_previous=previous_hop,
                    signed_by_self=self_hop,
                )
            )
            previous = root
            previous_raw = raw
        return hops

    def _validate_delegation_material(self) -> None:
        payload_type = self._parsed.signed.type
        if payload_type != Targets.type:
            if self.delegation_chain or self._delegation_raw:
                raise ObservationError(
                    f"Role '{self._role_name}' cannot have delegation "
                    "material"
                )
            return

        if self._role_name == Targets.type:
            if self.delegation_chain or self._delegation_raw:
                raise ObservationError(
                    "Top-level targets role cannot have delegation material"
                )
            return

        expected_chain = [
            Targets.type,
            *self.delegation_chain,
            self._role_name,
        ]
        if len(set(expected_chain)) != len(expected_chain):
            raise ObservationError(
                "Delegation chain contains duplicate role names"
            )
        missing = [
            name
            for name in expected_chain[:-1]
            if name not in self._delegation_raw
        ]
        if missing:
            raise ObservationError(
                "Missing delegation metadata for: " + ", ".join(missing)
            )
        unexpected = set(self._delegation_raw) - set(expected_chain[:-1])
        if unexpected:
            raise ObservationError(
                "Unused delegation metadata for: "
                + ", ".join(sorted(unexpected))
            )

    def _verify_role_path(
        self, errors: list[str]
    ) -> list[AuthorizationHop]:
        if self._parsed.signed.type == Root.type:
            return []

        top_level_roles = {"timestamp", "snapshot", Targets.type}
        if self._role_name in top_level_roles:
            chain_roles = [self._role_name]
        else:
            chain_roles = [
                Targets.type,
                *self.delegation_chain,
                self._role_name,
            ]

        hops: list[AuthorizationHop] = []
        delegator: _DelegatorMixin = self.final_root
        delegator_name = Root.type

        for role_name in chain_roles:
            if role_name == self._role_name:
                payload = self._parsed.signed_bytes
                signatures = self._parsed.signatures
            else:
                parsed = parse_envelope(
                    self._delegation_raw[role_name], self.envelope_type
                )
                payload = parsed.signed_bytes
                signatures = parsed.signatures

            try:
                hop = self._hop(
                    delegator,
                    role_name,
                    delegator_name,
                    self._delegator_version(delegator_name),
                    payload,
                    signatures,
                    errors,
                )
            except ObservationError as e:
                errors.append(str(e))
                return hops
            hops.append(hop)

            if role_name != self._role_name:
                delegator = self.delegations[role_name]
                delegator_name = role_name
        return hops

    def _delegator_version(self, delegator_name: str) -> int:
        if delegator_name == Root.type:
            return self.final_root.version
        delegator = self.delegations.get(delegator_name)
        if delegator is None:
            raise ObservationError(f"Unknown delegator '{delegator_name}'")
        return delegator.version

    def _hop(
        self,
        delegator: _DelegatorMixin,
        role_name: str,
        delegator_name: str,
        delegator_version: int,
        payload: bytes,
        signatures: dict[str, Signature],
        errors: list[str],
    ) -> AuthorizationHop:
        try:
            role = delegator.get_delegated_role(role_name)
        except ValueError as e:
            raise ObservationError(
                f"Role '{role_name}' is not delegated by "
                f"'{delegator_name}'"
            ) from e

        try:
            result: VerificationResult = delegator.get_verification_result(
                role_name, payload, signatures
            )
        except (ValueError, UnsignedMetadataError) as e:
            raise ObservationError(str(e)) from e

        evidence: list[SignatureEvidence] = []
        for keyid in role.keyids:
            try:
                key = delegator.get_key(keyid)
            except ValueError:
                errors.append(
                    f"No key material for keyid {keyid} in "
                    f"'{delegator_name}'"
                )
                continue
            valid = keyid in result.signed
            if not valid and keyid not in result.unsigned:
                continue
            evidence.append(
                SignatureEvidence(
                    keyid=keyid,
                    keytype=key.keytype,
                    scheme=key.scheme,
                    valid=valid,
                )
            )

        hop = AuthorizationHop(
            delegator=delegator_name,
            role=role_name,
            delegator_version=delegator_version,
            threshold=role.threshold,
            signatures=evidence,
        )
        if not hop.authorized:
            errors.append(
                f"'{role_name}' authorization failed: "
                f"{len(hop.valid_keyids)}/{hop.threshold} required "
                "signatures valid"
            )
        return hop
