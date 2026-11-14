Pruning a Certificate for Signature Verification
=================================================

Sometimes an archive export must carry only the OpenPGP public material
needed to verify one specific signature, without disclosing unrelated User
IDs, email addresses, or photo attributes that happen to be present on the
signer's certificate.

:py:func:`~pgpy.prune_certificate` builds a minimal, public-only
certificate for exactly that purpose. It never re-signs or re-issues
packets: the output is assembled solely from copies of packets that already
exist on the source key, so every retained signature stays byte-identical.

What is retained

* The primary public key packet.
* The actual signing key: the primary key itself, or exactly the signing
  subkey, together with its subkey binding signature and any embedded
  primary-key binding signature (type 0x19).
* Validity-affecting evidence: key and subkey revocation signatures,
  direct-key signatures, and certification revocations attached to a User
  ID that has to be retained. Revocation packets are never dropped to make
  a revoked key look usable.

What is removed

* Unrelated User IDs and all User Attribute (photo) packets.
* Third-party certifications that do not affect this verification.
* Subkeys that did not create the target signature (for example
  encryption-only subkeys).

If a primary key's expiration is only asserted by a User ID
self-signature, one User ID must be kept to preserve the original validity
conclusion. The returned :py:class:`~pgpy.PruneReport` records that
disclosure explicitly instead of synthesizing a certificate that would
verify differently.

Library usage::

    from pgpy import PGPKey, PGPSignature, prune_certificate, audit_removal

    key = PGPKey.from_file('signer.pub.asc')[0]
    signature = PGPSignature.from_file('data.tar.gz.sig')
    subject = open('data.tar.gz', 'rb').read()

    pruned, report = prune_certificate(key, signature, subject)

    # the verification conclusion before and after pruning is identical
    assert bool(key.verify(subject, signature)) == report.verification_after[0]

    # unrelated identity material is demonstrably gone
    print(audit_removal(key, pruned))

    # export the armored, public-only certificate
    open('signer.minimal.asc', 'w').write(str(pruned))
    print(report.format_text())

Private keys are accepted as input but are reduced to their public half
first; the output is asserted to contain no Secret-Key or Secret-Subkey
packets. The source key object is never modified.

Command line::

    python -m pgpy --signature data.tar.gz.sig \
                   --subject data.tar.gz \
                   --candidate signer.pub.asc \
                   --output signer.minimal.asc \
                   --report pruning-report.txt

Multiple ``--candidate`` files may be supplied; the first certificate that
contains the signature issuer is used and the rest are reported as skipped.
