# CRMF proof-of-possession validation example

This directory is a runnable integration example for RFC 4211 section 4.1
signature proof of possession, plus the regression material that proves a
validator actually binds the proof to the request.

It is not a production verifier.  Signature and password-based MAC checks are
pluggable callbacks; the example uses a fixed HMAC "signature" so the tests
are fast and deterministic.  Everything else is the real integration work.

## Why this exists

A `POPOSigningKey` is a signature by whoever holds a private key.  That is
not the same as evidence about a certificate request.  A validator that only
verifies the signature has authenticated *a key holder*.  It has not checked
that:

- the signed octets are the octets of *this* `CertRequest`;
- the `publicKey` inside `poposkInput` is the same key the template asks for;
- the template subject is the identity the sender signed;
- the sender identity is one the CA/RA actually established;
- an RA really approved *this* request when `raVerified` is used.

Each of those omissions is an attack below.

## Files

- `der.py` - hand-built DER for the octets RFC 4211 says are signed, and the
  fixed test signature/HMAC constructions.  Built independently of pyasn1 so
  an encoder bug cannot cancel itself out.
- `verifier.py` - reference validation and the `ValidatedPop` result type.
- `fixtures.py` - legitimate requests for every RFC branch and attack copies
  that differ in exactly one field.
- `demo.py` - prints the accept/reject decision for each fixture.

## Run it

```sh
python -m examples.crmf_pop.demo
```

Run the regressions:

```sh
python -m unittest tests.test_crmf_pop tests.test_crmf_pop_mutation
```

## The RFC 4211 section 4.1 cases

| Case | Template carries | `poposkInput` | Signed octets |
| --- | --- | --- | --- |
| 1, `publicKeyMAC` | subject and/or key | required | DER `POPOSigningKeyInput` |
| 2, `sender` | subject | required | DER `POPOSigningKeyInput` |
| 3, no input | subject and key | forbidden | DER `CertRequest` |

`poposkInput` must be present when the template lacks the subject *or* the
public key, and must be absent when it has both.  When present, its
`publicKey` must be byte-identical to the template's `publicKey`.

`authInfo.sender` is an authenticated identity only if the CA/RA established
it out of band; the `GeneralName` in the message is otherwise a claim.
`authInfo.publicKeyMAC` covers the DER public key only.  It does not bind any
template subject, so a subject alongside it is an unverified claim.

`raVerified` is reserved for an RA.  A requestor MUST NOT set it, so its
presence proves nothing on its own; accept it only in an explicit trusted-RA
context that names the exact `CertRequest`.

## Integration sketch

```python
from examples.crmf_pop import verifier

policy = verifier.VerificationPolicy(
    require_popo=True,
    require_bound_subject=True,
    require_authenticated_sender=True,
    allow_ra_verified=False,
)
issuer = verifier.IssuerContext(
    authenticated_subjects=frozenset({(subject_der, spki_der)}),
    authenticated_senders=frozenset({(sender_der, spki_der)}),
)

accepted = verifier.verify_cert_request(
    message,
    verify_signature=my_public_key_verify,        # (key, data, sig, alg) -> bool
    policy=policy,
    issuer=issuer,
    verify_public_key_mac=my_pbm_verify,          # (pbm, key, mac) -> bool
)
if accepted.subject_bound and accepted.subject_authenticated:
    issue_certificate(...)
```

`IssuerContext` takes `(identity, public key)` pairs from a prior
certificate or account lookup, never from the CRMF message.  Supplying only
the name from the message would let an attacker sign their own name.

## What the regressions demonstrate

- `tests/test_crmf_pop.py` - legitimate cases accepted, one-field attacks
  rejected, and `VerifySignatureOnlyDefectTest` shows that a validator which
  only checks signatures accepts the transplanted proofs.
- `tests/test_crmf_pop_mutation.py` - removes each binding rule from the
  verifier in turn and asserts the main suite fails, so the suite cannot
  silently lose coverage.
