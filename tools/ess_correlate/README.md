# Offline ESS signed-receipt correlation prototype

This is a forensic tool, not a mail client. It reconstructs which archived
CMS `SignerInfo` an S/MIME ESS signed receipt refers to, and keeps three
questions strictly separate:

| Level | Question answered | Inputs used |
| --- | --- | --- |
| 1. signature located | Does this receipt name exactly one SignerInfo? | raw ASN.1 fields only |
| 2. receipt trusted | Is the receipt genuine and bound to that signer's signed bytes? | level 1 + supplied receipt signature/trust status + `msgSigDigest` |
| 3. expected recipient confirmed | Did the expected recipient actually receive that signed message? | level 2 + supplied original-signature status + `receiptRequest` scope |

No cryptographic verification happens here. Signature and certificate
outcomes are read from an attestation JSON file. A missing entry is
`unknown`, and `unknown` never satisfies a level.

## Run it

```sh
.venv/bin/python -m tools.ess_correlate.cli --fixtures \
    --json /tmp/ess.json --markdown /tmp/ess.md
```

To analyse a real export, place base64/PEM `ContentInfo` objects in a
directory. Files named `receipt-*.pem`, `receipt_*.pem` or `receipt.pem`
are receipts; the prefix is stripped so the object name matches the
attestation key (`receipt-RECEIPT-B.pem` → `RECEIPT-B`).

```sh
.venv/bin/python -m tools.ess_correlate.cli \
    --archive /path/to/export \
    --attestations /path/to/attestations.json \
    --json report.json --markdown report.md
```

## Attestation file

```json
{
  "messages": {
    "MSG-B": {
      "layers": [
        {"signers": [
          {"signatureSha256": "…", "status": "valid", "reason": "offline verifier run 42"}
        ]}
      ]
    }
  },
  "receipts": {
    "RECEIPT-B": {
      "signatureStatus": "valid",
      "certificateTrust": "trusted",
      "signerNames": ["bob@example.com"]
    }
  }
}
```

Accepted status words: `valid`, `invalid`, `unknown` (aliases `verified`,
`failed`, `unverified`, `not_checked`). Accepted trust words: `trusted`,
`untrusted`, `unknown` (`distrusted`). Anything else raises rather than
being coerced to valid.

Message signers are addressed by `signatureSha256` because CMS encodes
`signerInfos` as a SET OF and DER canonical order can move signers between
exports. Positional lists also work when no hash is present.

`signerNames` on a receipt is the attested identity of the receipt signer. If
it is absent, the embedded certificate's e-mail address is shown for
reference but is not promoted to "attested identity"; level 3 then fails.

## What each field proves

- `Receipt.contentType` must equal the originator SignerInfo's `contentType`
  signed attribute (RFC 2634 §2.4 step 2.2). A mismatch means the receipt
  names a different content type, even if all other strings line up.
- `Receipt.signedContentIdentifier` must equal
  `receiptRequest.signedContentIdentifier` of the requesting SignerInfo
  (§2.4 step 2.3). When a signer has no `receiptRequest` but carries
  `contentIdentifier`, that identifier is used for the structural link and
  level 3 still fails with `not_requested`.
- `Receipt.originatorSignatureValue` must equal that SignerInfo's `signature`
  octets (§2.4 step 2.4).
- The receipt SignerInfo's `msgSigDigest` must equal a digest of the original
  SignerInfo's DER **SET OF** SignedAttributes (§2.4 step 5, §2.6 step 4),
  not merely of the body. This is what stops a `msgSigDigest` spliced from
  another message with the same body.
- The receipt SignerInfo's `messageDigest` must match the DER `Receipt`
  content carried in `eContent` (§2.6 step 5–6). Editing the Receipt after
  signing breaks it.

`signedAttrs` digests follow RFC 5652 §5.4: the IMPLICIT `[0]` tag is
replaced by the EXPLICIT `SET OF` tag, with the remaining octets unchanged.

## Why a body digest is not evidence

`MSG-A`, `MSG-B`, `MSG-RESIGN` and the inner layer of `MSG-FWD` all carry
byte-identical bodies (`38336f65…`). `RECEIPT-B` names only `MSG-B` because
`signedContentIdentifier` and `originatorSignatureValue` differ, and its
`msgSigDigest` hashes `MSG-B`'s SignedAttributes. Body equality would falsely
mark all four as delivered.

## Frozen answers from the fixture corpus

The generated `evidence-report.md` contains the full ledger. Key receipts
(level 1 / 2 / 3):

| Receipt | 1 | 2 | 3 | Decisive field |
| --- | --- | --- | --- | --- |
| `RECEIPT-B` | yes | yes | yes | all three fields match `MSG-B`; `msgSigDigest` hashes its SignedAttributes |
| `RECEIPT-SPLICED` | yes | no | no | `msgSigDigest` = `0x0e31…` = `MSG-A`'s SignedAttributes digest, not `MSG-B`'s `0xd089…` |
| `RECEIPT-NO-MSGDIGEST` | yes | no | no | `id-aa-msgSigDigest` absent; linkage cannot be proven |
| `RECEIPT-SIG-MISMATCH` | no | no | no | `originatorSignatureValue` starts `0x51…`; every candidate signature starts `0x50…` |
| `RECEIPT-MULTI-CAROL` | yes | yes | no | receipt is sound and binds to the second signer, but that signer carried no `receiptRequest`; its attestation is also `invalid` |
| `RECEIPT-NO-RR` | yes | yes | no | `MSG-NO-RR` has no `receiptRequest` anywhere |
| `RECEIPT-RESIGN` | yes | yes | no | original signer status is `unknown` |
| `RECEIPT-B-UNATTESTED` | yes | no | no | receipt status/trust omitted from the manifest |
| `RECEIPT-LIST-NONE` | yes | yes | no | `mlReceiptPolicy none` (RFC 2634 §2.3 step 1.2.1) |
| `RECEIPT-LIST-ADD` | yes | yes | yes | `dave@example.com` is in `receiptList` |
| `RECEIPT-LIST-UNEXPECTED` | yes | yes | no | `carol@example.com` is not in `receiptList` |
| `RECEIPT-LIST-FIRST` | yes | yes | no | `firstTierRecipients` after list expansion (§2.3 step 2.2.1) |

`MSG-FWD` is the forwarding control: its outer signer has no attestation and
stays `unknown`, while the inner `MSG-A` signature is still `valid` and its
SignedAttributes are byte-identical. A receipt can therefore succeed or
fail on the inner signer irrespective of the forwarder, and the forwarder's
status can never be substituted for the originator's.

## Schema correction in `rfc2634.py`

`ReceiptsFrom.receiptList`, `MLReceiptPolicy.insteadOf` and
`MLReceiptPolicy.inAdditionTo` are `SEQUENCE OF` values, but the published
module tagged them as `tagFormatSimple`. That makes the alternatives
unconstructable and mislabels the constructed encoding. The fix changes only
the tag format (three lines); the existing RFC 2634 test vector still passes.

## Known limits

- The fixtures' signature octets are placeholders; they prove structure and
  linkage logic, not that a real signature verifies. Real verification
  belongs in the attestation producer.
- Body `To`/`Cc` parsing is a convenience for the `allReceipts` scope. It is
  never treated as authoritative: the receipt signer's identity must be
  attested, and the header text is reported with its provenance.
- `EnvelopedData` layers are opaque and are recorded as such; encrypted
  inner signatures cannot be correlated offline without decryption.
- Receipts with more than one SignerInfo, or with a `receiptRequest` of their
  own, are flagged and cannot reach level 2.

## Interpretation rules enforced in code

- Multiple requesting signers must carry identical `receiptRequest` values (RFC 2634 §2.2.1). If verified requests differ, no receipt is valid; if only one signer requested, a receipt for another signer stops at level 2.
- `mlExpansionHistory` is read only from the topmost layer that carries it (§2.3 step 1). `none` blocks, `firstTierRecipients` plus expansion blocks; `insteadOf`/`inAdditionTo` change where a receipt is *sent*, not who may send it.
- Receipts are rejected if they carry a `receiptRequest` themselves (§2.2), if `Receipt.version` is not 1, or if the receipt SignedData has more than one SignerInfo.
- E-mail identity matching is case-insensitive and is labelled as normalization; other GeneralName forms are compared verbatim.
