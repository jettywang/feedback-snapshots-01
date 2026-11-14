# S/MIME ESS signed-receipt correlation report

All signature and certificate-status outcomes come from explicit attestation input. This report never performs cryptographic verification and never upgrades an unknown status.

## Identical body digests
| body SHA-256 | messages |
|---|---|
| 38336f65828267f3254fe7768a1c291758eb512aff06993aa491035276c02087 | MSG-A, MSG-B, MSG-RESIGN, MSG-FWD |
| 860f19b7472bb2d2ea4e49813b7af1117cc4d85c3fe8aac031e09b9766fb4558 | MSG-LIST-NONE, MSG-LIST-ADD, MSG-LIST-FIRST |

## Receipts: three cumulative levels
| receipt | matched message | matched signer | L1 signature located | L2 receipt trusted | L3 recipient confirmed |
|---|---|---|---|---|---|
| RECEIPT-B | MSG-B | layers[0].signerInfos[0] | yes | yes | yes |
| RECEIPT-SPLICED | MSG-B | layers[0].signerInfos[0] | yes | no | no |
| RECEIPT-NO-MSGDIGEST | MSG-B | layers[0].signerInfos[0] | yes | no | no |
| RECEIPT-SIG-MISMATCH | — | — | no | no | no |
| RECEIPT-MULTI-CAROL | MSG-MULTI | layers[0].signerInfos[0] | yes | yes | no |
| RECEIPT-NO-RR | MSG-NO-RR | layers[0].signerInfos[0] | yes | yes | no |
| RECEIPT-RESIGN | MSG-RESIGN | layers[0].signerInfos[0] | yes | yes | no |
| RECEIPT-B-UNATTESTED | MSG-B | layers[0].signerInfos[0] | yes | no | no |
| RECEIPT-LIST-NONE | MSG-LIST-NONE | layers[1].signerInfos[0] | yes | yes | no |
| RECEIPT-LIST-ADD | MSG-LIST-ADD | layers[1].signerInfos[0] | yes | yes | yes |
| RECEIPT-LIST-UNEXPECTED | MSG-LIST-ADD | layers[1].signerInfos[0] | yes | yes | no |
| RECEIPT-LIST-FIRST | MSG-LIST-FIRST | layers[1].signerInfos[0] | yes | yes | no |

## Field-by-field linkage
| receipt | Receipt.contentType = signer contentType | signedContentIdentifier = request/identifier | originatorSignatureValue = SignerInfo.signature | receipt msgSigDigest | recomputed SignedAttributes digest | match |
|---|---|---|---|---|---|---|
| RECEIPT-B | yes | yes | yes | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | yes |
| RECEIPT-SPLICED | yes | yes | yes | 0x0e316a120f8ff6d459d3a88b577128326d71d42cff71b8c462ef0fc27eaea22d | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | no |
| RECEIPT-NO-MSGDIGEST | yes | yes | yes | — | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | no |
| RECEIPT-SIG-MISMATCH | ? | ? | ? | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | — | ? |
| RECEIPT-MULTI-CAROL | yes | yes | yes | 0x1ac4bba0b302e6804af9d0bd6cdadf10e6e35ae70629b623299c314a007d7144 | 0x1ac4bba0b302e6804af9d0bd6cdadf10e6e35ae70629b623299c314a007d7144 | yes |
| RECEIPT-NO-RR | yes | yes | yes | 0x5537dabcb4f208a7e7c74b54f412638a6c8be7e13f3fc1bd6d63192f18e32b74 | 0x5537dabcb4f208a7e7c74b54f412638a6c8be7e13f3fc1bd6d63192f18e32b74 | yes |
| RECEIPT-RESIGN | yes | yes | yes | 0xd7fd38e5885133e6191cf622e453d8b55803a50490a0cf20d832f3c00db5a681 | 0xd7fd38e5885133e6191cf622e453d8b55803a50490a0cf20d832f3c00db5a681 | yes |
| RECEIPT-B-UNATTESTED | yes | yes | yes | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08 | yes |
| RECEIPT-LIST-NONE | yes | yes | yes | 0xbad2833ca47ae10af78a7fa36d32d0aeaa01590e4b2d457aa1683651f8acc42e | 0xbad2833ca47ae10af78a7fa36d32d0aeaa01590e4b2d457aa1683651f8acc42e | yes |
| RECEIPT-LIST-ADD | yes | yes | yes | 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce | 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce | yes |
| RECEIPT-LIST-UNEXPECTED | yes | yes | yes | 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce | 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce | yes |
| RECEIPT-LIST-FIRST | yes | yes | yes | 0xe27eababa6aa2e32c54539a79947198a1e36974727c6bff6ee7b172fc20bce29 | 0xe27eababa6aa2e32c54539a79947198a1e36974727c6bff6ee7b172fc20bce29 | yes |

## Field evidence ledger
### RECEIPT-B

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d5052494d4152592d42; `Receipt.originatorSignatureValue` = 0x5052494d4152592d5349474e41545552452d42
- receipt SignerInfo: `messageDigest` = 0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4; `msgSigDigest` = 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d5052494d4152592d42` vs expected `0x5343492d5052494d4152592d42` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x5052494d4152592d5349474e41545552452d42` vs expected `0x5052494d4152592d5349474e41545552452d42` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; computed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; computed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=confirmed; identityBasis=attestation signerNames; matched=rfc822Name:bob@example.com; reasons=receipt signer matches an archived To/Cc recipient and allReceipts permits that recipient to respond
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'status': 'absent', 'detail': '最外层 SignedData 没有任何签名者携带 mlExpansionHistory'}`

### RECEIPT-SPLICED

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d5052494d4152592d42; `Receipt.originatorSignatureValue` = 0x5052494d4152592d5349474e41545552452d42
- receipt SignerInfo: `messageDigest` = 0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4; `msgSigDigest` = 0x0e316a120f8ff6d459d3a88b577128326d71d42cff71b8c462ef0fc27eaea22d; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = dave@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d5052494d4152592d42` vs expected `0x5343492d5052494d4152592d42` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x5052494d4152592d5349474e41545552452d42` vs expected `0x5052494d4152592d5349474e41545552452d42` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; computed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0x0e316a120f8ff6d459d3a88b577128326d71d42cff71b8c462ef0fc27eaea22d`; computed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; algorithm `2.16.840.1.101.3.4.2.1`; ok=no
- L3 recipient evaluation: status=unconfirmed; identityBasis=attestation signerNames; matched=—; reasons=回执签名者不在归档正文的 To/Cc 收件人中，无法导出预期收件人确认
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'status': 'absent', 'detail': '最外层 SignedData 没有任何签名者携带 mlExpansionHistory'}`

### RECEIPT-NO-MSGDIGEST

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d5052494d4152592d42; `Receipt.originatorSignatureValue` = 0x5052494d4152592d5349474e41545552452d42
- receipt SignerInfo: `messageDigest` = 0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4; `msgSigDigest` = None; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d5052494d4152592d42` vs expected `0x5343492d5052494d4152592d42` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x5052494d4152592d5349474e41545552452d42` vs expected `0x5052494d4152592d5349474e41545552452d42` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; computed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `None`; computed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; algorithm `2.16.840.1.101.3.4.2.1`; ok=no
- L3 recipient evaluation: status=confirmed; identityBasis=attestation signerNames; matched=rfc822Name:bob@example.com; reasons=receipt signer matches an archived To/Cc recipient and allReceipts permits that recipient to respond
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'status': 'absent', 'detail': '最外层 SignedData 没有任何签名者携带 mlExpansionHistory'}`

### RECEIPT-SIG-MISMATCH

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d5052494d4152592d42; `Receipt.originatorSignatureValue` = 0x5152494d4152592d5349474e41545552452d42
- receipt SignerInfo: `messageDigest` = 0xf51021fe7d7a8fa91110488f383f1a8ce4aafb45d7240389819ba32a4109f8b3; `msgSigDigest` = 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- closest candidate MSG-B layers[0].signerInfos[0]: 3 checked fields match
- mismatch `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x5052494d4152592d5349474e41545552452d42` vs expected `0x5152494d4152592d5349474e41545552452d42`
- L3 recipient evaluation: status=None; identityBasis=None; matched=—; reasons=—

### RECEIPT-MULTI-CAROL

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4d554c54492d5345434f4e44415259; `Receipt.originatorSignatureValue` = 0x4d554c54492d5349474e41545552452d4341524f4c
- receipt SignerInfo: `messageDigest` = 0x9e9e239dec66ce8b0f1571c183f47fe510a9a89edfc122c91c64af678df111db; `msgSigDigest` = 0x1ac4bba0b302e6804af9d0bd6cdadf10e6e35ae70629b623299c314a007d7144; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = carol@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4d554c54492d5345434f4e44415259` vs expected `0x5343492d4d554c54492d5345434f4e44415259` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x4d554c54492d5349474e41545552452d4341524f4c` vs expected `0x4d554c54492d5349474e41545552452d4341524f4c` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x9e9e239dec66ce8b0f1571c183f47fe510a9a89edfc122c91c64af678df111db`; computed `0x9e9e239dec66ce8b0f1571c183f47fe510a9a89edfc122c91c64af678df111db`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0x1ac4bba0b302e6804af9d0bd6cdadf10e6e35ae70629b623299c314a007d7144`; computed `0x1ac4bba0b302e6804af9d0bd6cdadf10e6e35ae70629b623299c314a007d7144`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=not_requested; identityBasis=attestation signerNames; matched=—; reasons=匹配的 SignerInfo 上没有 ReceiptRequest 属性（RFC 2634 第 2.3 节：未请求则不得生成回执）；回执仍可与该签名者的字节关联，但不能解释为被请求的投递确认
- L3 scope evidence: `{'scope': 'none', 'status': 'not_requested', 'detail': '匹配的 SignerInfo 没有 ReceiptRequest'}`

### RECEIPT-NO-RR

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4e4f2d5252; `Receipt.originatorSignatureValue` = 0x4e4f2d524551554553542d5349474e4154555245
- receipt SignerInfo: `messageDigest` = 0x7cb37c47c66565ac1aa5efd2b1b2b0acdcf8882ab18d861353b086eec3332495; `msgSigDigest` = 0x5537dabcb4f208a7e7c74b54f412638a6c8be7e13f3fc1bd6d63192f18e32b74; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4e4f2d5252` vs expected `0x5343492d4e4f2d5252` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x4e4f2d524551554553542d5349474e4154555245` vs expected `0x4e4f2d524551554553542d5349474e4154555245` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x7cb37c47c66565ac1aa5efd2b1b2b0acdcf8882ab18d861353b086eec3332495`; computed `0x7cb37c47c66565ac1aa5efd2b1b2b0acdcf8882ab18d861353b086eec3332495`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0x5537dabcb4f208a7e7c74b54f412638a6c8be7e13f3fc1bd6d63192f18e32b74`; computed `0x5537dabcb4f208a7e7c74b54f412638a6c8be7e13f3fc1bd6d63192f18e32b74`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=not_requested; identityBasis=attestation signerNames; matched=—; reasons=匹配的 SignerInfo 上没有 ReceiptRequest 属性（RFC 2634 第 2.3 节：未请求则不得生成回执）；回执仍可与该签名者的字节关联，但不能解释为被请求的投递确认
- L3 scope evidence: `{'scope': 'none', 'status': 'not_requested', 'detail': '匹配的 SignerInfo 没有 ReceiptRequest'}`

### RECEIPT-RESIGN

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d52455349474e2d4132; `Receipt.originatorSignatureValue` = 0x52455349474e45442d5349474e41545552452d4132
- receipt SignerInfo: `messageDigest` = 0x6a68b00c354b8c3e38a516702072c60a1a0d113e070f9fc9e4c80c26426b0278; `msgSigDigest` = 0xd7fd38e5885133e6191cf622e453d8b55803a50490a0cf20d832f3c00db5a681; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d52455349474e2d4132` vs expected `0x5343492d52455349474e2d4132` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x52455349474e45442d5349474e41545552452d4132` vs expected `0x52455349474e45442d5349474e41545552452d4132` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x6a68b00c354b8c3e38a516702072c60a1a0d113e070f9fc9e4c80c26426b0278`; computed `0x6a68b00c354b8c3e38a516702072c60a1a0d113e070f9fc9e4c80c26426b0278`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0xd7fd38e5885133e6191cf622e453d8b55803a50490a0cf20d832f3c00db5a681`; computed `0xd7fd38e5885133e6191cf622e453d8b55803a50490a0cf20d832f3c00db5a681`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=confirmed; identityBasis=attestation signerNames; matched=rfc822Name:bob@example.com; reasons=receipt signer matches an archived To/Cc recipient and allReceipts permits that recipient to respond
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'status': 'absent', 'detail': '最外层 SignedData 没有任何签名者携带 mlExpansionHistory'}`

### RECEIPT-B-UNATTESTED

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d5052494d4152592d42; `Receipt.originatorSignatureValue` = 0x5052494d4152592d5349474e41545552452d42
- receipt SignerInfo: `messageDigest` = 0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4; `msgSigDigest` = 0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[0].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d5052494d4152592d42` vs expected `0x5343492d5052494d4152592d42` → yes
- `layers[0].signerInfos[0].signature` SignerInfo.signature: observed `0x5052494d4152592d5349474e41545552452d42` vs expected `0x5052494d4152592d5349474e41545552452d42` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; computed `0xa156ae230ec228d6f9af494f3cbdf8c72fa84113d0528ccb17b9edc5d1152af4`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; computed `0xd0893436d3022f294a1585c2f86ed17b73027f3b6a1a13e268649c5416e30f08`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=identity_unverified; identityBasis=embedded certificate (unattested identity); matched=—; reasons=回执签名者身份仅来自其自带的证书，未由验签输入确认；不能升级为预期收件人
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'status': 'absent', 'detail': '最外层 SignedData 没有任何签名者携带 mlExpansionHistory'}`

### RECEIPT-LIST-NONE

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4c4953542d4e4f4e45; `Receipt.originatorSignatureValue` = 0x4c4953542d4e4f4e452d5349474e4154555245
- receipt SignerInfo: `messageDigest` = 0x3f87e2f7fb94e3f4252ff1c60ede7894b4631aa1e0c783f75dd3ea7ba0ad3299; `msgSigDigest` = 0xbad2833ca47ae10af78a7fa36d32d0aeaa01590e4b2d457aa1683651f8acc42e; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[1].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4c4953542d4e4f4e45` vs expected `0x5343492d4c4953542d4e4f4e45` → yes
- `layers[1].signerInfos[0].signature` SignerInfo.signature: observed `0x4c4953542d4e4f4e452d5349474e4154555245` vs expected `0x4c4953542d4e4f4e452d5349474e4154555245` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x3f87e2f7fb94e3f4252ff1c60ede7894b4631aa1e0c783f75dd3ea7ba0ad3299`; computed `0x3f87e2f7fb94e3f4252ff1c60ede7894b4631aa1e0c783f75dd3ea7ba0ad3299`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0xbad2833ca47ae10af78a7fa36d32d0aeaa01590e4b2d457aa1683651f8acc42e`; computed `0xbad2833ca47ae10af78a7fa36d32d0aeaa01590e4b2d457aa1683651f8acc42e`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=blocked; identityBasis=attestation signerNames; matched=—; reasons=mlReceiptPolicy 为 none：RFC 2634 第 2.3 节步骤 1.2.1 规定必须不生成回执
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'allReceipts'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'layer': 'layers[0]', 'history': ({'mailListIdentifier': 'issuer=2.5.4.3=Announce List, 1.2.840.113549.1.9.1=announce@example.com, serial=3003', 'expansionTime': '20261113090000Z', 'mlReceiptPolicy': {'kind': 'none', 'names': []}},), 'policyKind': 'none', 'policyNames': [], 'conflictAcrossSigners': False}`

### RECEIPT-LIST-ADD

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4c4953542d414444; `Receipt.originatorSignatureValue` = 0x4c4953542d4144442d5349474e4154555245
- receipt SignerInfo: `messageDigest` = 0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab; `msgSigDigest` = 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = dave@example.com
- `layers[1].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4c4953542d414444` vs expected `0x5343492d4c4953542d414444` → yes
- `layers[1].signerInfos[0].signature` SignerInfo.signature: observed `0x4c4953542d4144442d5349474e4154555245` vs expected `0x4c4953542d4144442d5349474e4154555245` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab`; computed `0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce`; computed `0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=confirmed; identityBasis=attestation signerNames; matched=rfc822Name:dave@example.com; reasons=回执签名者出现在 receiptRequest.receiptsFrom.receiptList 中
- L3 scope evidence: `{'scope': 'receiptList', 'names': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}]}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'layer': 'layers[0]', 'history': ({'mailListIdentifier': 'issuer=2.5.4.3=Announce List, 1.2.840.113549.1.9.1=announce@example.com, serial=3003', 'expansionTime': '20261113090000Z', 'mlReceiptPolicy': {'kind': 'inAdditionTo', 'names': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}]}},), 'policyKind': 'inAdditionTo', 'policyNames': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}], 'conflictAcrossSigners': False}`

### RECEIPT-LIST-UNEXPECTED

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4c4953542d414444; `Receipt.originatorSignatureValue` = 0x4c4953542d4144442d5349474e4154555245
- receipt SignerInfo: `messageDigest` = 0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab; `msgSigDigest` = 0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = carol@example.com
- `layers[1].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4c4953542d414444` vs expected `0x5343492d4c4953542d414444` → yes
- `layers[1].signerInfos[0].signature` SignerInfo.signature: observed `0x4c4953542d4144442d5349474e4154555245` vs expected `0x4c4953542d4144442d5349474e4154555245` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab`; computed `0x3da4208d9b6972b6f1c8f8fc33e6a684377fba4883b3e55e68aca5659ce5abab`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce`; computed `0x4b0918d557e35e7091b4ab807fdf67e30d17ea54647f9d19a33cb12eebeb3dce`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=unexpected_recipient; identityBasis=attestation signerNames; matched=—; reasons=回执签名者不在 receiptList 中：RFC 2634 第 2.3 节步骤 3.2 规定必须不生成回执
- L3 scope evidence: `{'scope': 'receiptList', 'names': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}]}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'layer': 'layers[0]', 'history': ({'mailListIdentifier': 'issuer=2.5.4.3=Announce List, 1.2.840.113549.1.9.1=announce@example.com, serial=3003', 'expansionTime': '20261113090000Z', 'mlReceiptPolicy': {'kind': 'inAdditionTo', 'names': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}]}},), 'policyKind': 'inAdditionTo', 'policyNames': [{'kind': 'rfc822Name', 'value': 'dave@example.com'}], 'conflictAcrossSigners': False}`

### RECEIPT-LIST-FIRST

- `Receipt.version` = 1; `Receipt.contentType` = 1.2.840.113549.1.7.1; `Receipt.signedContentIdentifier` = 0x5343492d4c4953542d4649525354; `Receipt.originatorSignatureValue` = 0x4c4953542d46495253542d5349474e4154555245
- receipt SignerInfo: `messageDigest` = 0xaaa246782d71f67858070aef36d0ff8d7caa66cb3e48dc1cbcd2cd8da8482215; `msgSigDigest` = 0xe27eababa6aa2e32c54539a79947198a1e36974727c6bff6ee7b172fc20bce29; `digestAlgorithm` = 2.16.840.1.101.3.4.2.1; `signatureAlgorithm` = 1.2.840.10045.4.3.2; cert emails = bob@example.com
- `layers[1].signerInfos[0].signedAttrs` SignedAttributes presence: observed `present` vs expected `present` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3` contentType attribute: observed `1.2.840.113549.1.7.1` vs expected `1.2.840.113549.1.7.1` → yes
- `layers[1].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.1` receiptRequest.signedContentIdentifier (or contentIdentifier when absent): observed `0x5343492d4c4953542d4649525354` vs expected `0x5343492d4c4953542d4649525354` → yes
- `layers[1].signerInfos[0].signature` SignerInfo.signature: observed `0x4c4953542d46495253542d5349474e4154555245` vs expected `0x4c4953542d46495253542d5349474e4154555245` → yes
- L2 `Receipt content messageDigest` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.4`: observed `0xaaa246782d71f67858070aef36d0ff8d7caa66cb3e48dc1cbcd2cd8da8482215`; computed `0xaaa246782d71f67858070aef36d0ff8d7caa66cb3e48dc1cbcd2cd8da8482215`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L2 `msgSigDigest over matched SignerInfo SignedAttributes` at `layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.16.2.5`: observed `0xe27eababa6aa2e32c54539a79947198a1e36974727c6bff6ee7b172fc20bce29`; computed `0xe27eababa6aa2e32c54539a79947198a1e36974727c6bff6ee7b172fc20bce29`; algorithm `2.16.840.1.101.3.4.2.1`; ok=yes
- L3 recipient evaluation: status=blocked; identityBasis=attestation signerNames; matched=—; reasons=receiptsFrom 为 firstTierRecipients 且存在 mlExpansionHistory：RFC 2634 第 2.3 节步骤 2.2.1 规定必须不生成回执
- L3 scope evidence: `{'scope': 'allOrFirstTier', 'value': 'firstTierRecipients'}`
- L3 scope evidence: `{'scope': 'mlExpansionHistory', 'layer': 'layers[0]', 'history': ({'mailListIdentifier': 'issuer=2.5.4.3=Announce List, 1.2.840.113549.1.9.1=announce@example.com, serial=3003', 'expansionTime': '20261113090000Z', 'mlReceiptPolicy': {'kind': None, 'names': []}},), 'policyKind': None, 'policyNames': [], 'conflictAcrossSigners': False}`

## Per-receipt conclusions
### RECEIPT-B

找到对应签名：MSG-B layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认：回执签名者可被认定为该 ReceiptRequest 范围内的收件人。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: satisfied
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-SPLICED

找到对应签名：MSG-B layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执未达可信层：msgSigDigest 与匹配签名者的 SignedAttributes 摘要不符。 预期收件人确认未评估（第二层未成立）。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: blocked
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-NO-MSGDIGEST

找到对应签名：MSG-B layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执未达可信层：缺少 msgSigDigest 关联属性。 预期收件人确认未评估（第二层未成立）。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: blocked
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-SIG-MISMATCH

未找到字段完全吻合的签名者；最接近的是 MSG-B layers[0].signerInfos[0]（3/4 项可比字段吻合），不吻合字段：originatorSignatureValue。

- **1. signature located**: blocked
- **2. receipt trusted**: blocked
- **3. expected recipient confirmed**: blocked

### RECEIPT-MULTI-CAROL

找到对应签名：MSG-MULTI layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：原签名验签状态为 invalid，不是 valid；匹配的 SignerInfo 上没有 ReceiptRequest 属性（RFC 2634 第 2.3 节：未请求则不得生成回执）；回执仍可与该签名者的字节关联，但不能解释为被请求的投递确认。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-NO-RR

找到对应签名：MSG-NO-RR layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：匹配的 SignerInfo 上没有 ReceiptRequest 属性（RFC 2634 第 2.3 节：未请求则不得生成回执）；回执仍可与该签名者的字节关联，但不能解释为被请求的投递确认。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-RESIGN

找到对应签名：MSG-RESIGN layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：原签名验签状态为 unknown，不是 valid。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-B-UNATTESTED

找到对应签名：MSG-B layers[0].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执未达可信层：回执签名状态不是 valid(unknown)、回执证书链不是 trusted(unknown)。 预期收件人确认未评估（第二层未成立）。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: blocked
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-LIST-NONE

找到对应签名：MSG-LIST-NONE layers[1].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：mlReceiptPolicy 为 none：RFC 2634 第 2.3 节步骤 1.2.1 规定必须不生成回执。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-LIST-ADD

找到对应签名：MSG-LIST-ADD layers[1].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认：回执签名者可被认定为该 ReceiptRequest 范围内的收件人。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: satisfied
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-LIST-UNEXPECTED

找到对应签名：MSG-LIST-ADD layers[1].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：回执签名者不在 receiptList 中：RFC 2634 第 2.3 节步骤 3.2 规定必须不生成回执。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

### RECEIPT-LIST-FIRST

找到对应签名：MSG-LIST-FIRST layers[1].signerInfos[0] 的 contentType、signedContentIdentifier、originatorSignatureValue 与回执逐字吻合。 回执可信：回执签名=valid，证书=trusted，msgSigDigest 与签名者的 SignedAttributes 摘要一致。 预期收件人确认不成立：receiptsFrom 为 firstTierRecipients 且存在 mlExpansionHistory：RFC 2634 第 2.3 节步骤 2.2.1 规定必须不生成回执。

- **1. signature located**: satisfied
  - 三字段逐字节吻合仅证明回执自称指向该 SignerInfo；不证明任何签名通过验签。
- **2. receipt trusted**: satisfied
  - 本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；尚未要求原签名验签通过，也不判断回执是否来自预期收件人。
- **3. expected recipient confirmed**: blocked
  - 仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。

## Controls
### same_body_resignature

回执只绑定 originatorSignatureValue 与 msgSigDigest；同正文的其他签名者即使正文摘要一致也不匹配，正文摘要不得作为签收证据。

- RECEIPT-B → MSG-B; L1=True L2=True L3=True
- RECEIPT-SPLICED → MSG-B; L1=True L2=False L3=False
- RECEIPT-NO-MSGDIGEST → MSG-B; L1=True L2=False L3=False
- RECEIPT-SIG-MISMATCH → no match; L1=False L2=False L3=False
- RECEIPT-MULTI-CAROL → MSG-MULTI; L1=True L2=True L3=False
- RECEIPT-NO-RR → MSG-NO-RR; L1=True L2=True L3=False
- RECEIPT-RESIGN → MSG-RESIGN; L1=True L2=True L3=False
- RECEIPT-B-UNATTESTED → MSG-B; L1=True L2=False L3=False
- RECEIPT-LIST-NONE → MSG-LIST-NONE; L1=True L2=True L3=False
- RECEIPT-LIST-ADD → MSG-LIST-ADD; L1=True L2=True L3=True
- RECEIPT-LIST-UNEXPECTED → MSG-LIST-ADD; L1=True L2=True L3=False
- RECEIPT-LIST-FIRST → MSG-LIST-FIRST; L1=True L2=True L3=False

### forwarded_encapsulation

外层转发签名不携带 ReceiptRequest，内层 SignedData 逐字节保留；回执只能匹配内层签名者，外层签名状态不能替代内层，未知外层状态也不影响已由 msgSigDigest 绑定的内层结论；反之，外层签名通过也不能把回执归给转发者。

- MSG-FWD layers=['1.2.840.113549.1.7.2', '1.2.840.113549.1.7.1'] outer=['unknown'] inner=['valid']
- MSG-LIST-NONE layers=['1.2.840.113549.1.7.2', '1.2.840.113549.1.7.1'] outer=['valid'] inner=['valid']
- MSG-LIST-ADD layers=['1.2.840.113549.1.7.2', '1.2.840.113549.1.7.1'] outer=['valid'] inner=['valid']
- MSG-LIST-FIRST layers=['1.2.840.113549.1.7.2', '1.2.840.113549.1.7.1'] outer=['valid'] inner=['valid']

### missing_required_linkage_attribute

msgSigDigest 是收据与原始 SignedAttributes 的必要关联证据；删除后仍可通过签名者身份与 contentIdentifier 找到候选，但无法证明收件人收到的是原签名者签署的字节，因此停在第一层。

- RECEIPT-NO-MSGDIGEST missing 1.2.840.113549.1.9.16.2.5: L1=True L2=False L3=False

### multiple_originator_signers

每个 SignerInfo 独立承载自己的 receiptRequest；只有一个签名者带 ReceiptRequest 时，回执即使指向另一签名者也不构成该签名者的签收请求。RFC 2634 section 2.2.1 要求带请求的多个 SignerInfo 的 receiptRequest 必须完全相同；不一致时必须不生成回执。

- MSG-MULTI layers[0].signerInfos[0] receiptRequest=False verification=invalid receipts=RECEIPT-MULTI-CAROL
- MSG-MULTI layers[0].signerInfos[1] receiptRequest=True verification=valid receipts=none

### mailing_list_expansion

mlExpansionHistory 只在最外层签名者上生效：mlReceiptPolicy none 抑制回执；firstTierRecipients 在发生列表扩展后不得回执；insteadOf/inAdditionTo 改变回执的发送对象（receiptsTo 路由），不扩大有权回执的收件人集合——后者仍由 receiptsFrom 的 receiptList 或 allOrFirstTier 决定。上述规则不改变回执与内层签名者的字段绑定。

- RECEIPT-LIST-NONE via bob@example.com: recipient=blocked; L1=True L2=True L3=False
- RECEIPT-LIST-ADD via dave@example.com: recipient=confirmed; L1=True L2=True L3=True
- RECEIPT-LIST-UNEXPECTED via carol@example.com: recipient=unexpected_recipient; L1=True L2=True L3=False
- RECEIPT-LIST-FIRST via bob@example.com: recipient=blocked; L1=True L2=True L3=False

## Method
- `receiptStruct`: 1.2.840.113549.1.9.16.1.1
- `msgSigDigestOid`: 1.2.840.113549.1.9.16.2.5
- `receiptRequestOid`: 1.2.840.113549.1.9.16.2.1
- `signedAttributesDigestRule`: RFC 5652 section 5.4: digest the DER SET OF encoding, replacing the IMPLICIT [0] tag with the EXPLICIT SET OF tag
- `normalization`: rfc822Name values compared case-insensitively; other GeneralName forms are case-sensitive
