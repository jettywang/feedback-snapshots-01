# Encryption evidence grading for msoffcrypto

This note evaluates one claim a file-detection service can make today:

> `msoffcrypto.is_encrypted() == True` means the document is a **strongly encrypted document**.

The claim is not supportable. For the formats this library actually handles (legacy
Office XOR obfuscation, RC4, and OOXML Agile/Standard), `is_encrypted()` reports that a
**declaration** exists. It does not report that a password was checked, that content was
recovered, that integrity was verified, or that the protection is strong. Those are four
different observations produced by four different code paths, and several of them are
opt-in or absent per format.

Scope: only the methods this library actually processes are covered - legacy Office XOR
obfuscation (XLS implemented, DOC declared but not decryptable), RC4 (plain RC4 and RC4
CryptoAPI in DOC/XLS/PPT), and OOXML Agile/Standard. Extensible encryption, Word/Excel/
PowerPoint 95, and any modern "strong encryption" claim outside these paths are out of
scope and are reported as unsupported rather than as “strong”.

Everything below is reproducible with the local fixtures and the probe in
`tools/encryption_evidence.py`:

```sh
.venv/bin/python tools/encryption_evidence.py --matrix
.venv/bin/python tools/encryption_evidence.py --samples --output docs/evidence/samples.json
```

The adapter is importable (`observe`, `classify`) if the backend wants to reuse the same
observation and classification steps instead of shelling out. It performs no writes to the
source tree. Read-only metadata extraction reuses the library's format parsers (a few of
which are underscore-prefixed); a production backend should replace those with its own
parsers or with public APIs if the library adds them.

The probe copies fixtures to a temporary directory before truncating, tampering, or
forging anything. `tests/inputs` is never modified. `docs/evidence/samples.json` contains
42 status objects: each records the requested check mode, the fixture it was derived from
(including SHA-256), the declared parameters, the three check results, the evidence level,
and the claims that remain unproven. `--matrix` prints the same cases compactly.

The files are not re-encrypted by the probe except for one deliberately forged Agile
sample; all other mutations preserve the original key material, so a verifier match is a
real observation rather than an artifact of the test.

## 1. What `is_encrypted()` actually observes

`OfficeFile` dispatch is structural: OLE files are routed by stream name and ZIP files by
`[Content_Types].xml` (`msoffcrypto/__init__.py:43-78`). Each format then reads a single
producer-controlled field:

| Family | Detection field | What a `True` proves | What it does not prove |
| --- | --- | --- | --- |
| OOXML (`ooxml.py:321-338`) | presence of an OLE container with an `EncryptionInfo` stream | a producer wrote an encryption descriptor | the descriptor is valid, the payload exists, or the method is supported |
| DOC (`doc97.py:488-501`) | FIB `fEncrypted` bit | the FIB declares encryption | FIB `fObfuscation` selects only XOR/RC4 **intent**; content may be absent |
| XLS (`xls97.py:656-693`) | `FilePass` record + `wEncryptionType` ∈ {0= XOR, 1= RC4} | a FilePass record declares XOR or RC4 | the record's payload parsed, the password, or the sheet data |
| PPT (`ppt97.py:812-838`) | `UserEditAtom.recLen == 0x20` | the edit atom has the encrypted-shape length | a `CryptSession10Container` exists at the referenced persist offset |

Two consequences matter for a detection service:

* **Unknown declarations are reported as “not encrypted”.** An XLS `FilePass` with a
  `wEncryptionType` other than 0 or 1 makes `is_encrypted()` return `False`; a DOC FIB with
  `fEncrypted=1` but an unsupported table header makes `is_encrypted()` return `True` and
  `load_key()` fail later. Detection is neither a positive plaintext test nor a complete
  encryption test.
* **Declarations are forgeable.** A plain DOC/XLS/PPT can be given one marker bit or one
  record and will be reported as encrypted. The probe includes such samples:
  `doc_forged_marker.doc` (FIB bit only) and `ppt_forged_marker.ppt` (edit-atom length
  only). Both are `is_encrypted() == True` while their key paths fail.

## 2. The four checks, per family

The important distinction is between **format declaration**, **password verification**,
**content decryption**, and **payload integrity**. They are performed by different code
and are not interchangeable.

### OOXML Agile (`ecma376_agile.py`)

* **Declaration** (`ooxml.py:118-130`, `_parseinfo_agile`): XML inside `EncryptionInfo`
  names `cipherAlgorithm`, `keyBits`, `hashAlgorithm`, `spinCount`, and points at
  `EncryptedPackage`. All strings are producer-supplied.
* **Password check** (`ooxml.py:203-214`, `ecma376_agile.py:423-469`):
  `load_key(verify_password=True)` decrypts the verifier input and compares a hash.
  **Default `load_key(password=...)` does not run this check** (`ooxml.py:185-214`); it
  derives a candidate key and returns. The verifier comparison is an equality test against
  a stored value, so its strength is the verifier hash's collision resistance — 512 bits
  for the SHA-512 fixture, 160 bits for the SHA-1 fixture.
* **Content decryption** (`ecma376_agile.py:206-243`): AES-CBC over `EncryptedPackage`,
  guided by the 8-byte size field. Wrong key material yields bytes; the library's only
  post-check is `zipfile.is_zipfile()` (`ooxml.py:295-299`).
* **Integrity** (`ooxml.py:262-277`, `ecma376_agile.py:472-503`): only when
  `decrypt(verify_integrity=True)` is requested. The HMAC covers the **EncryptedPackage
  ciphertext**, keyed by a key derived from the password-derived secret. It proves the
  ciphertext was not changed after this producer wrote it. It does not prove who produced
  it, and it is never run by `is_encrypted()` or `load_key()`.
* **Optional HMAC, mandatory parser**: MS-OFFCRYPTO makes `dataIntegrity` optional, but
  `_parseinfo_agile` indexes `getElementsByTagName("dataIntegrity")[0]` unconditionally
  (`ooxml.py:72-80`). Removing that element from an otherwise valid Agile file makes
  `OfficeFile()` raise `IndexError`, so the sample `agile_no_data_integrity.docx` is
  reported as `ENCRYPTION_DECLARED_UNPARSED`, not as an Agile file without integrity.

### OOXML Standard (`ecma376_standard.py`)

* **Declaration**: `EncryptionInfo` version 2/3/4.2 with an encryption header
  (`algId`, `algIdHash`, `keySize`, provider). In the fixture it declares AES-128/SHA-1.
* **Password check**: `verify_password=True` runs AES-ECB over the stored verifier and
  compares a SHA-1 hash (`ecma376_standard.py:35-54`). As with Agile, the default path
  skips it.
* **Content decryption**: AES-ECB over `EncryptedPackage` (`ecma376_standard.py:18-33`).
* **Integrity**: **none.** There is no HMAC in this method. `verify_integrity=True` is
  accepted by `OOXMLFile.decrypt` but ignored for Standard (`ooxml.py:286-289`); the probe
  records this as `integrity.applicable = false`.

### RC4 (XLS / DOC / PPT)

* **Declaration**: XLS `FilePass.wEncryptionType == 1` with version 1.1 (plain RC4) or
  2/3/4.2 (RC4 CryptoAPI); DOC FIB `fEncrypted=1, fObfuscation=0` plus a table header;
  PPT `UserEditAtom.recLen == 0x20` plus a `CryptSession10Container`.
* **Password check**: `load_key()` always runs the verifier for supported RC4 paths
  (`rc4.py:50-70`, `rc4_cryptoapi.py:43-64`). There is no `verify_password` argument; the
  check is not optional. MD5-based (RC4) and SHA-1-based (RC4 CryptoAPI) verifier
  comparisons are 128/160-bit equality tests.
* **Content decryption**: stream ciphers with per-block rekeying; DOC decrypts
  `WordDocument`, `1Table`, and optional `Data`; XLS decrypts the Workbook record stream;
  PPT decrypts persist objects referenced from `PersistDirectoryAtom`.
* **Integrity**: **none.** There is no MAC over the payload for any RC4 path.

### XOR obfuscation (XLS; DOC is declared but not implemented)

* **Declaration**: XLS `FilePass.wEncryptionType == 0`; DOC FIB `fEncrypted=1,
  fObfuscation=1`.
* **Password check**: XLS runs `DocumentXOR.verifypw` (`xor_obfuscation.py:182-213`).
  This is a **16-bit** value comparison. It is not a cryptographic password check, and
  collisions are easy: a targeted random search found the different password
  `A5XSZmz6VjoEywz` after about 40,000 guesses (0.16 s). That password matches the stored
  verifier and produces a structurally valid Workbook whose bytes differ from the correct
  recovery in **72,177 of 80,843** positions.
* **Content decryption**: byte-level XOR/rotate over the Workbook stream
  (`xor_obfuscation.py:314-354`). There is no key schedule, no cipher, and no MAC. This is
  obfuscation, not encryption.
* **Integrity**: **none.**
* **DOC caveat**: `Doc97File.load_key` recognises the XOR FIB bits but only logs `IKey`;
  it sets no type and runs no verifier (`doc97.py:309-312`). `decrypt()` then raises
  `AttributeError` because `self.type` was never assigned. Regarding DOC XOR, the library
  can **declare** the method but cannot check a password or decrypt.

## 3. Local experiments

All rows below come from `tools/encryption_evidence.py`; the full JSON with hashes and
facts is in `docs/evidence/samples.json`. “Truncated” means the original container was
retained but ciphertext/structure was zeroed beyond the header region.

All generated samples are written under a fresh temporary directory and identified in the
bundle by `ephemeral: true` plus the fixture SHA-256; none of the repository fixtures or
expected outputs are touched.

### 3.1 Normal controls

| Case | API call | Observation | Limit |
| --- | --- | --- | --- |
| `agile_default` | `load_key(password=correct)` | `decrypt()` returns 11,995 bytes; package has `[Content_Types].xml`, 11 members, CRCs ok | **no verifier was checked**; outcome is “decrypted, key unverified” |
| `agile_verified_integrity` | `+ verify_password, verify_integrity` | verifier match (SHA-512) and HMAC pass | proves key possession + post-write byte integrity, not producer identity |
| `agile_sha1_verified` | same | SHA-1 verifier + HMAC pass | same |
| `standard_default` | `load_key(password=correct)` | 3,939 bytes, valid OOXML package | no verifier checked |
| `standard_verified` | `+ verify_password` | SHA-1 verifier match | no payload integrity exists |
| `xor_ok` | `load_key(password=correct)` | 16-bit verifier match; Workbook BOF/EOF walk ok | verifier is 16 bits; BOF/EOF is framing, not content |
| `xls_rc4_ok`, `doc_rc4_ok`, `ppt_rc4_ok` | `load_key(password=correct)` | RC4 CryptoAPI SHA-1 verifier match; OLE/BIFF/FIB/record-header structure ok | no payload integrity; DOC validates only the FIB, PPT only the first record header |

### 3.2 Wrong password

| Case | Result | Meaning |
| --- | --- | --- |
| `agile_wrong_default` (Agile, no `verify_password`) | `decrypt()` raises `InvalidKeyError: The file could not be decrypted with this password`, **after writing 11,995 bytes to the caller's buffer** | the message names the password, but the gate is `zipfile.is_zipfile()` on decrypted bytes (`ooxml.py:296-299`). The buffer already contained unauthenticated bytes. |
| `agile_wrong_verified` | `load_key(verify_password=True)` raises `InvalidKeyError: Key verification failed` | a verifier mismatch; payload never touched |
| `standard_wrong_verified` | same | same |
| `xls_rc4_wrong`, `doc_rc4_wrong`, `ppt_rc4_wrong` | `InvalidKeyError: Failed to verify password` | RC4 verifier mismatch |
| `xor_wrong` | `InvalidKeyError: Failed to verify password` | 16-bit verifier mismatch (but collisions exist) |

The “wrong password” wording is accurate only where a verifier was actually run. For OOXML
default mode it is a heuristic inferred from a failed ZIP check, so the same exception
also covers “correct password, corrupt payload” and “not an OOXML payload at all”.

### 3.3 Header-only / truncated samples

| Case | Container retained | Result | What it shows |
| --- | --- | --- | --- |
| `agile_header_only_verified` | `EncryptionInfo` + zeroed `EncryptedPackage` after its 8-byte size field | verifier **matches**; `decrypt()` raises; 11,995 bytes were already written | verifier lives in `EncryptionInfo`; a password can be “confirmed” while the content is gone |
| `agile_header_only_default` | same | no verifier; `decrypt()` raises; 11,995 bytes already written | failure cannot be attributed: with no verifier run, wrong password and missing payload look identical |
| `agile_header_only_integrity` | same | `InvalidKeyError: Payload integrity verification failed` before decryption | HMAC detects zeroed ciphertext |
| `agile_info_only_default` | `EncryptionInfo` only; `EncryptedPackage` absent | verifier **matches**; `decrypt()` raises `unpack requires a buffer of 8 bytes` | `load_key` success is independent of payload presence |
| `standard_header_only` | `EncryptionInfo` + zeroed `EncryptedPackage` | verifier matches; `decrypt()` raises; 3,939 bytes written; no end-of-central-directory | the verifier identifies the key; Standard has no HMAC, so the payload itself is unconfirmed |
| `xor_header_only` | `FilePass` retained, Workbook records zeroed | verifier matches; `decrypt()` raises `unpack requires a buffer of 4 bytes` | 16-bit verifier match says nothing about remaining records |
| `rc4_header_only.xls` | `FilePass` retained, records zeroed | verifier matches; `decrypt()` raises `unpack requires a buffer of 4 bytes` | same for RC4 CryptoAPI |
| `doc_header_only.doc` | FIB + table encryption header retained, stream bodies zeroed | verifier matches; `decrypt()` **returns 23,040 bytes**; FIB magic ok, fEncrypted cleared; 3,555 of 4,096 `WordDocument` bytes differ from the correct recovery | the library validates only the FIB; “decrypted” does not mean “recovered” |
| `ppt_header_only.ppt` | crypt session + tail atoms retained, earlier persist objects zeroed | verifier matches; `decrypt()` **returns 43,008 bytes**; first record type is `0x1978`, not Document `0x03e8`; 38,278 of 38,706 bytes differ | same; only a structure check at the caller exposes it |

The DOC and PPT rows are the clearest counterexamples to “decryption success = content
confirmed”. The key was genuinely verified and the API returned success with full-length
output; the output was nevertheless mostly wrong.

### 3.4 The ZIP-magic trap

`OOXMLFile.decrypt` ends with `zipfile.is_zipfile(io.BytesIO(obuf))`. That function only
locates an end-of-central-directory record; it does not require `[Content_Types].xml`,
member CRC success, or an actual document. The probe builds
`agile_minimal_zip_payload.docx`: a 4,096-byte plaintext whose only ZIP structure is a
22-byte EOCD record, encrypted with the **correct** password.

* `zipfile.is_zipfile()` → `True`
* Agile HMAC (`verify_integrity=True`) → `True`
* OOXML package check → **fails**: no `[Content_Types].xml`, no `_rels/.rels`

So even a *verified* HMAC plus a passing ZIP check establishes only “these bytes were
encrypted by someone holding this key”. It does not establish that the bytes are an OOXML
document. A backend must not map the ZIP check to password confirmation or to document
validity.

A tampered Agile sample makes the same distinction visible without the forged payload:
`agile_tampered_default` returns 11,995 bytes and `zipfile_is_zipfile=True`, but a member
inflate fails; with `verify_integrity=True` the same file yields `Payload integrity
verification failed`. The Standard analogue (`standard_tampered_member.docx`) returns 3,939
bytes, has `zipfile_is_zipfile=True`, and fails only when members are inflated;
`verify_integrity` is ignored because Standard has no HMAC. Both rows therefore keep
`zipfile_is_zipfile: true` while their structural verdict is `fail`.

## 4. Backend status contract

Recommended persisted fields. The probe emits exactly this shape
(`docs/evidence/samples.json`); all strings are stable enum values.

```json
{
  "schema_version": "1.0",
  "case": "agile_header_only_verified",
  "requested_check_mode": {"verify_password": true, "verify_integrity": false},
  "file": {"name": "agile_header_only.docx", "size": 18432,
           "sha256": null, "ephemeral": true, "container": "ole",
           "derived_from": {"fixture": "example_password.docx", "sha256": "0605..."}},
  "format": {
    "family": "ooxml",
    "dispatch": "zip + [Content_Types].xml",
    "declared_method": "agile",
    "declaration_source": "EncryptionInfo stream",
    "declaration_present": true,
    "parameters": {"version": "4.4", "payload_cipher": "AES", "payload_key_bits": 256,
                   "payload_hash": "SHA512", "spin_count": 100000,
                   "password_hash": "SHA512", "has_data_integrity": true},
    "declaration_is_forgeable": true
  },
  "checks": {
    "encryption_marker": true,
    "key": {"attempted": true, "mechanism": "agile_verifier", "result": "match",
            "verifier_bits": 512, "collision_resistant": true, "error": null},
    "decryption": {"attempted": true, "result": "error",
                   "exception": "InvalidKeyError: The file could not be decrypted with this password",
                   "output_bytes": 11995, "wrote_output_before_error": true,
                   "output_validation": {"kind": "zip_eocd", "depth": "magic",
                                          "result": "fail",
                                          "detail": "no end-of-central-directory record",
                                          "zipfile_is_zipfile": false,
                                          "complete": true}},
    "integrity": {"requested": false, "applicable": false, "mechanism": "none",
                  "result": "not_checked", "scope": "not available",
                  "authenticates_producer": false}
  },
  "evidence": {"level": "key_checked", "facts": ["..."], "not_proven": ["..."]},
  "policy": {"class": "aes_agile_hmac", "declared_cipher": "AES",
             "declared_key_bits": 256, "declared_integrity": "hmac",
             "assessment": "backend policy derived from declared parameters; not an API verdict",
             "supported_by_api": false},
  "verdict": {"state": "PAYLOAD_TRUNCATED_OR_CORRUPTED", "severity": "reject",
              "reject_reason": "PAYLOAD_TRUNCATED_OR_CORRUPTED"}
}
```

### 4.1 `verdict.state`

| State | Severity | Meaning |
| --- | --- | --- |
| `NO_ENCRYPTION_DECLARED` | info | no supported declaration; not proof of plaintext |
| `ENCRYPTION_DECLARED_UNPARSED` | reject | marker exists, `EncryptionInfo` is damaged |
| `ENCRYPTION_DECLARATION_INCONSISTENT` | reject | marker exists, referenced crypt session/header is absent |
| `UNSUPPORTED_ENCRYPTION_METHOD` | reject | method/version not processable (e.g. Extensible, DOC XOR, unknown FilePass type) |
| `UNSUPPORTED_CONTAINER` | reject | not an OLE/ZIP container this library dispatches |
| `KEY_REJECTED` | reject | a supported verifier was checked and did not match |
| `DECRYPTION_INCONCLUSIVE` | reject | no verifier checked and decryption failed; cause unknown |
| `PAYLOAD_TRUNCATED_OR_CORRUPTED` | reject | verifier matched, payload absent/truncated/corrupt |
| `PAYLOAD_INTEGRITY_FAILED` | reject | Agile HMAC mismatch |
| `DECRYPTION_ERROR` | reject | decryption raised for another reason |
| `OUTPUT_STRUCTURE_INVALID` | reject | bytes returned but fail the family's structural check |
| `CONTENT_DECRYPTED_KEY_UNVERIFIED` | info | bytes + structure, but no verifier ran |
| `CONTENT_DECRYPTED_WEAK_KEY_MATCH` | info | bytes + structure, but verifier is 16-bit XOR |
| `CONTENT_DECRYPTED_KEY_VERIFIED` | info | bytes + structure + supported verifier match |
| `INTEGRITY_VERIFIED` | info | decrypted + structure valid + Agile HMAC pass; HMAC implies possession of the secret key, though `verify_password` may not have run |

`NO_ENCRYPTION_DECLARED` must not be rendered as “plaintext” or “no password”; it is only
“no supported declaration”. Likewise `UNSUPPORTED_ENCRYPTION_METHOD` must not be rendered as
“not encrypted” even though `is_encrypted()` returns `True` for some of those files.

### 4.2 `checks.decryption.output_validation`

Structural validation is deliberately tiered so that a shallow check cannot masquerade as
content verification:

| `kind` | `depth` | `complete` | Used for |
| --- | --- | --- | --- |
| `zip_eocd` | `magic` | true | no EOCD record found (the library's own `is_zipfile` gate) |
| `ooxml_package` | `package` / `members` | true | `[Content_Types].xml`, `_rels/.rels`, namespace, member inflate/CRC |
| `ole_container` / `ole_fib` / `biff` / `ppt_record` | `container` / `header` / `framing` | **false** | legacy formats: only OLE presence, FIB magic, BOF/EOF, or the first record header |
| `none` | `none` | `null` | validation was not reached (key rejected, integrity aborted, unsupported) |

When `complete` is false, the evidence object adds the caveat that bytes beyond the checked
depth may still be wrong. That is why `doc_rc4_header_only` is `CONTENT_DECRYPTED_KEY_VERIFIED`
(a verifier did match) while remaining explicitly unverified at the content level.

### 4.3 `verdict.reject_reason`

`UNSUPPORTED_CONTAINER`, `ENCRYPTIONINFO_UNPARSEABLE`, `DECLARATION_INCONSISTENT`,
`UNSUPPORTED_ENCRYPTION_VERSION`, `UNSUPPORTED_ENCRYPTION_TYPE`,
`KEY_VERIFIER_MISMATCH`, `KEY_UNVERIFIED_AND_DECRYPTION_FAILED`,
`PAYLOAD_TRUNCATED_OR_CORRUPTED`, `PAYLOAD_INTEGRITY_FAILED`,
`OUTPUT_STRUCTURE_INVALID`, `DECRYPTION_ERROR`. Non-reject states carry `null`.

User-facing copy should distinguish “the password did not match a verifier”
(`KEY_VERIFIER_MISMATCH`) from “the password could not be checked and decryption failed”
(`KEY_UNVERIFIED_AND_DECRYPTION_FAILED`) from “the password matched but the payload is
gone” (`PAYLOAD_TRUNCATED_OR_CORRUPTED`). The library raises `InvalidKeyError` for all three.

### 4.4 `evidence.level`

`none` < `container_only` < `declaration` < `key_checked_negative` < `key_checked` <
`decrypted` < `decrypted_weak_key_check` ≈ `decrypted_key_checked` < `integrity_verified`.
Only the last level includes a cryptographic integrity result, and only Agile can reach it.

### 4.5 Reading the axes together

Do not collapse the three checks into one boolean. The useful backend rule is:

* `key.result = mismatch` → `KEY_REJECTED` (a real negative check).
* `key.result = match` + payload failure → `PAYLOAD_TRUNCATED_OR_CORRUPTED` (the key is
  not the problem).
* `key.result = not_checked` + payload failure → `DECRYPTION_INCONCLUSIVE` (the library
  cannot say whether the password or the payload is wrong).
* `key.result = match` + bytes + structure → content-level states, with
  `CONTENT_DECRYPTED_WEAK_KEY_MATCH` whenever the verifier is weaker than 128 bits.
* `integrity.result = pass` → `INTEGRITY_VERIFIED`, but only on top of a valid structure;
  HMAC alone must never lift `OUTPUT_STRUCTURE_INVALID` to success (see
  `agile_minimal_zip_payload`).

Forged declarations never reach `KEY_REJECTED`: a forged PPT marker produces
`ENCRYPTION_DECLARATION_INCONSISTENT` (`KeyError: 0` while locating the crypt session), a
forged DOC bit produces `UNSUPPORTED_ENCRYPTION_METHOD` (`DecryptionError` on the bogus
version), a forged XLS `FilePass` type 1 produces `is_encrypted() == True` followed by
`DecryptionError: Unsupported encryption method` in `load_key`, and an unknown XLS type 2
produces `is_encrypted() == False` followed by a later `AttributeError`. Recording the
library's own exception alongside the declaration keeps these distinguishable from a
genuine password rejection.

### 4.6 Sample outputs

`docs/evidence/samples.json` has the full objects. Three representative verdicts, with the
fields a backend would persist:

```json
{"case": "agile_default",
 "requested_check_mode": {"verify_password": false, "verify_integrity": false},
 "checks": {"key": {"result": "not_checked", "mechanism": "agile_verifier"},
            "decryption": {"result": "ok", "output_bytes": 11995,
                           "output_validation": {"kind": "ooxml_package", "depth": "members",
                                                 "result": "pass", "zipfile_is_zipfile": true,
                                                 "complete": true}},
            "integrity": {"requested": false, "applicable": false, "result": "not_checked"}},
 "evidence": {"level": "decrypted"},
 "verdict": {"state": "CONTENT_DECRYPTED_KEY_UNVERIFIED", "severity": "info"}}
```

```json
{"case": "agile_header_only_integrity",
 "checks": {"key": {"result": "match", "mechanism": "agile_verifier", "verifier_bits": 512},
            "decryption": {"result": "error",
                           "exception": "InvalidKeyError: Payload integrity verification failed",
                           "output_bytes": 0, "wrote_output_before_error": false},
            "integrity": {"requested": true, "applicable": true,
                          "result": "fail", "scope": "EncryptedPackage ciphertext"}},
 "evidence": {"level": "key_checked"},
 "verdict": {"state": "PAYLOAD_INTEGRITY_FAILED", "severity": "reject",
             "reject_reason": "PAYLOAD_INTEGRITY_FAILED"}}
```

```json
{"case": "agile_minimal_zip_payload",
 "checks": {"key": {"result": "match", "verifier_bits": 512},
            "decryption": {"result": "ok", "output_bytes": 4096,
                           "output_validation": {"kind": "ooxml_package", "depth": "package",
                                                 "result": "fail",
                                                 "detail": "missing [Content_Types].xml, _rels/.rels",
                                                 "zipfile_is_zipfile": true, "complete": true}},
            "integrity": {"requested": true, "result": "pass"}},
 "evidence": {"level": "key_checked"},
 "verdict": {"state": "OUTPUT_STRUCTURE_INVALID", "severity": "reject",
             "reject_reason": "OUTPUT_STRUCTURE_INVALID"}}
```

```json
{"case": "doc_xor_declared",
 "format": {"family": "doc97", "declared_method": "xor",
            "declaration_source": "FIB fEncrypted/fObfuscation"},
 "checks": {"key": {"result": "not_implemented", "mechanism": "xor_16bit_verifier"},
            "decryption": {"result": "error",
                           "exception": "AttributeError: 'Doc97File' object has no attribute 'type'"}},
 "verdict": {"state": "UNSUPPORTED_ENCRYPTION_METHOD", "severity": "reject",
             "reject_reason": "UNSUPPORTED_ENCRYPTION_TYPE"}}
```

These four cover the operational cases: decrypted-but-unverified, key-matched-but-payload-
failed, bytes-returned-but-structure-invalid, and declared-but-unimplemented. For legacy
families the structure block also carries `"complete": false`, which triggers the shallow-
validation caveat on `doc_rc4_header_only`, `xor_ok`, `xls_rc4_ok`, `ppt_rc4_ok`.

## 5. Observation vs. conclusion

The API can supply these **observations** directly:

* container family and dispatch (OLE stream names, ZIP `[Content_Types].xml`);
* declared method/version/algorithm parameters, as strings from the file;
* whether a verifier was run, its mechanism, and its result;
* whether `decrypt()` raised, how many bytes it wrote before raising, and a structural
  check on the bytes;
* Agile HMAC result, only when requested.

The API **cannot** supply these conclusions on its own:

| Claim | Why it is unsupported |
| --- | --- |
| “strongly encrypted” | no strength concept exists; AES-256 Agile and 16-bit XOR both produce `True`. Map declared parameters through a backend policy table instead. |
| “password confirmed” after default OOXML decryption | `load_key` skips the verifier; the only gate is `is_zipfile()` on decrypted bytes. Use `verify_password=True` and persist the verifier result. |
| “integrity verified” for RC4 or Standard | those methods have no payload MAC; `verify_integrity=True` is ignored (Standard) or irrelevant. |
| “integrity verified” ⇒ authentic document | Agile HMAC covers `EncryptedPackage` under the file's key; the forged minimal-ZIP payload passes HMAC. Producer identity is out of scope. |
| “content recovered” from `decrypt()` returning bytes | DOC/PPT header-only samples return full-length output that is mostly wrong; only the FIB or first record header is checked. |
| “correct password” from `InvalidKeyError` | the same exception covers wrong password, corrupt payload, and non-Office payload when no verifier ran. |
| “not encrypted” from `False` | unknown `FilePass` types and unsupported declarations also yield `False`; plaintext is not positively validated. |
| “encrypted” from `True` | one FIB bit, one record, or one edit-atom length can be forged; the probe demonstrates each. |
| “unique password” from a verifier match | XOR's verifier is 16 bits; the probe's colliding password decrypts to different bytes that still pass framing. |
| “Excel/Word/PowerPoint content is valid” | validators are structural (`[Content_Types].xml`, FIB magic, BOF/EOF, first record header), not semantic. |

## 6. Recommended service behavior

1. Replace the single “strongly encrypted document” label with
   `{state, evidence_level, declared_method, declared_parameters, reject_reason}`.
2. For OOXML, call `load_key(..., verify_password=True)` **and**
   `decrypt(..., verify_integrity=True)` when the service needs password or integrity
   assertions; persist the per-check results, not a combined boolean.
3. Treat `is_encrypted()` as a routing hint, never a verdict.
4. Map declared algorithms to a versioned policy table (`obfuscation`, `rc4_legacy`,
   `aes_standard_no_integrity`, `aes_agile_hmac`, plus `unsupported`/`unknown` for
   declarations with no usable key/content path); do not present the table as something
   the API proved.
5. Discard or quarantine any `decrypt()` output written before an exception; the library
   writes to the caller's buffer before its post-check.
6. For legacy formats, label results as “structure-checked”, not “content-verified”;
   only a real Office parser or semantic validator can go further.

## 7. Answer to the original claim

| Claim | Supported by the current interface? | Evidence |
| --- | --- | --- |
| “this is an encrypted document” | partially; only as a declaration | `is_encrypted()` reads one field per format and can be forged (§1) |
| “this is a strongly encrypted document” | **no** | AES-256 Agile and 16-bit XOR both return `True`; only declared parameters are available |
| “the password is correct” | only with `verify_password=True` for OOXML, and always for legacy RC4/XLS-XOR; **not** for default OOXML or DOC XOR | §2, §3.2 |
| “the content was recovered” | no; only structural checks per family | DOC/PPT header-only files return full-length wrong output (§3.3) |
| “the payload is intact” | only Agile with `verify_integrity=True`; never RC4/Standard | §2, §3.4 |
| “the password is the original one” | no; even a strong verifier match is an equality check, and XOR matches collide | §3.1, §3.2 |
| “the document is authentic” | no | HMAC proves key possession, not producer identity; the forged minimal-ZIP payload passes HMAC |
| “the file is not encrypted” | no; absence of a supported marker is not plaintext validation | unknown XLS `FilePass` types return `False` |

The correct replacement for the single label is the status object in §4: a declaration
record, three independent check results, a policy classification, and an explicit
`not_proven` list.

## 8. Current gaps in the library that affect the contract

* `OOXMLFile.decrypt` writes output before the `is_zipfile` check, so a rejected
  decryption leaves unauthenticated bytes in the caller's buffer
  (`ooxml.py:285-299`; observed as `wrote_output_before_error: true`). `load_key` has
  already derived a candidate key at that point, so callers must not treat the buffer as
  plaintext on exception.
* `is_zipfile` is a magic/EOCD heuristic, not package validation
  (`ooxml.py:296`); a 22-byte EOCD appended to 4,074 zero bytes passes it.
* `Doc97File.load_key` for XOR neither verifies nor sets a type; `decrypt` then raises
  `AttributeError` (`doc97.py:309-312`, `366-467`).
* `Xls97File.is_encrypted` returns `False` for unknown `FilePass` types and for some
  damaged records, while `load_key` may raise later (`xls97.py:656-693`, `479-557`). A
  forged FilePass with type 1 returns `True`, then `load_key` raises
  `DecryptionError: Unsupported encryption method`; a plain workbook with a forged
  type 2 returns `False`, then `decrypt` raises `AttributeError`.
* Legacy `load_key` signatures take no `verify_password`; verifier checks are implicit
  and cannot be skipped or requested uniformly. `decrypt` signatures take no
  `verify_integrity` outside OOXML.
* Exceptions do not distinguish verifier mismatch, unchecked-key failure, and payload
  corruption; the backend contract above adds the distinction.
* The CLI `--test` contract is inverted relative to `README.md:54`: `__main__.py:70-76`
  exits `1` for "not encrypted" and `0` for "encrypted". `__main__.py:43-44` also returns
  `False` for any non-OLE input, so an arbitrary file is reported as "not encrypted"
  rather than "unsupported". A detection service should not reuse the exit code as a
  security signal.
