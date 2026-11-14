# USM key material interop vectors

Companion table for `test_usm_key_material_interop.py`. It maps every
piece of input material an integrator may hand us — USM pass-phrase,
master key, or already localized key — to the engine identity it is
bound to, and pins the exact derived values the tests assert through
the real USM send/receive paths.

All derivations are computed independently of the pysnmp
implementation: password-to-key expansion per RFC 3414 A.2 applied
with SHA-256 as specified by RFC 7860 section 9.3, message
authentication per RFC 7860 section 4 (HMAC-SHA-256 truncated to 192
bits), privacy per RFC 3826 section 3 (AES-128 CFB).

## Fixed inputs

| Item | Value |
| --- | --- |
| Auth protocol | `usmHMAC192SHA256AuthProtocol` (RFC 7860) |
| Privacy protocol | `usmAesCfb128Protocol` (RFC 3826, AES-128) |
| Auth pass-phrase | `authPassw0rd!` |
| Privacy pass-phrase | `privPassw0rd!` (different from auth on purpose) |
| USM user | `usr-interop` |
| Engine A ID (binary) | `80001f8880ff001020304001` |
| Engine B ID (binary) | `80001f88800100fedcba9802` |
| Engine C ID (binary) | `80001f8880cafe00beefcafe03` |

## Input material to engine identity mapping

| Input material | Entry point | Bound to engine | Derived value (hex) |
| --- | --- | --- | --- |
| `authPassw0rd!` | pass-phrase | none yet (re-localizable) | master `3c28b829a6af93f8c0c1e73ffaa3afcb17178ff4dfe439423d05cb6048dc090f` |
| `privPassw0rd!` | pass-phrase | none yet (re-localizable) | master `e772948eec60a487fb653c36b4e88e40c44bec338a14e18c72b78d557549c410` |
| master auth key | master key | none yet (re-localizable) | same as derived above |
| master priv key | master key | none yet (re-localizable) | same as derived above |
| master auth key + engine A | localized | A only | `4b43a0c4276374eee6ec777c1db235f63b4e952784f521f616233138ac58c08d` |
| master priv key + engine A | localized | A only | `728305f77414ead88e7687707a09ce89` |
| master auth key + engine B | localized | B only | `38e74b4842baa85faf662734c53cac0000f4cb8ec02b6b4b13d650d17b02336b` |
| master priv key + engine B | localized | B only | `70a60af373680914ce48cfcc12a6ec42` |
| master auth key + engine C | localized | C only | `970b5a1b091c43be1deb0c48cd511f7dc646b38f2f85f9ad59ec0ca6dc6025b8` |
| master priv key + engine C | localized | C only | `6e330f5dff68a613f612a3ddb56729cd` |

Pass-phrase and master key entries keep the master key in the LCD
(`pysnmpUsmKeyAuth`/`pysnmpUsmKeyPriv`) and stay re-localizable towards
any engine. A localized entry stores no master key (the columns keep
their eight-zero-octet default) and cannot be re-localized; it is
valid for its own engine identity only. Material localized for engine
B presented at engine C fails authentication on the real receive path
(`authenticationFailure`), so a local key minted for one engine is
never silently usable at another.

## Runnable wire vector

GET request from engine A to authoritative engine B, security level
authPriv, `snmpEngineBoots=1`, `snmpEngineTime=0`, `msgID=1`,
`request-id=1`, AES salt `0102030405060709`. Identical bytes are
produced whether the user was configured with the pass-phrases, the
master keys, or the localized keys above:

```
30818b020103300e020101020300ffe304010702010304473045040c
80001f88800100fedcba9802020101020100040b7573722d696e7465
726f7004187bfe4cbd4c6b6d91bb14d9ce15876011a7b3ece4bdd52a
1f04080102030405060709042d66353a4ab546bf24204bdc4f75e087
3fd262d49e721ea3036dce1050d671a696ce479b3e3a98aab13b9553
1025
```

| Field | Value (hex) |
| --- | --- |
| `msgAuthenticationParameters` (HMAC-SHA-256-192) | `7bfe4cbd4c6b6d91bb14d9ce15876011a7b3ece4bdd52a1f` |
| `msgPrivacyParameters` (AES salt) | `0102030405060709` |
| encrypted scopedPDU (AES-128 CFB) | `66353a4ab546bf24204bdc4f75e0873fd262d49e721ea3036dce1050d671a696ce479b3e3a98aab13b95531025` |

The test re-computes the HMAC over the message with a zeroed
authentication field using the independently derived localized auth
key, and decrypts the ciphertext with `boots || time || salt` as IV
and the independently derived localized privacy key, recovering the
plaintext GetRequest scopedPDU.

## Rejected material

Wrong key types (outside `passphrase`/`master`/`localized`), master or
localized keys whose length does not match the authentication
protocol's key length (32 octets for SHA-256), localized privacy keys
shorter than the privacy protocol key size (16 octets for AES-128),
and unknown protocol OIDs are all rejected before anything is written
to the LCD: no half-configured user row is left behind, and a
previously configured working user survives a failed reconfiguration
attempt unchanged.

## Running

```sh
uv run scripts/tests.py --test-path tests/proto/secmod/test_usm_key_material_interop.py
```
