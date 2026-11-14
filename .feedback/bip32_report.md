# BIP32 minimal derivation module

Implemented in `src/ecdsa/bip32.py`.

## Public surface

- `master_from_seed(seed, network="mainnet")`
- `parse_path(path)`
- `ExtendedKey.from_base58()` / `.from_string()`
- `ExtendedPrivateKey`, `ExtendedPublicKey`
- `derive(index)` / `derive_path(path)`
- `neuter()` and `to_base58()` / `to_bytes()`

## Verification

- Official BIP32 vectors 1-4 (including leading-zero vectors)
- Official BIP32 test vector 5 invalid extended keys
- Controlled HMAC replacement for invalid `I_L >= n`, zero child, and infinity
- Hardened-bit preservation, depth overflow, typed deserialization, Base58Check
- Full fast suite: 1835 passed, 1 skipped
