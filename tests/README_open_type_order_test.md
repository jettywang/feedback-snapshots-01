# Open-Type Import-Order Differential Tests

## Why

`pyasn1.type.opentype.OpenType` stores its OID→schema map **by reference**
and resolves the governing OID at decode time. RFC modules in this package
mutate three shared maps with `dict.update(...)` at import time:

| Family | Map | Pristine entries | After all 130 RFC modules |
| --- | --- | --- | --- |
| CMS content types | `rfc5652.cmsContentTypesMap` | 7 | 46 |
| CMS signed attributes | `rfc5652.cmsAttributesMap` | 4 | 124 |
| Certificate extensions | `rfc5280.certificateExtensionsMap` | 22 | 56 |

A long-running backend that lazily imports modules as features activate can
therefore resolve the **same DER with different schemas depending on import
order**, altering how an object is interpreted.

## Components

- `tests/registry_order_worker.py` — runs in a **fresh interpreter** per
  order. Imports modules in the requested sequence, then emits a JSON snapshot
  of the three maps, a provenance-resolved decode of three fixed-DER fixtures,
  and their DER round-trip status.
- `tests/test_open_type_import_order.py` — orchestrates orders, classifies
  registry relationships, locates minimal module sequences, protects unknown
  OIDs, and validates the conflict discriminator.
- `pyasn1_modules/guarded_registry.py` — a **dict-compatible** provenance
  registry. Existing `map[oid] = spec` / `map.update(...)` call sites keep
  working; it additionally records every source and flags only *incompatible*
  overrides.

## Fixed DER fixtures (identical in every subprocess)

| Fixture | Governing OID | DER (hex) |
| --- | --- | --- |
| CMS `ContentInfo` | `1.2.840.113549.1.7.1` (`id_data`) | `302806092a864886f70d010701a01b04196f726465722d696e646570656e64656e742d636f6e74656e74` |
| CMS `Attribute` (unknown OID) | `1.3.6.1.4.1.99999.42.1` | `3023060a2b06010401868d1f2a01311504130001027261772d6d7573742d737572766965` |
| X.509 `Extension` (`BasicConstraints`) | `2.5.29.19` | `300f0603551d130101ff040530030101ff` |

## Discriminator

A registration is an **equivalent alias** if both schemas share the same
pyasn1 `typeId`, `tagSet` and `baseTagSet` (the same decoding contract).
Subclass-only differences such as `rfc7906.Classification(ESSSecurityLabel)`
or the duplicated `FriendlyName` in `rfc2985`/`rfc7292` are therefore
*aliases* and may coexist. It is an **incompatible override** only when the
fingerprints differ (e.g. OctetString vs Integer, universal tags `0x04` vs
`0x02`), and every contributing source is retained.

## Key findings in the shipped registries

Coverage (audit) relationships are preserved in every run even though no
true wire-incompatible override survives. Examples:

- Alias, CMS content type OID `1.2.840.113549.1.9.16.1.23`
  (`AuthEnvelopedData`): registered by `rfc5083`, re-asserted by `rfc6032`.
  Minimal exposing sequence: `[rfc5083]`.
- Alias, signed-attribute OID `1.2.840.113549.1.9.16.2.2`
  (`ESSSecurityLabel`/`Classification`): same wire schema across `rfc2634`,
  `rfc5035`, `rfc5126`, `rfc5752`, `rfc7906`.
- Alias, PKCS#9 `1.2.840.113549.1.9.20` (`FriendlyName`): BMPString schema
  in both `rfc2985` and `rfc7292`.
- Unknown OID `1.3.6.1.4.1.99999.42.1` stays an opaque `AttributeValue(Any)`
  with byte-identical re-encoding after all modules are imported — no
  unrelated module swallows it.

## Import failures are not findings

The worker returns `status: "import-error"` with the module and exception
metadata. The orchestrator collects these separately and never converts them
into a registry conflict. A synthetic failing module is used to demonstrate
this; all 130 shipped RFC modules import cleanly.

## Handling recommendation (non-breaking)

The guarded-registry prototype does not change any default behaviour:

1. Keep the public maps as `GuardedRegistry` (a `dict` subclass), so all
   existing explicit `map[...] = ...` and `map.update(...)` usage and every
   `OpenType` lookup remain valid.
2. On incompatible fingerprint, **do not** silently replace: retain the first
   registration as active, keep the incoming schema + source in
   `incompatible_overrides`, and expose the list for startup logging/metrics.
3. Emit a single `warnings.warn(...)` at most once per OID so strict
   applications can turn it into an error without breaking alias users.
4. Unknown OIDs continue to decode as opaque `Any` (current decoder
   behaviour); the guard never invents a schema for an unregistered OID.
5. Applications that need determinism can pin import order (or pre-import the
   feature set at startup) and assert `incompatible_overrides == {}`.
