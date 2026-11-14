# RFC 6031 MFA symmetric-key import planner

This package turns an **already decrypted and authenticated** CMS Symmetric
Key Package (RFC 6031) into an immutable, fully validated *import plan* for an
MFA backend.  It never decrypts or verifies a package itself and never writes
a credential: planning and storage are separate phases so the caller stays in
control of persistence.

## Flow

1. The transport/CMS layer decrypts and authenticates the package and hands a
   `pyasn1_modules.rfc6031.SymmetricKeyPackage` (or its
   `rfc5652.ContentInfo` wrapper) to `build_import_plan()`.
2. The planner performs every check in one pass and returns an
   `ImportPlan`.  A single failure sets `importable=False`; the plan still
   carries a non-secret summary and one `ValidationIssue` per finding.
3. Only when `importable` is true does the caller pass the plan to a
   `CredentialStore` through `install_plan()`.  Installation stages every
   credential first and commits once, rolling back on any failure, so a
   rejected plan never leaves a partial credential behind.

## What is validated

- **Attribute scope.** Package-level attributes (`sKeyPkgAttrs`, e.g.
  manufacturer, device validity) are kept distinct from per-key attributes
  (`sKeyAttrs`).  A misplaced or undefined OID blocks import.
- **Critical parameters.** Key id and algorithm are required; only the HOTP,
  TOTP and PIN PSKC algorithm profiles (RFC 6030) are understood, and every
  key must carry seed material.  Unknown algorithms or parameters make the
  whole plan non-importable.
- **HOTP/TOTP consistency.** HOTP requires an event counter and forbids time
  parameters; TOTP requires a positive time interval and forbids a counter.
  Response/challenge check digits are only valid with `DECIMAL` encoding.
- **Validity windows.** Inverted key or device windows are rejected, and each
  key window is checked against the device window jointly.
- **Usage.** OTP/PIN keys that declare usages must include `OTP`.
- **PIN association.** A `pinKeyId` must resolve to a different, PIN-profile
  key carried in the same package; dangling, self, or non-PIN references are
  rejected.
- **Identity.** Duplicate key ids are rejected; the same id bound to different
  seed material raises an additional seed-mismatch finding.

## Secret handling

- Seeds and PIN material live only on `CredentialEntry.seed` (excluded from
  `repr`) and are exposed solely through `CredentialEntry.seed_bytes()` for
  the storage callback.
- `ImportPlan.summary()`, `ValidationIssue` text and dataclass `repr()` never
  include seeds, PIN values, key material, or hex of material.
- Plans are frozen dataclasses populated from plain Python copies, so mutating
  the source ASN.1 object after planning cannot change an accepted plan.

## Demo and tests

```sh
.venv/bin/python demo_mfa_import.py
.venv/bin/python -m unittest tests.test_mfa_import
```

The demo exercises a legal two-key import, a second-key constraint conflict,
a cross-package PIN reference (and the same keys once the PIN key travels in
the package), all-or-nothing rollback, plan immutability, and secret hygiene.
