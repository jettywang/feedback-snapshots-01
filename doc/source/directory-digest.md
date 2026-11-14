# Directory Artifact Digests

in-toto can record an entire directory as a single artifact (one name, one
hash) instead of enumerating every file. Two independent schemes exist:

* `dir:` — the legacy scheme, kept stable for backward compatibility. Existing
  link metadata continues to verify exactly as before.
* `dirv2:` — an explicitly versioned scheme with an unambiguous, locale-free
  binary serialization. Use it for new evidence.

The two schemes are never equivalent: they use different URI schemes, different
serializations and therefore different digest values. A verifier MUST NOT treat
a `dir:` digest and a `dirv2:` digest for the same path as interchangeable.

## Legacy `dir:` Scheme

For a directory URI the legacy
{py:class}`~in_toto.resolver.DirectoryResolver` hashes the regular files inside
the directory, equivalent to:

```bash
find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum \
  | sha256sum | cut -f1 -d' '
```

Limitations that motivated `dirv2:`:

* Sorting relies on the process locale (`LC_ALL=C`) and mutates global locale
  state.
* Entries are joined as text lines, so a file name containing a newline can be
  confused with a record boundary; non-ASCII names depend on text encoding.
* Only regular files are represented. Empty directories and the distinction
  between a file and a directory at the same relative path are not captured, so
  structurally different trees can produce the same digest.

This behavior is intentionally frozen. Do not change it, or historical link
metadata will stop verifying.

## Versioned `dirv2:` Scheme

{py:class}`~in_toto.resolver.DirV2Resolver` builds a canonical byte string and
returns its SHA-256. Everything is defined in bytes, so the result does not
depend on locale, platform line endings, or text newline handling.

### Serialization

The message starts with a fixed preamble and is followed by one record per
traversed entry (files, directories and symbolic links):

```text
dirv2 0x1e
<entry-name> 0x1f <type> 0x1f <digest> 0x1e
<entry-name> 0x1f <type> 0x1f <digest> 0x1e
...
```

* `0x1e` (ASCII Record Separator) terminates each record, including the
  preamble.
* `0x1f` (ASCII Unit Separator) delimits the three fields inside a record.
* `entry-name` is the path relative to the hashed directory, with backslashes
  normalized to forward slashes, encoded as UTF-8. It may contain arbitrary
  characters including newlines and non-ASCII text; the control-byte separators
  keep them unambiguous.
* `type` is one of:
  * `f` — regular file,
  * `d` — directory,
  * `s` — symbolic link.
* `digest` depends on the entry type:
  * `f`: SHA-256 of the file content (line endings normalized when
    `normalize_line_endings` is enabled),
  * `d`: empty; the entry's presence and type are the relevant information,
  * `s`: SHA-256 of the link target string encoded as UTF-8.
* Records are sorted by the raw UTF-8 bytes of `entry-name` (a plain byte-wise
  ordering with no locale or collation table).
* The directory digest is the SHA-256 of the complete message.

An empty directory contains only the preamble, i.e. `b"dirv2\x1e"`, so its
digest is distinct from the legacy empty-input digest
(`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

### Semantics

* **Sorting.** Byte-wise ordering of UTF-8 entry names; identical on every
  platform and under any locale.
* **Empty directories.** Recorded as `d` entries. A tree that only differs by
  an empty subdirectory produces a different digest.
* **Symbolic links.** A linked file is always recorded as an `s` entry whose
  digest covers its target name. A linked directory is recorded as a single `s`
  entry when `follow_symlink_dirs` is false; when it is true, the target tree is
  enumerated under the link's name instead. Broken symlinks cannot be read and
  are skipped.
* **Exclude patterns.** Gitignore-style patterns apply to entries *inside* each
  directory, never to the directory URI itself. Excluding a directory removes
  that directory entry and everything beneath it.
* **Path prefix stripping.** `lstrip_paths` only changes the artifact name
  stored in the result dictionary; it never changes the digest.

### Recomputing and Migrating

* `tests/dirv2_recompute.py` is a standalone, standard-library-only
  implementation of this format. Point it at a directory to recompute its
  digest independently of the in-toto package:
  `python tests/dirv2_recompute.py PATH`.
* `tests/dirv2_migration_example.py` shows a dual-record migration: a directory
  is recorded under both `dir:` and `dirv2:`, the historical `dir:` proof is
  re-verified with the legacy resolver, and the new `dirv2:` proof is verified
  with both the new resolver and the standalone script.
