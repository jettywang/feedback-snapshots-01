# Strict Artifact Recording

By default, in-toto records an artifact by opening its path and hashing the
bytes it reads. If another process replaces the path, truncates the file, or
adds or removes directory entries while recording is in progress, the resulting
hash can describe a different state than the one that was actually attested.

Strict recording makes such *observed* changes hard failures. It is available as
`strict=True` on the `in_toto_run`, `in_toto_record_start`, and
`in_toto_record_stop` APIs, and as `--strict` on the `in-toto-run` and
`in-toto-record` command line tools.

```{code-block} sh
in-toto-record start --step-name review --signing-key mykey \
    --materials . --strict
in-toto-record stop --step-name review --signing-key mykey \
    --products . --strict
```

When strict recording fails, `in_toto.exceptions.StrictRecordingError` is
raised (also available as the alias `ArtifactConsistencyError`). The exception
has `path` and `reason` attributes for the artifact and the detected
inconsistency. No partial materials or products are returned, and the failure
occurs before any metadata is signed or written. For `in-toto-record stop`,
the preliminary link file is left in place so the step can be retried.

## What is checked

- A file is opened once. Its device and inode are captured from the open
  descriptor, and the path is checked to name that same file before and after
  reading. If the path starts naming a different file, recording fails. The
  replacement is never reopened or hashed, even if it has identical content.
- Hashing uses only bytes read from the originally opened descriptor. After
  each chunk, identity, size, mtime, and ctime are compared with the values
  observed at open time. If fewer bytes are read than the size observed at open
  time, recording fails. This detects truncation and in-place modification
  that the filesystem reports between reads.
- Directories are snapshotted when entered, and re-listed after recording all
  reachable entries. Added, removed, or replaced entries, including new
  directories, fail recording. So does a directory path that no longer refers
  to the same filesystem object.
- An explicitly passed artifact that does not exist, or that is neither a
  regular file nor a directory, fails recording instead of being silently
  skipped as in non-strict mode.
- OSTree artifacts are rejected in strict mode, because their refs and commit
  objects are not read with these checks.

## What is not checked

Strict recording is not a transaction and does not take a filesystem snapshot.
Ordinary file reads cannot prove that the entire directory tree was in one state
at a single instant. In particular, the following changes can go unobserved:

- A path replaced and restored to the same inode (or content modified and
  restored with identical size, mtime, and ctime) outside the check points.
- A file modified after its final verification but before metadata is signed.
- A file whose content changes without any change in identity, size, mtime,
  ctime, or readable bytes, including changes made through another hard link
  or by a writer that preserves timestamps.
- A file modified after it was hashed, if a later re-listing happens to observe
  an unchanged size and mtime, for example on filesystems with coarse
  timestamps.
- Directory entries added and removed between the snapshot and the final
  re-listing, including entries outside excluded patterns. Excluded entries
  are not part of the snapshot.
- Files outside the passed paths, and changes that occur after recording
  completes.
- Filesystems that do not report stable identity or timestamps, or where
  another process can write through an already open file without changing them.

Use strict recording together with a trusted execution environment and
appropriate path selection when stronger guarantees are required.
