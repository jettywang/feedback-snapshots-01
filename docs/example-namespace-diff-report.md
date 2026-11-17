# Example: Comparing the ISO9660, Joliet, Rock Ridge, and UDF namespaces

A hybrid ISO does not have a single filesystem tree.  It can carry up to four independent name-to-data views at once: the original ISO9660 namespace, the Joliet namespace, the Rock Ridge namespace, and (when present) a UDF namespace.  Each namespace has its own spelling for names, and a path that looks identical in two namespaces does **not** necessarily point at the same bytes.

Three different on-disk situations are easy to confuse if only paths are compared:

1.  **Hard links.** Several names resolve to the *same* inode and the same data extents.  This is always the case for a normal file that is visible from both ISO9660 and Joliet, and can also be created explicitly with [add_hard_link](api/pycdlib.html#pycdlib.pycdlib.PyCdlib.add_hard_link).
1.  **Independent, byte-identical copies.** Two names resolve to *different* inodes with separate data extents that happen to hold the same content.  Editing one would not change the other.
1.  **Different payloads.** Two names with the same display path resolve to different inodes with different content.

The read-only `pycdlib.namespacediff` module walks each namespace independently, records the original name, the location of the name record, and the data extent range(s) each name points at, then correlates the views without treating any namespace as authoritative.

## Building a small hybrid medium

This constructs a tiny ISO that contains all three situations at once.

```python
from io import BytesIO

import pycdlib
from pycdlib import namespacediff

iso = pycdlib.PyCdlib()
iso.new(joliet=3, rock_ridge='1.12', udf='2.60')

# One allocation, linked from every namespace: all four views are hard links.
shared = b'shared payload\n'
iso.add_fp(BytesIO(shared), len(shared),
           iso_path='/SHARED.;1', rr_name='shared',
           joliet_path='/shared', udf_path='/shared')

# An extra ISO9660/Rock Ridge name for that same inode.
iso.add_hard_link(iso_old_path='/SHARED.;1',
                  iso_new_path='/LINK.;1', rr_name='link')

# Same display path '/dup', but a separate allocation per namespace, each
# carrying byte-identical content (independent copies, not hard links).
dup = b'identical copy\n'
iso.add_fp(BytesIO(dup), len(dup), iso_path='/DUP.;1', rr_name='dup')
iso.add_fp(BytesIO(dup), len(dup), joliet_path='/dup')
iso.add_fp(BytesIO(dup), len(dup), udf_path='/dup')

# Same display path '/split' with genuinely different payloads.
iso.add_fp(BytesIO(b'iso payload\n'), 12,
           iso_path='/SPLIT.;1', rr_name='split')
iso.add_fp(BytesIO(b'joliet payload!\n'), 16, joliet_path='/split')
iso.add_fp(BytesIO(b'udf payload data\n'), 17, udf_path='/split')

# Extent locations are only assigned once the image is written, and the
# report is a read-only view of on-disk media, so write it out and reopen.
iso.write('hybrid.iso')
iso.close()

iso = pycdlib.PyCdlib()
iso.open('hybrid.iso')
report = namespacediff.build_report(iso)
```

## Reading the report

`build_report` returns a `NamespaceDiffReport`.  `namespaces` holds the per-namespace entries; `comparisons` groups entries by their display path and classifies each group.

```python
for comparison in report.comparisons:
    if comparison.path in ('/shared', '/dup', '/split'):
        print(comparison.path, '->', comparison.relation)
        print('   ', comparison.explanation)
```

For the ISO above this prints (in effect):

*   `/shared` -> `hard-link` — every present namespace resolves to one inode and one data extent range; the names differ only in their name mapping.
*   `/dup` -> `same-content-copy` — distinct inodes with separate extents hold byte-identical content; these are duplicates, not links.
*   `/split` -> `different-content` — distinct inodes with distinct extents and different bytes; equal paths do not mean equal data.

Each `NamespaceEntry` also keeps the forensic details:

```python
entry = report.namespaces['joliet'].entries[0]
print(entry.raw_name)         # original bytes as stored on disk (UTF-16 for Joliet)
print(entry.record_location)  # LBA/offset/size of the name record itself
print(entry.data_ranges)      # the data extents the name resolves to
print(entry.identity)         # equal for hard links, distinct for copies
```

## A corrupted namespace does not hide the others

Each namespace is enumerated in isolation, so a failure in one view is recorded without discarding the others.

```python
for name, result in report.namespaces.items():
    if result.error is not None:
        print(name, 'failed:', result.error)
    else:
        print(name, len(result.entries), 'entries')
```

The same report is available from the command line as `pycdlib-namespace-diff image.iso` (add `--json` for machine-readable output).  The tool exits non-zero when a namespace could not be enumerated, but still prints everything the healthy namespaces revealed.
