
ASN.1 modules for Python
------------------------
[![PyPI](https://img.shields.io/pypi/v/pyasn1-modules.svg?maxAge=2592000)](https://pypi.org/project/pyasn1-modules)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyasn1-modules.svg)](https://pypi.org/project/pyasn1-modules/)
[![Build status](https://github.com/pyasn1/pyasn1-modules/actions/workflows/main.yml/badge.svg)](https://github.com/pyasn1/pyasn1-modules/actions/workflows/main.yml)
[![Coverage Status](https://img.shields.io/codecov/c/github/pyasn1/pyasn1-modules.svg)](https://codecov.io/github/pyasn1/pyasn1-modules)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/pyasn1/pyasn1-modules/master/LICENSE.txt)

The `pyasn1-modules` package contains a collection of
[ASN.1](https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.208-198811-W!!PDF-E&type=items)
data structures expressed as Python classes based on [pyasn1](https://github.com/pyasn1/pyasn1)
data model.

If ASN.1 module you need is not present in this collection, try using
[Asn1ate](https://github.com/kimgr/asn1ate) tool that compiles ASN.1 documents
into pyasn1 code.

**NOTE:** The package is now maintained by *Christian Heimes* and
*Simon Pichugin* in project https://github.com/pyasn1/pyasn1-modules.

Offline manifest view checking
------------------------------

`pyasn1_modules.rfc6486_manifest_view` checks whether a local repository
directory is a complete RFC 6486 manifest generation.  It assumes the
manifest signature was already verified, never touches the network or the
filesystem, and considers only the candidate mapping it is given, so files
not listed on the manifest cannot enter the trusted view.

```python
from pyasn1_modules import rfc6486_manifest_view

view = rfc6486_manifest_view.evaluate(
    manifest_econtent, candidates, previous=accepted, checked_at='20261115000000Z')

if view.state == 'verified':
    use(view.files)          # the closed set of consumable files
else:
    inspect(view.issues)     # per-file missing/extra/mismatch/manifest defects
```

Missing files, extra files, hash mismatches, stale or rolled-back manifests
and signature failures are reported as distinct issue codes and states
rather than a single boolean.  `evaluate_generation` applies the RFC 6486
current-manifest rule to several manifests and refuses to substitute an
older complete manifest for an incomplete current one.

`tools/manifest-view-check.py` demonstrates an interrupted sync where each
file is individually valid but the merged directory belongs to no complete
generation.

Feedback
--------

If something does not work as expected, 
[open an issue](https://github.com/pyasn1/pyasn1-modules/issues) at GitHub
or post your question [on Stack Overflow](https://stackoverflow.com/questions/ask)
 
New modules contributions are welcome via GitHub pull requests.

Copyright (c) 2005-2020, [Ilya Etingof](mailto:etingof@gmail.com).
All rights reserved.
