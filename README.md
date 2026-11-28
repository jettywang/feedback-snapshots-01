# pypi-attestations

<!--- BADGES: START --->
[![CI](https://github.com/pypi/pypi-attestations/actions/workflows/tests.yml/badge.svg)](https://github.com/pypi/pypi-attestations/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/pypi-attestations.svg)](https://pypi.org/project/pypi-attestations)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pypi-attestations.svg)](https://repology.org/project/python:pypi-attestations/versions)
<!--- BADGES: END --->

A library to generate and convert between Sigstore Bundles and [PEP 740]
Attestation objects.

> [!IMPORTANT]
> This library is an implementation detail within the reference implementation
> of [PEP 740]. Most users should not need to interact with it directly;
> see the [PyPI documentation] for full details.

## Installation

```bash
python -m pip install pypi-attestations
```

## Usage as a library

See the full API documentation [here].

### Signing and verification

Use these APIs to create a PEP 740-compliant `Attestation` object by signing a Python artifact
(i.e: sdist or wheel files), and to verify an `Attestation` object against a Python artifact.

```python
from pathlib import Path

from pypi_attestations import Attestation, Distribution
from sigstore.oidc import Issuer
from sigstore.models import ClientTrustConfig
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

dist = Distribution.from_file(Path("test_package-0.0.1-py3-none-any.whl"))

# Sign a Python artifact
trust_config = ClientTrustConfig.production()
issuer: Issuer = Issuer(trust_config.signing_config.get_oidc_url())
signing_ctx = SigningContext.from_trust_config(trust_config)

with signing_ctx.signer(issuer.identity_token(), cache=True) as signer:
    attestation = Attestation.sign(signer, dist)

print(attestation.model_dump_json())

# Verify an attestation against a Python artifact
attestation_path = Path("test_package-0.0.1-py3-none-any.whl.attestation")
attestation = Attestation.model_validate_json(attestation_path.read_bytes())
identity = policy.Identity(identity="example@gmail.com", issuer="https://accounts.google.com")
attestation.verify(identity=identity, dist=dist)
```

### Low-level model conversions

These conversions assume that any Sigstore Bundle used as an input was created
by signing a distribution file.

```python
from pathlib import Path
from pypi_attestations import Attestation
from sigstore.models import Bundle

# Sigstore Bundle -> PEP 740 Attestation object
bundle_path = Path("test_package-0.0.1-py3-none-any.whl.sigstore")
with bundle_path.open("rb") as f:
    sigstore_bundle = Bundle.from_json(f.read())
attestation_object = Attestation.from_bundle(sigstore_bundle)
print(attestation_object.model_dump_json())

# PEP 740 Attestation object -> Sigstore Bundle
attestation_path = Path("attestation.json")
with attestation_path.open("rb") as f:
    attestation = Attestation.model_validate_json(f.read())
bundle = attestation.to_bundle()
print(bundle.to_json())
```

## Usage as a command line tool

> [!IMPORTANT]
> The `pypi-attestations` CLI is intended primarily for
> experimentation, and is not considered a stable interface for
> generating or verifying attestations. Users are encouraged to
> generate attestations using [the official PyPA publishing action]
> or via this package's [public Python APIs].

````bash
pypi-attestations --help
usage: pypi-attestation [-h] [-v] [-V] COMMAND ...

Sign, inspect or verify PEP 740 attestations

positional arguments:
  COMMAND        The operation to perform
    sign         Sign one or more inputs
    verify       Verify one or more inputs
    inspect      Inspect one or more inputs
    convert      Convert a Sigstore bundle into a PEP 740 attestation

options:
  -h, --help     show this help message and exit
  -v, --verbose  run with additional debug logging; supply multiple times to
                 increase verbosity (default: 0)
  -V, --version  show program's version number and exit
````

### Signing a package

> [!NOTE]
> If run locally (i.e. not within GitHub Actions or another source of
> ambient OIDC credentials), this will open a browser window to perform
> the Sigstore OAuth flow.

```bash
# Generate a whl file
make package
pypi-attestations sign dist/pypi_attestations-*.whl
```

### Inspecting a PEP 740 Attestation

> [!WARNING]
> Inspecting does not mean verifying. It only prints the structure of
> the attestation.

```bash
pypi-attestations inspect dist/pypi_attestations-*.whl.publish.attestation
```

### Verifying a PEP 740 Attestation

```bash
pypi-attestations verify attestation  \
  --identity https://github.com/trailofbits/pypi-attestations/.github/workflows/release.yml@refs/tags/v0.0.19 \
  test/assets/pypi_attestations-0.0.19.tar.gz
```

### Verifying a release matrix

Single-artifact verification answers "is this artifact backed by this
attestation?". A release ledger answers a different question: "does this
release contain exactly the version/platform combinations we expect, each
with its own evidence?". Use `verify matrix` for the latter so one signed
attestation cannot be mistaken for approval of the whole release.

```json
{
  "version": 1,
  "name": "demo-project",
  "release": "1.2.3",
  "targets": [
    { "platform": "any" },
    { "platform": "manylinux_2_17_x86_64" },
    { "platform": "win_amd64", "reason": "Windows wheel is not produced for this release" },
    { "platform": null }
  ]
}
```

- Each target is a `(version, platform)` slot; `null` is the sdist.
- The verifier parses actual filenames to fill each slot, so it checks the
  version and platform recorded in the build itself.
- Every filled slot must have its own `*.publish.attestation` and/or
  `*.slsa.attestation`, and each attestation must name that exact artifact.
- A target with a `reason` may be absent; it is still listed as an uncovered,
  approved omission so the reason is preserved.

```bash
pypi-attestations verify matrix \
  --identity https://example.com/demo/.github/workflows/release.yml@refs/tags/v1.2.3 \
  --matrix-file test/assets/release-matrix-demo/matrix.json \
  --artifact-dir test/assets/release-matrix-demo \
  --trusted-root test/assets/release-matrix-demo/trusted_root.json
```

The checked-in demo is self-contained and cryptographically real: the
fixtures are signed by a local Sigstore test root, so the command verifies
fully offline. It reports:

```
Release matrix: demo-project 1.2.3
Admitted targets:
  OK   manylinux_2_17_x86_64: demo_project-1.2.3-...manylinux2014_x86_64.whl
  OK   sdist: demo_project-1.2.3.tar.gz
Uncovered targets:
  MISS any: incomplete evidence: ...attestation subject is '...linux...', expected '...py3-none-any.whl'
  MISS win_amd64 (approved omission): Windows wheel is not produced for this demo release
Artifacts without complete evidence:
  - demo_project-1.2.3-py3-none-any.whl
```

The universal wheel deliberately reuses the Linux wheel's attestation, so it
is reported as uncovered rather than admitted. Regenerate the fixtures with
`python tools/gen_release_matrix_demo.py`.

The command prints admitted targets, uncovered targets (with reasons), and
artifacts whose evidence is missing or incomplete. It exits non-zero while
any required target is uncovered. Use `--json` for machine-readable output,
and `--approved-platform PLATFORM=REASON` to exclude an additional target at
invocation time. Omit `--trusted-root` to verify against Sigstore's normal
TUF-backed production/staging root. The existing `verify attestation` command
remains the single-artifact investigation path.

### Verifying a PyPI package

> [!NOTE]
> The package to verify can be passed either as a path to a local file, a
> `pypi:` prefixed filename (e.g: 'pypi:sampleproject-1.0.0-py3-none-any.whl'),
> or as a direct URL to the artifact hosted by PyPI.

```bash
# Download the artifact (and its provenance) from PyPI and verify it
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  pypi:sigstore-3.6.1-py3-none-any.whl

# or alternatively, using the direct URL:
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  https://files.pythonhosted.org/packages/70/f5/324edb6a802438e97e289992a41f81bb7a58a1cda2e49439e7e48896649e/sigstore-3.6.1-py3-none-any.whl

# Verify the artifact and its provenance using local files
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  --provenance-file ~/Downloads/sigstore-3.6.1-py3-none-any.whl.provenance \
  ~/Downloads/sigstore-3.6.1-py3-none-any.whl
```

This command downloads the artifact, if needed, and its provenance from PyPI. The artifact
is then verified against the provenance, while also checking that the provenance's
signing identity matches the repository specified by the user.

### Converting a Sigstore bundle into a PEP 740 Attestation

```bash
pypi-attestations convert --output-file /tmp/rfc8785-0.1.2-py3-none-any.whl.publish.attestation  \
  test/assets/rfc8785-0.1.2-py3-none-any.whl.sigstore
```


## License
```
Copyright 2024 Trail of Bits

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```


[PEP 740]: https://peps.python.org/pep-0740/

[here]: https://pypi.github.io/pypi-attestations

[public Python APIs]: https://pypi.github.io/pypi-attestations

[the official PyPA publishing action]: https://github.com/pypa/gh-action-pypi-publish

[PyPI documentation]: https://docs.pypi.org/attestations
