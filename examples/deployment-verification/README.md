# Deployment verification example

Internal dependency tooling sometimes rebuilds a wheel under an identical
name and version. Version-only checks cannot tell those builds apart, so
`pip-audit` provides a deployment verification entrypoint that fingerprints
the installed artifacts and compares them against a deployment lockfile:

```console
$ pip-audit --generate-deployment-lock [--path ENV] [-o LOCK]
$ pip-audit --verify-deployment LOCK [--path ENV]
```

Each locked package is reported as:

- `same-build`: the installed artifact's fingerprint matches the lockfile;
- `pending-evidence`: name and version match, but the lockfile records no
  `--hash=sha256:<digest>` evidence for the package;
- `build-mismatch`: name and version match, but the installed artifact is a
  different build (the expected and actual fingerprints are shown);
- `version-mismatch` / `not-installed`: the locked package is deployed at a
  different version, or not at all.

Verification exits nonzero exactly when a package is `build-mismatch`,
`version-mismatch`, or `not-installed`; `pending-evidence` is reported
without failing the gate. Locked and installed versions are always shown,
so remediation owners can see what is deployed regardless of the verdict.

## Running the demo

```console
$ PIP_AUDIT=../../.venv/bin/pip-audit ./run_example.sh
```

The script:

1. builds two wheels of `internal-widget==1.0.0` with different contents
   (`make_widget_wheel.py build-a` / `build-b`) and "installs" each into
   its own directory;
2. generates a deployment lockfile from the `build-a` environment;
3. verifies the `build-a` environment: `same-build`, exit 0;
4. verifies the `build-b` environment (same name, same version, different
   build): `build-mismatch`, exit 1;
5. strips the `--hash` evidence from the lockfile and verifies again:
   `pending-evidence`, exit 0, with versions still listed.

Generated files go to `.work/` and can be removed with `rm -rf .work`.
