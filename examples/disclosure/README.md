# Disclosure example: public summary vs. internal work order

This example runs the real `pip-audit` CLI path against a throwaway set of
installed distributions. Only the OSV HTTP session is replaced, with a
deterministic fixture, so the example works offline and does not depend on a
live advisory database.

## What gets produced

| Artifact | Audience | Destination |
| --- | --- | --- |
| ordinary CLI output (`--format json`) | whoever runs the audit | stdout (or `--output`) |
| `internal.json` | operations / remediation | `--internal-report` |
| `public.json` | public disclosure | `--public-report` |

The ordinary CLI output is unchanged and remains a full-fidelity artifact. Do
not publish it. Use `--public-report` for publication.

## Run it

```console
$ python examples/disclosure/run.py success "$TMPDIR/disclosure/success"
$ python examples/disclosure/verify.py success "$TMPDIR/disclosure/success"

$ python examples/disclosure/run.py failure "$TMPDIR/disclosure/failure"
$ python examples/disclosure/verify.py failure "$TMPDIR/disclosure/failure"
```

Both run modes exit non-zero (`1`) because the fixture contains findings and
because the failure mode aborts the audit. That is expected; `verify.py`
checks the artifacts, not the audit exit code.

The success directory contains:

```text
public-allowlist.txt   # only "public-lib" is approved for publication
site-packages/         # fake installed distributions
public.json            # allowlisted projection
internal.json          # full remediation work order
```

The failure directory contains the same inputs but only `internal.json`. The
public report is deliberately absent.

## The local fake dependencies

`fake_environment.py` writes three `.dist-info` directories under
`site-packages/`:

| Distribution | Version | Why it exists |
| --- | --- | --- |
| `public-lib` | `1.0.0` | allowlisted; has a public advisory |
| `internal-payments-lib` | `1.2.3` | private; has a private advisory |
| `internal-broken-lib` | `NOT-A-VERSION` | exercises the skipped-dependency path |

`pip list --path` accepts these directories, so `pip-audit --path` exercises
the real `PipSource`, the real `Auditor`, and the real formatters.

## The failing service

`osv_fixture.py` answers two queries and then raises
`requests.ConnectTimeout` on the third. That exercises the real
`OsvService.query` translation into `pip_audit._service.interface.ConnectionError`
and the real CLI failure path.

## The four data classes and where each goes

| Data | Public `public.json` | Internal `internal.json` | Ordinary CLI output | `stderr` |
| --- | --- | --- | --- | --- |
| allowlisted dependency name | yes | yes (`"visibility": "public"`) | yes | summary counts only |
| private dependency name | no | yes (`"visibility": "private"`) | yes | no |
| vulnerability ID / aliases / fix versions | yes, token-validated | yes | yes | no |
| advisory description | **no** | yes | yes, with `--desc` | no |
| skip reason | **no** | yes | yes, in manifest/columns/markdown | only with `--strict` |
| exception message / traceback | **no field exists** | yes, in `error` | no | yes |

The public report is not a redacted copy of the ordinary output. It is built
from `PublicDependencyFact` / `PublicVulnerabilityFact` values, which have no
description, skip-reason, or error fields. See
`pip_audit/_disclosure.py`.

## Publication rules enforced by the CLI

1. `--public-report` requires `--public-allowlist`.
2. `--public-report` cannot be combined with `--dry-run` (unless `--fix` also
   makes the run a fix dry-run).
3. The public report, internal report, ordinary output, and allowlist must all
   be different files.
4. The public report target is removed before the audit starts, so a failed
   run leaves no public artifact behind.
5. The public report is validated immediately before it is written: names must
   be allowlisted, identifier/version fields must be machine tokens, and no
   private dependency name or free-form advisory/skip text may appear.
6. The public report is written atomically with mode `0644`; the internal work
   order is written atomically with mode `0600`.

## Evidence to check

`verify.py` asserts:

- the public report names only `public-lib`;
- the public report has no `description`, `skip_reason`, `error`, or
  `traceback` keys;
- the public report contains none of the fixture's private names, paths, or
  advisory markers, including inside the **public** package's advisory text;
- the internal report names all three distributions, keeps the private
  description and skip reason, and labels visibility;
- the failure run has no `public.json`, while `internal.json` has
  `"status": "failed"` and a structured `error`.
