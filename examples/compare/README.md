# `pip-audit-compare` fixtures

Each directory holds a `before.json` / `after.json` pair for one review
scenario. `before.json` is the pre-upgrade report and `after.json` is the
post-upgrade report; the pairs are also used to check that swapping the two
inputs yields the inverse review.

| Directory      | Scenario                                | Expected outcome                                                                    |
| -------------- | --------------------------------------- | ----------------------------------------------------------------------------------- |
| `fixed`        | `requests` upgraded `2.30.0 -> 2.32.3`  | `CVE-2024-35195` is `fixed`; the upgrade is recorded as evidence.                   |
| `removed`      | `pyyaml` no longer installed            | `CVE-2020-14343` is `resolved-by-removal`; the package absence is evidence.         |
| `not-reported` | `jinja2` unchanged, advisory absent     | `GHSA-h5c8-rqwp-cp95` is `not-reported`; no upgrade evidence, so not "fixed".       |
| `downgrade`    | `urllib3` downgraded `2.2.1 -> 1.26.18` | `CVE-2024-37891` is still present at a lower version; reported as `still-reported`. |

The `removed` pair intentionally uses the legacy report shape (a bare JSON
array) for `before.json`. That is the shape `pip-audit` emitted before 2.0
and it has no `fixes` array, so the comparison must rely on the dependency
list alone.

Run a pair with:

```console
$ pip-audit-compare examples/compare/fixed/before.json examples/compare/fixed/after.json
```
