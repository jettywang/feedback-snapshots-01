# TUF Dependency Admission Planner

A planning-only install backend built on python-tuf. It turns the dependency
closure of one root package into an `InstallationPlan` that a separate
installer can execute. The planner never downloads target files and never
installs anything: it only reads signed TUF metadata.

## Dependency declarations

Every package target carries its dependencies in the standard TUF
`custom` field:

```json
{
  "length": 19,
  "hashes": {"sha256": "..."},
  "custom": {
    "dependencies": [
      {"path": "packages/lib/core-2.1.tar", "sha256": "<64 hex chars>", "optional": false},
      {"path": "packages/optional/extras-0.3.tar", "sha256": "<64 hex chars>", "optional": true}
    ]
  }
}
```

Each entry contains the in-repository target `path`, the pinned `sha256`
digest and whether the dependency is `optional`.

## Admission rules

- **Authorization comes from TUF target lookup, not from declarations.**
  Each path is resolved with the standard `Updater` pre-order walk of the
  delegation graph, including terminating delegations and signature
  verification. A package writing another path into its own
  `custom.dependencies` does not grant itself publication rights for that
  path. The plan records the role (and delegating parent) that actually
  answered each lookup.
- **One client snapshot for the whole closure.** A single
  `AuthenticatedUpdater` performs one `refresh()`; every subsequent lookup is
  served from that snapshot, so metadata versions can never be mixed.
- **Pinned digests are checked against signed metadata**, never against
  downloaded bytes. Target content is never fetched.
- **Failures are all-or-nothing.** Missing required dependencies, digest
  mismatches, dependency cycles and same-path requirements pinning different
  digests reject the entire plan; no partial plan is returned.
- **Optionality is narrow.** An optional dependency is skipped only when no
  role publishes it. Unsigned or malformed delegated metadata raises instead
  of being treated as "not published".

## Layout

- `planner.py` — `AuthenticatedUpdater` (lookup + authorizing role) and
  `DependencyPlanner` (closure resolution, conflict/cycle checks, stable
  Kahn topological order).
- `models.py` — `DependencyRequirement`, `TargetAuthorization`,
  `PlannedPackage`, `InstallationPlan`.
- `exceptions.py` — typed planner failures.
- `demo_repo.py` — in-memory `RepositorySimulator` with a shared dependency
  and a terminating delegation, plus fault injection helpers.
- `demo.py` — runnable end-to-end demonstration.

## Demo and tests

```sh
python -m install_planner.demo
python -m pytest tests/test_install_planner.py -q
```
