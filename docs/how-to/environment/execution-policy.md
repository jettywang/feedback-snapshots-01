# How to gate execution in automated services

-----

An automated service often wants to prepare a project's environments without letting the project
run arbitrary code. Hatch ships an **optional runtime execution convention** that separates the two
stages of that workflow:

- **Prebuild** — create an environment and install the dependencies the project declares.
- **Execute** — run project-owned code: the project's install step, its pre/post-install commands,
  commands passed to `hatch run` / `hatch env run`, and executable plugin callbacks such as [build
  hooks](../../plugins/build-hook/reference.md).

The convention is disabled unless you opt in, so nothing changes for normal interactive use.

## Enabling the convention

Set the `HATCH_EXECUTION_POLICY` environment variable (or the `--execution-policy` [root
option](../../cli/reference.md#hatch)) to the stages you want to allow:

| Value | Prebuild | Execute |
| --- | --- | --- |
| unset / `0` / `false` | :white_check_mark: | :white_check_mark: |
| `prebuild` | :white_check_mark: | |
| `execute` | :white_check_mark: | :white_check_mark: |

`execute` always implies `prebuild`. A list may also be given, e.g. `HATCH_EXECUTION_POLICY="prebuild,execute"`.

With only `prebuild`, Hatch creates environments and installs their **declared** dependencies — the
project can still prepare itself — but every executable action is blocked:

```console
$ HATCH_EXECUTION_POLICY=prebuild hatch env create
Creating environment: default
```

```console
$ HATCH_EXECUTION_POLICY=prebuild hatch run test:unit
Execution of `pytest` was denied (project-command, environment `test`). Approve this exact action with HATCH_EXECUTION_APPROVAL=… or HATCH_EXECUTION_APPROVAL=* to approve execution broadly.
```

## Approving executable actions

Granting the **execute** stage is necessary but not sufficient: each executable action must also be
approved. When an action is denied, Hatch prints its fingerprint. Pass one or more fingerprints with
`HATCH_EXECUTION_APPROVAL` (or repeat `--approve`):

```console
$ HATCH_EXECUTION_POLICY=execute HATCH_EXECUTION_APPROVAL=ebe1bbb6148069df hatch run test:unit
```

Use `*` to approve every executable action for the run:

```console
$ HATCH_EXECUTION_POLICY=execute HATCH_EXECUTION_APPROVAL='*' hatch run test:unit
```

### Project commands and plugin callbacks are separate

A project command and an executable plugin callback are never conflated, even when their command
text is identical. Approving `pytest` as a project command does not approve a build hook that
happens to invoke `pytest`. This keeps the two trust boundaries — the project's own commands and the
build backend's plugin callbacks — independent.

### The decision follows the action, not the environment

An action's fingerprint is derived from its phase, category, environment name, and the command
text. It deliberately excludes the working directory and any transient state. As a result:

- Changing directories (for example, when a command runs from a subdirectory) does not change the
  decision.
- Retrying after an exception observes the same decision. A retry of an approved action that failed
  is allowed to run again; a refused action stays refused.

## Producing a comparison record

Set `HATCH_EXECUTION_JOURNAL` to a file path to write a JSON record of every attempted action. This
is intended for automated callers that need to prove what ran:

```console
$ HATCH_EXECUTION_POLICY=prebuild HATCH_EXECUTION_JOURNAL=execution.json hatch env create
$ cat execution.json
{
  "version": 1,
  "policy": {"enabled": true, "phases": ["prebuild"], "approvals": []},
  "totals": {"executed": 1, "denied": 0, "deferred": 1, "failed": 0},
  "events": [
    {"phase": "prebuild", "category": "provision", "label": "create-environment", "allowed": true, "status": "executed"},
    {"phase": "execute", "category": "project-command", "label": "install-project", "allowed": false, "status": "deferred"}
  ],
  "pending": [
    {"phase": "execute", "category": "project-command", "label": "install-project", "environment": "default", "fingerprint": "fcd9bcc1dc9d9957"}
  ]
}
```

Each event has one of these statuses:

| Status | Meaning |
| --- | --- |
| `executed` | The action ran. |
| `denied` | The action was blocked and did not run. |
| `deferred` | An executable step encountered during prebuild that will run once approved. |
| `failed` | An approved action raised; a retry may run it again. |
| `allowed` | The action was permitted but not executed through the run path (for example, when checked explicitly). |

The `pending` list contains the execute actions a run would perform if approved — each with the
fingerprint to pass to `HATCH_EXECUTION_APPROVAL`.

!!! tip
    The journal is written on every exit path, including failures, so a caller can always compare
    the attempted actions against what was permitted.
