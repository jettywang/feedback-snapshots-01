# Lockfile auditing for Linux and macOS targets

One PEP 751 lockfile (`pylock.toml`) covers two environments:

| Target  | Decides                       |
|---------|-------------------------------|
| `linux` | the Linux service (`x86_64`)  |
| `macos` | the macOS desktop tool (arm64) |

The lockfile has conditional packages (`uvloop` only on Linux, `pyobjc-core`
only on macOS), two versions of `certifi` selected by platform, a Python-version
condition (`tomli`), a vulnerable `jinja2`, and one package guarded by a marker
value neither demo target specifies (`legacy-ctypes` on `platform_machine`).

Run the demo (no network; the advisory feed is in-memory):

```console
$ python examples/target-environments/demo.py
```

Or drive it from the CLI with the same targets:

```console
$ pip-audit --locked examples/target-environments \
    --target "linux:sys_platform=linux,platform_system=Linux,platform_machine=x86_64,python_version=3.12" \
    --target "macos:sys_platform=darwin,platform_system=Darwin,platform_machine=arm64,python_full_version=3.12.7" \
    --target-output /tmp/target-evidence
```

Expected behavior:

- `linux` selects `uvloop` and `certifi 2024.2.2`; `macos` selects
  `pyobjc-core` and `certifi 2024.8.30`.
- Packages whose marker does not hold are listed under **Excluded by
  condition** and are not audited for that target.
- `legacy-ctypes` is listed under **Cannot decide for this target** because
  `platform_machine` is unspecified; it is never silently dropped.
- Swapping the order of `--target` arguments produces byte-identical evidence
  files, since each target is collected and audited from scratch.
- A target outside the lockfile's `environments` (for example `windows`) gets
  its own result with an explicit error and exit code `2`.
