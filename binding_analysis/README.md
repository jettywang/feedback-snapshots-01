# binding_analysis — restricted static binding analysis

Decides, for every imported (undefined) dynamic symbol of an ELF module,
whether another module can take over the binding. Built on pyelftools;
purely static: nothing is loaded, executed, or borrowed from the host.

## Model

* The caller explicitly provides the module set **and** its load order
  (`BindingAnalyzer(paths)`). The analyzer never discovers dependencies on
  its own; `DT_NEEDED` entries missing from the set are reported as scope
  notes.
* Scope lookup follows the given order (first definition wins), with the
  documented ELF exceptions:
  * `STV_PROTECTED` / `STV_HIDDEN` / `STV_INTERNAL` definitions pin
    references issued by the defining module;
  * `DF_SYMBOLIC` searches the module's own definitions first;
  * `RTLD_DEEPBIND` is a `dlopen()` flag, not an ELF bit, so the caller
    declares it (`deepbind_modules={...}`); only its self-first lookup
    effect is modeled.
* GNU symbol versioning is honored: a versioned reference requires a
  matching non-hidden version definition, or an unversioned definition in a
  module with no version definitions at all; an unversioned reference
  ignores hidden (non-default) versions.

## Result classification

Each import gets one `Resolution` with a three-way certainty:

* `definite` — `pinned-local` (protected/hidden/symbolic self-bind, not
  replaceable) or `unique-provider` (exactly one candidate);
* `multiple-candidates` — `contested`: several modules define the symbol,
  the winner follows the caller-provided order, and the import is
  replaceable;
* `policy-dependent` — `unresolved-weak` (binds to 0 unless runtime policy
  supplies a definition) or `unresolved-strong` (no provider inside the
  modeled set); whether the import can be replaced is undecided.

Every candidate carries the actual `.dynsym` evidence (module, symbol
index, binding, visibility, version, value).

## Demo

```
.venv/bin/python examples/static_binding_analysis.py
```

builds a short synthetic ELF set (plain override, protected definition,
unresolved weak reference, versioned import, `DF_SYMBOLIC`) and prints the
full report. Tests: `test/test_static_binding.py`; synthetic ELF fixtures:
`test/binding_fixtures.py`.
