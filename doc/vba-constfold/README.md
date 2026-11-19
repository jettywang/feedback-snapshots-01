# Traceable static constant-expression folding for VBA

`oletools/vba_constfold.py` adds **traceable** constant-expression results to
the static deobfuscation of VBA macros. For every expression it can evaluate,
it records not only the resulting string (or integer) but also:

- the **module** the expression came from and its exact **character span** and
  line, and
- a list of **recomputable derivation steps**, each tied to its own source
  span, so a reviewer can reproduce every transformation by hand.

It is fully static: **no VBA is executed and Python `eval`/`exec`/`compile`
are never used**. Every value comes from explicit arithmetic and string
helpers in the module.

## Why a separate folder

The existing pyparsing-based `detect_vba_strings` in `olevba.py` returns a flat
`(encoded, decoded)` pair without provenance and, in places, lets an
un-decidable sub-expression raise. This folder instead:

- keeps the source range and a step-by-step trace of each result;
- distinguishes **fully folded**, **partially folded** and **must stop**
  expressions;
- enforces explicit VBA integer type boundaries and reports overflow instead
  of wrapping or guessing;
- never bulk-decodes encoded strings found anywhere in the text — a value is
  only attached to an expression that was actually parsed and folded.

## Supported whitelist

Only pure, side-effect-free constructs are evaluated.

- Integer literals: decimal, `&H` hex and `&O` octal, with type suffixes
  `%` (Integer/16-bit), `&` (Long/32-bit), `^` (LongLong/64-bit).
- Arithmetic: `+ - * \ Mod ^` and unary `-`.
- Bitwise: `Not And Or Xor` and shifts `<< >>`.
- String concatenation with `&` (and `+` when both operands are strings).
- Parentheses, arbitrary nesting and line continuations (` _`).
- Functions: `Chr/Chr$/ChrB/ChrB$/Chr/ChrW$`, `Asc/AscB/AscW`, `Str/CStr`,
  `CInt/CLng/Hex`, `Len`, `Left/Right/Mid`, `UCase/LCase`,
  `Trim/LTrim/RTrim`, `Space`, `String`, `Replace`, `StrReverse`.

## Where evaluation must stop

When a value cannot be known statically, the folder **stops with a reason
instead of guessing**. Typical cases:

- unknown variable or identifier (no constant value available);
- object/member calls such as `Application.Environment` or `a!b`;
- a function outside the whitelist;
- comparison/logical operators and floating-point literals;
- floating-point division `/` (use integer `\`);
- division/`Mod` by zero;
- a result that overflows the declared VBA type;
- string-building built-ins past the safety cap.

### Type boundaries and overflow

Bare integer literals are *flexible*: like VBA, literal arithmetic may widen
`Integer -> Long -> LongLong` on overflow (`32767 + 1` becomes a `Long`). An
explicit suffix fixes the boundary, so `32767% + 1%` is reported as an
**overflow stop**, never wrapped. Each recorded step carries the VBA type it
was checked against.

## Result statuses

Each derivation step is tagged `derived`: `false` for quoted input literals
and `true` for anything computed from them (a function call, arithmetic,
bitwise operation or concatenation).

- `FULL` — the whole expression reduced to one constant; `value` is set.
- `PARTIAL` — at least one **derived** value was produced before folding
  stopped. For example `Chr(100) & obj.Environment` derives the concrete
  character `"d"`, then halts on the member call; retained `steps` show what
  was learned and `stop_reason` explains where it halted.
- `STOPPED` — no transformation completed. Quoted input literals may still be
  retained as non-derived steps (e.g. `"Shell" & Unknown` keeps the `"Shell"`
  input), and `stop_reason` explains why no value was produced. Pure
  arithmetic failures such as `10 \ 0` are STOPPED as well.

## API

```python
from oletools import vba_constfold as cf

# one standalone expression, always returns a FoldResult (never raises for an
# expected stop or syntax problem)
result = cf.fold_expression('Chr(65 + 2) & Chr(66)')
print(result.status, result.value)          # full 'CB'
for step in result.steps:                   # recomputable trace
    print(step['source'], '=>', step['result'], step['type'])

# scan a whole module; results stay bound to module + span
results = cf.evaluate_module('ThisDocument', module_source,
                             include_stops=False)
print(cf.format_trace(results))             # human-readable trace
[d.to_dict() for d in results]              # JSON-ready, span-annotated data
```

`include_stops=True` additionally surfaces `STOPPED` expressions and their
reasons. By default only evidence-bearing `FULL`/`PARTIAL` results are
returned.

## Command line

```
olevba --const-fold sample.xlsm
olevba --const-fold --const-fold-stops sample.docm
```

The trace is printed per module after the standard analysis. It is an opt-in
feature and does not change any existing olevba output when not requested.

## What this deliberately does not do

- It does **not** scan the whole document for hex/base64-looking strings and
  decode them in bulk, then claim those are values the program actually uses.
  A result is always the value of a specific parsed expression at a specific
  span, with the steps that produced it.
- It does not execute macros, call VBA runtimes, or evaluate Python code
  derived from the input.
- It does not invent values for unknown state; those expressions are reported
  as `PARTIAL`/`STOPPED` with an explicit reason.

## Demo and tests

- `doc/vba-constfold/demo_constfold.bas` — short module showing the same value
  from different sources, partially evaluable expressions, and expressions
  that must stop.
- `doc/vba-constfold/demo_trace.txt` — the generated, recomputable trace.
- `tests/olevba/test_constfold.py` — unit tests for every guarantee above.
