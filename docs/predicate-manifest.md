# Predicate manifests

`schema.manifest` produces an offline-verifiable inventory of every predicate
compiled into a schema. It exists to answer a narrow question during a security
review:

> After this upgrade, which fields must be approved again?

Comparing compiled predicate **names** is not enough. The compiled rule keeps the
name and arguments, but the callable that will run is resolved from the
predicate registry at build time. A child schema can replace `config.predicates`,
a gem can move a built-in predicate to a different implementation, and both keep
the same name. A name-only diff would call those fields unchanged when the code
that validates them has changed.

## Loading

The data model can be loaded on its own, which is what an offline reviewer needs:

```ruby
require "dry/schema/manifest"

Dry::Schema::Manifest.verify(File.read("child.json"))
Dry::Schema::Manifest.compare(
  JSON.parse(File.read("parent.json")),
  JSON.parse(File.read("child.json"))
)
```

Loading the extension additionally adds `#manifest` and `#manifest_changes` to
schema processors:

```ruby
Dry::Schema.load_extensions(:manifest)
```

## Building a manifest

```ruby
parent = Dry::Schema.define do
  required(:account).hash do
    required(:name).value(:string, min_size: 2, max_size: 32)
    required(:age).value(:integer, gt: 18)
  end
end

child = Dry::Schema.define(parent: parent) do
  config.predicates = MyPredicates

  required(:account).hash do
    required(:name).value(:string, max_size: 32, min_size: 2)
    required(:age).value(:integer, gt: 18)
  end
end

parent_manifest = parent.manifest(name: "parent")
child_manifest = child.manifest(name: "child")

File.write("parent.json", parent_manifest.to_json)
File.write("child.json", child_manifest.to_json)
```

Manifest generation is read-only. It walks the compiled rule objects and reads
method reflection (`source_location`, `owner`, `parameters`) and, where
available, the method body source. It never calls a rule, a predicate, or an
application callback.

## What is recorded

Each predicate occurrence produces an entry:

| Field | Meaning |
| --- | --- |
| `field` | Schema path, `account.name`, `items[].sku`, `(root)` |
| `occurrence` | Zero-based index when the same predicate appears more than once with the same identity |
| `logical_rule_path` | Enclosing operators with associative `and`/`or`/`set` groups collapsed, then the predicate |
| `rule_path` | Exact structural path in the compiled rule tree |
| `predicate` | Predicate name, e.g. `min_size?` |
| `args` | Tagged encoding of the arguments, so `:int`, `"int"` and `1` never collide |
| `approval_id` | Identity of the occurrence **and** its binding |
| `binding` | What will actually execute |

### Binding evidence

A binding is `builtin` only when all of these hold:

- the owning module is `Dry::Logic::Predicates::Methods`,
- the defining gem is `dry-logic`,
- the method body source is readable.

Built-in bindings record a `stable_id` derived from the predicate name,
arguments, owning module, gem-relative source path, and a SHA-256 of the method
body. The gem version and line number are deliberately excluded: a patch upgrade
that leaves the implementation byte-identical must not force re-approval, while
any change to the body does.

Everything else is a `runtime` binding and declares an **evidence gap**:

- custom predicate modules (`config.predicates = MyPredicates`),
- methods redefined or defined with `define_method` at runtime,
- monkey-patched predicate modules,
- C-implemented methods or platforms where the body cannot be read.

Runtime bindings have no `stable_id`. They remain approval-required even when
their owner, source location, and registry match, because equal metadata does not
prove equal behaviour. The manifest says so instead of pretending otherwise.

## Comparing manifests

```ruby
changes = Dry::Schema::Manifest.compare(parent_manifest, child_manifest)

changes.approval_required.map(&:field) # => ["account.age"]
```

Each change has a machine-readable `kind`:

| Kind | Meaning | Re-approval |
| --- | --- | --- |
| `unchanged` | Same occurrence, same binding | Only for runtime bindings |
| `proof_order` | Same predicates and bindings, only declaration order differs within one `and`/`or` group | No |
| `rebound` | Same field, predicate name, and arguments; different binding | Yes |
| `added` | New occurrence | Yes |
| `removed` | Occurrence no longer compiled | Yes |

`proof_order` exists because a rule's `and` operands are commutative. Declaring
`min_size: 2, max_size: 32` and then `max_size: 32, min_size: 2` changes the AST
but not the semantics. The manifest identifies those two entries by logical path,
so the change is visible in `rule_path` but does not request approval.

A rebinding of the same predicate name is the case name-only comparisons miss.
The change carries both bindings, the previous and current `stable_id`, and
`reasons` naming the exact differences (owner, source, body digest, registry).

## Approval artifacts

`changes.to_h` is JSON suitable for a committed artifact or an approval ticket,
and `changes.report` renders Markdown:

```ruby
File.write("changes.json", changes.to_json)
File.write("approval.md", changes.report)
```

`changes.report` includes an approval-basis section with the previous and current
binding for every field that needs re-approval, plus a table of runtime-only
evidence gaps from the current manifest.

## Integrity

Every document carries two SHA-256 digests:

- `entries`: the predicate entries,
- `document`: the whole document except the digests themselves.

`Dry::Schema::Manifest.verify(document)` recomputes both. A tampered predicate
name, argument, or binding is rejected. This is what makes a committed manifest
checkable without running the schema.

## Worked example

`examples/predicate_manifest.rb` builds a parent/child pair where:

- `account.name` only swaps two equivalent predicates,
- `account.age` keeps `gt: 18` but binds `gt?` to a recording module,

then asserts that the recording module received zero calls while the manifests
and the change set were produced:

```sh
ruby -Ilib examples/predicate_manifest.rb /tmp/manifests
```

Expected output includes:

```
Predicate calls during manifest generation: 0
Fields requiring re-approval: ["account.age"]
```

Set `DEMO_RUN_SCHEMA=1` to additionally validate an input and print the calls the
same recording module captures, proving the zero-call check is not vacuous:

```sh
DEMO_RUN_SCHEMA=1 ruby -Ilib examples/predicate_manifest.rb
# Calls recorded by an actual validation: [[18, 18]]
```
