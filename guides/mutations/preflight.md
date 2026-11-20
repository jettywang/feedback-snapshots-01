# Preflight (dry-run) authorization

Sometimes a client submits several updates at once -- for example, a page that saves a batch of form changes. The server may want to check permissions for the _whole_ batch before deciding which updates to apply.

`GraphQL::Schema.preflight` does that: it runs the authorization hooks for a mutation document but never calls `resolve`, so no data is written.

## Example

```ruby
batch = MySchema.preflight(<<~GRAPHQL, context: { current_user: viewer })
  mutation {
    a: updatePost(postId: "1", title: "First") { ok }
    b: updatePost(postId: "2", title: "Second") { ok }
    c: deletePost(postId: "3") { ok }
  }
GRAPHQL

batch.each do |result|
  if result.authorized?
    # Apply this update outside of preflight (or call the mutation for real).
  else
    # Reject it and report result.errors
  end
end
```

It returns a `GraphQL::Schema::Preflight::Batch`. `Batch#[]` / `#fetch` look up a result by response key (`"a"`, `"b"`, ...), and the Batch itself is enumerable.

## What runs

For each top-level mutation field, preflight:

- coerces the arguments (including variables)
- calls `ready?`
- resolves `loads:` arguments through `Schema.object_from_id` or `load_*` (just like execution)
- checks each loaded object with its type's `.authorized?(object, context)`
- runs argument `authorized?` hooks
- runs the mutation's `#authorized?(**loaded_args)`
- runs the mutation class's `.authorized?(object, context)`

For Relay Classic mutations (`RelayClassicMutation`), `input:` is flattened before `ready?` and `authorized?` run, matching real execution.

Preflight **never calls `resolve` or `call_resolve`**. If a bug tries to, it raises instead of writing.

## Keep hooks read-only

`loads:` hooks and `ready?` / `authorized?` still run during preflight. They must not write data or cause other side effects. Put side effects in `resolve`, where they belong.

## Results are not authorization tokens

Each result is a snapshot of one check, not a permission that can be stored and reused later. Permissions and data can change between the check and the write, so a stale "yes" is dangerous.

Results enforce this:

- `result.authorized?` is `false` once the result is consumed, or older than `Schema.preflight_max_age` (30 seconds by default; set `nil` to disable).
- `result.checked?` is the original boolean, for reporting only.
- `result.consume!` spends the result.
- `result.recheck!(context: fresh_context)` spends the old result and runs the check again with fresh permissions. Use this right before applying a change:

```ruby
if result.authorized? && result.recheck!(context: fresh_context).authorized?
  # Apply the update
end
```

`result.to_h` is deterministic for the same document, context, and data, and includes `authorized`, `checked`, and `consumed` fields, so it can be logged. Don't feed a cached `to_h` back into your authorization logic.

## Limits

`preflight` only accepts mutation documents. It also rejects documents with more than `max_fields:` root fields (default `50`) so a single request can't trigger unbounded `loads:` work:

```ruby
MySchema.preflight(doc, context: ctx, max_fields: 20)
```

Static validation errors are reported per field (with no hooks run), and missing fields are reported instead of raising.
