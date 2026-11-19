# Policy Lookup

Action Policy tries to automatically infer policy class from the target using the following _probes_:

1. If the target is a `Symbol`:

    a) Try `"#{target.to_s.camelize}Policy"` as a `policy_name` (see below);

    b) If `String#classify` is available, e.g. when using Rails' ActiveSupport, try `"#{target.to_s.classify}Policy"`;

2. If the target responds to `policy_class`, then use it;
3. If the target's class responds to `policy_class`, then use it;
4. If the target or the target's class responds to `policy_name`, then use it (the `policy_name` should end with `Policy` as it's not appended automatically);
5. Otherwise, use `#{target.class.name}Policy` or `#{target.name}Policy` if target is a Module or Class.

> \* [Namespaces](namespaces.md) could be also be considered when `namespace` option is set. You can also set the `strict_namespace` option to disable constant cascade lookup.

When `strict_namespace: true` is set together with a `namespace`, the lookup must resolve a policy defined **inside** that namespace. It no longer cascades to parent or top-level (public/tenant) policies. If no such policy exists, an `ActionPolicy::NotFound` error is raised whose message names the strict namespace and the expected policy class, so the failure can be located quickly. The error also exposes the `namespace`, `strict_namespace` and `policy_name` readers. Calls that do not opt into strict mode keep the original cascade fallback.

You can call `ActionPolicy.lookup(record, options)` to infer policy class for the record.

When no policy class is found, an `ActionPolicy::NotFound` error is raised.

When Rails instrumentation is enabled, every lookup fires an `action_policy.lookup` notification. Its payload contains the `target`, `namespace`, `strict_namespace` flag and the `policy` class that was finally adopted (`nil` when the lookup returned no policy).

You can [customize lookup](custom_lookup_chain.md) logic if necessary.
