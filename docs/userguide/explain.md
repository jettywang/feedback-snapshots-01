---
title: Explaining
description: How to explain object-level permission decisions for support and audit tooling.
---

# Explain permission decisions

Boolean checks (`has_perm`) tell you *whether* an identity has a permission,
but not *why*. When support asks "the detail view opens, why is the object
missing from my list?", a bare boolean is not enough. Guardian offers an
optional, opt-in explanation API for trusted callers (support desks, audit
tooling) that distinguishes:

- **direct** object permissions assigned to the user,
- **group** permissions inherited through group memberships,
- **global** (model-level) permissions, which affect
  `get_objects_for_user(..., accept_global_perms=True)` and Django's
  model-wide `user.has_perm('app.codename')` but not object-level checks.

The plain boolean interfaces are unchanged; explanations are available only
through the explicit `explain_perm` methods.

## Explaining a single decision

```python
>>> from guardian.core import ObjectPermissionChecker
>>> checker = ObjectPermissionChecker(joe)
>>> explanation = checker.explain_perm('change_site', site)
>>> explanation.allowed
True
>>> explanation.sources
['group:editors']
>>> print(explanation)
ALLOW sites.change_site for joe on <Site: example.com>: granted via group:editors
```

The same capability exists on the authentication backend, applying the same
user/object support checks as `has_perm`:

```python
>>> from guardian.backends import ObjectPermissionBackend
>>> ObjectPermissionBackend().explain_perm(joe, 'sites.change_site', site)
PermissionExplanation(..., allowed=True, sources=['group:editors'], ...)
```

## Evidence comes from a single evaluation

Every `PermissionExplanation` is computed from one fresh evaluation: it
never reads the checker's permission cache, so the verdict and its evidence
(`direct_perms`, `group_perms`, `global_perms`) always describe the same
point-in-time decision - even if permissions changed after an earlier
boolean check on the same checker instance.

## Excluding global permissions

Pass `consider_global=False` to mirror
`get_objects_for_user(..., accept_global_perms=False)`: global permissions
are then excluded from both the verdict and the evidence:

```python
>>> checker.explain_perm('change_site', site, consider_global=False).allowed
False
```

## Inactive accounts

For inactive users the verdict is always `allowed=False` with
`reason='user account is inactive'`, matching the boolean checks. Note that
`get_objects_for_user` does not evaluate `is_active`; the explanation is
what reveals that a listed grant is inert.
