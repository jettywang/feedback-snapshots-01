---
title: Visitor Principals
description: Explicitly marked guest identities that are distinct from Django's anonymous user.
---

# Visitor Principals

Some deployments have a guest account that the ingress layer explicitly marks
as a *visitor*. A visitor is a real guest identity with its own object
permissions. It is **not** the same thing as Django's
`AnonymousUser`, and it is not the Guardian anonymous user created from
`ANONYMOUS_USER_NAME`:

| Concept | Identity | Permissions come from |
| --- | --- | --- |
| Authenticated user | The logged-in user | The user and its groups |
| Anonymous request | Django `AnonymousUser`, mapped by Guardian to `ANONYMOUS_USER_NAME` | The site-wide anonymous user configuration |
| Visitor request | The configured guest account | Only that guest account's explicit grants |

Guardian exposes the type explicitly, so a view never has to guess whether an
identity is "anonymous" or "a guest that happens to be unattached".

## Configuration

```python
# The real account that represents visitor requests.
GUARDIAN_VISITOR_USER_NAME = "VisitorUser"

# Optional: resolve the visitor per request (receives the request, returns a
# user instance or a username). Takes precedence over the name above.
# GUARDIAN_GET_VISITOR_USER = "myapp.visitors.get_visitor_user"

# Optional: honour a marker header injected by a trusted ingress proxy.
# Leave unset if the ingress instead sets request.guardian_visitor.
GUARDIAN_VISITOR_HEADER = "X-Guardian-Visitor"

# Allow an inactive authenticated user to be replaced by the visitor without
# passing allow_inactive_switch=True explicitly. Prefer per-call confirmation.
GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH = False

# Optional audit sink called with a PrincipalSwitch record for every switch.
GUARDIAN_PRINCIPAL_AUDIT_HANDLER = "myapp.audit.record_principal_switch"
```

The visitor account must exist and must be different from the user named by
`ANONYMOUS_USER_NAME`. Otherwise `guardian.exceptions.VisitorNotConfigured` is
raised; Guardian never silently falls back to the anonymous identity.

## Request middleware

Add the middleware after Django's authentication middleware:

```python
MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "guardian.middleware.GuardianPrincipalMiddleware",
]
```

For every request it sets `request.guardian_principal` and
`request.guardian_user`. A request is treated as a visitor when the ingress
sets `request.guardian_visitor = True` or sends the configured header. The
middleware does **not** rewrite `request.user`; the original authenticated user
stays available for auditing.

The request boundary fails closed: a visitor request with no usable visitor
account, or an unconfirmed switch away from an inactive user, returns `403`
rather than falling back to a different identity.

## Authorizing with a principal

```python
from guardian.principals import get_request_principal

def schedule(request):
    principal = get_request_principal(request)
    if principal.is_visitor:
        ...
    visible = principal.get_objects_for_user("schedule.view_programme", Programme)
```

`get_objects_for_user`, `get_perms`, `ObjectPermissionChecker` and
`ObjectPermissionBackend` also accept a `Principal` directly; they unwrap it
to the identity that participates in the decision. `PermissionRequiredMixin`
and `PermissionListMixin` resolve the request principal automatically.

An ordinary anonymous request keeps using `AnonymousUser`, so the existing
anonymous-user configuration still decides what it can see. A visitor request
uses only the visitor account's explicit grants.

## Switching away from an authenticated user

Replacing a logged-in user with the visitor is a privilege transition. For an
**inactive** source user it requires explicit confirmation:

```python
from guardian.principals import resolve_request_principal

principal = resolve_request_principal(
    request,
    allow_inactive_switch=True,
    confirmation="operator-7/ticket-42",
)
```

Without confirmation
`guardian.exceptions.PrincipalSwitchDenied` is raised and no switch happens.

Every authenticated-to-visitor switch produces a
`guardian.principals.PrincipalSwitch` containing the source and target user
ids, the confirmation reference, the request path and a UTC timestamp. It is:

- logged through the `guardian.principals` logger;
- sent through the `guardian.signals.principal_switched` signal;
- passed to `GUARDIAN_PRINCIPAL_AUDIT_HANDLER` when configured.

If the configured audit handler raises, the switch is refused. A transition
that cannot be traced does not happen.
