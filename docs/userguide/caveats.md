---
title: Caveats
description: Things to be aware of when using django-guardian.
---

# Caveats

There are a few things to be aware of when using django-guardian to manage object permissions.
If ignored, they can lead to unexpected behavior and potential security issues.

## Orphaned object permissions

Note the following does not apply if using direct foreign keys, as
documented in `performance-direct-fk`.

Permissions, in particular *per object permissions*, can be tricky to manage.
For example, how can we manage permissions that are no longer used?
In some setups, it is possible to reuse database primary keys
which have been removed from the database.
When permissions are at the model level only, this is not a problem;
but can lead to tremendous security issues when using object permissions.
How can we deal with this?

Let's imagine our table has primary key to the filesystem path.
We have a record with pk equal to `/home/www/joe.config`.
User *jane* has read access to joe's configuration and we store that information in database
by creating guardian's object permissions.
Now, *joe* user removes account from our site and another user creates account with *joe* as username.
The problem is that if we haven't removed object permissions explicitly in
the process of first *joe* account removal, *jane* still
has read permissions for *joe's* configuration file - but this is another user.

There is no easy way to deal with orphaned permissions as they are not
foreign keyed with objects directly. Even if they would, there are some
database engines—or *ON DELETE* rules—which restricts removal of
related objects.

!!! danger "Important"

    It is **extremely** important to remove`UserObjectPermission` and
    `GroupObjectPermission` as we delete objects for which permissions are defined.

Guardian comes with utility function which tries to help to remove
orphaned object permissions. Remember - those are only helpers.
Applications should remove those object permissions explicitly by
itself.

From our previous example, our application should remove a user object (e.g., *joe*).
However, permissions for the *joe* user assigned to *jane* would**NOT** be removed.
In this case, it would be easy to remove
user/group object permissions if we connect proper action with proper
signal.
This could be achieved by following snippet:

```python
    from django.contrib.contenttypes.models import ContentType
    from django.db.models import Q
    from django.db.models.signals import pre_delete
    from guardian.models import User
    from guardian.models import UserObjectPermission
    from guardian.models import GroupObjectPermission


    def remove_obj_perms_connected_with_user(sender, instance, **kwargs):
        filters = Q(content_type=ContentType.objects.get_for_model(instance),
            object_pk=instance.pk)
        UserObjectPermission.objects.filter(filters).delete()
        GroupObjectPermission.objects.filter(filters).delete()

    pre_delete.connect(remove_obj_perms_connected_with_user, sender=User)
```

This signal handler would remove all object permissions connected with
user just before user is actually removed.

If we forgot to add such handlers, we may still remove orphaned object
permissions by using `clean_orphan_obj_perms` If our application uses
[celery](http://www.celeryproject.org/), it is also straightforward to remove
orphaned permissions periodically with `guardian.utils.clean_orphan_obj_perms` function.
We would still **strongly** advise to remove orphaned object permissions explicitly
(i.e., at view that confirms object removal or using signals as described above).

!!! info
    - `guardian.utils.clean_orphan_obj_perms`
    - `clean_orphan_obj_perms`

## Using multiple databases

`ObjectPermissionChecker` (and the shortcuts built on it, such as
`get_perms()`, `get_user_perms()` and `get_group_perms()`) checks permissions
against the database each object belongs to. The owning database is taken
from the object's `_state.db`, which Django sets whenever an instance is
fetched (e.g. via `.using('replica')`) or saved. Content types, permission
rows and group memberships are all resolved on that database, and the
checker's in-memory cache is keyed by database alias, so one checker instance
can safely be reused for objects living in different databases - even when
primary keys, content type ids or user ids collide across them.

`prefetch_perms()` works per database as well: pass a queryset routed to the
desired database (or a list of objects from one database) and the permissions
are prefetched from that database.

Because primary keys are reused across databases, guardian refuses to guess
when ownership is unclear and raises
`guardian.exceptions.ObjectDatabaseAmbiguityError` instead:

- checking an object that was never fetched from or saved to a database
  (its `_state.db` is `None`), or
- prefetching a list that mixes objects from different databases -
  prefetch each database's objects separately.

Note that custom `GUARDIAN_GET_CONTENT_TYPE` functions only take part in
per-database resolution if they accept an optional `using` keyword argument;
otherwise they keep being called exactly as before.

Queryset-returning shortcuts such as `get_objects_for_user()` still do not
support spanning multiple databases due to a Django bug. See
[288](https://github.com/django-guardian/django-guardian/issues/288) and
[16281](https://code.djangoproject.com/ticket/16281).

## Primary key types

Guardian stores object primary keys as text in the `object_pk` column of its
permission tables. When filtering querysets (e.g. in `get_objects_for_user` or
`get_objects_for_group`), guardian must cast primary keys so that the stored
text values can be compared against the model's actual PK column.

The following PK types are natively supported with optimised casts:

| PK field type | Cast strategy |
|---|---|
| `IntegerField`, `AutoField`, `BigIntegerField`, `SmallIntegerField`, `PositiveIntegerField`, `PositiveSmallIntegerField` | Cast to `BigIntegerField` |
| `UUIDField` | Native UUID cast (or string with hyphens stripped on databases without native UUID support) |
| `CharField` | No cast needed — already stored as text |

For **any other primary key type** (e.g. `TextField`, PostgreSQL `macaddr` or
`inet` fields), guardian automatically falls back to casting PKs with
`Cast("pk", CharField())`. This means models with non-standard PK types work
out of the box:

```python
from django.db import models

class Device(models.Model):
    mac = models.TextField(primary_key=True)

    class Meta:
        permissions = (("view_device", "Can view device"),)
```

```python
from guardian.shortcuts import assign_perm, get_objects_for_user

device = Device.objects.create(mac="00:1B:44:11:3A:B7")
assign_perm("view_device", user, device)

# Returns a queryset containing the device — no extra configuration needed
devices = get_objects_for_user(user, "app.view_device")
```

!!! warning "Performance consideration"

    The string-casting fallback adds a `Cast()` annotation to every query,
    which prevents the database from using primary key indexes directly. For
    large tables this can be noticeably slower than native type comparisons.
    If performance is critical, consider using
    [direct foreign keys](performance.md#direct-foreign-keys) instead.

!!! note

    Permission management functions such as `assign_perm`, `remove_perm`, and
    `get_perms` work with any PK type without special handling. The
    casting behaviour described above only applies to queryset-filtering
    functions like `get_objects_for_user` and `get_objects_for_group`.
