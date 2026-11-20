"""Convenient shortcuts to manage or check object permissions."""

from collections import defaultdict
from functools import lru_cache, partial
from itertools import groupby
from operator import itemgetter
from typing import Any, TypeAlias, TypeVar
import warnings

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from django.db.models import (
    BigIntegerField,
    CharField,
    Count,
    ForeignKey,
    IntegerField,
    Manager,
    Model,
    Q,
    QuerySet,
    UUIDField,
)
from django.db.models.expressions import Value
from django.db.models.functions import Cast, Replace
from django.shortcuts import _get_queryset

from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type
from guardian.exceptions import (
    MixedContentTypeError,
    MultipleIdentityAndObjectError,
    ObjectNotPersisted,
    StalePermissionStateError,
    WrongAppError,
)
from guardian.utils import (
    get_anonymous_user,
    get_group_obj_perms_model,
    get_identity,
    get_user_obj_perms_model,
)

# Mapping of identity primary keys to the set of permission codenames they hold.
PermissionGrantMap: TypeAlias = dict[Any, set[str]]

# A full authorization snapshot for one object, covering both user and group grants.
PermissionSnapshot: TypeAlias = dict[str, PermissionGrantMap]


@lru_cache(None)
def _get_ct_cached(app_label: str, codename: str) -> ContentType:
    """Caches `ContentType` instances like its `QuerySet` does."""
    return ContentType.objects.get(app_label=app_label, permission__codename=codename)


# kwargs are required to be connected to a django signal
def clear_ct_cache(**kwargs) -> None:
    """Helper to clear cache of `_get_ct_cached`"""
    _get_ct_cached.cache_clear()


# Allow sorting/grouping by pk by returning first in result tuple
_get_first = itemgetter(0)


def _ensure_permission(perm: Permission | str) -> Permission:
    """Converts string permission to the corresponding django model, if required."""
    if isinstance(perm, str):
        try:
            app_label, codename = perm.split(".", 1)
        except ValueError:
            raise ValueError(
                f"For global permissions, first argument must be in format: 'app_label.codename' (is {perm!r})"
            )
        perm = Permission.objects.get(content_type__app_label=app_label, codename=codename)
    return perm


def _normalize_perm(perm: Permission | str) -> Permission | str:
    """Normalizes permission codename, if it is a string."""
    if isinstance(perm, str) and "." in perm:
        _, perm = perm.split(".", 1)

    return perm


def assign_perm(
    perm: str | Permission,
    user_or_group: Any,
    obj: Model | None = None,
) -> str | Permission | None:
    """Assigns permission to user/group and object pair.

    Parameters:
        perm (str | Permission): permission to assign for the given `obj`,
            in format: `app_label.codename` or `codename` or `Permission` instance.
            If `obj` is not given, must be in format `app_label.codename` or `Permission` instance.
        user_or_group (User | AnaonymousUser | Group | list | QuerySet):
            instance of `User`, `AnonymousUser`, `Group`,
            list of `User` or `Group`, or queryset of `User` or `Group`;
            passing any other object would raise a`guardian.exceptions.NotUserNorGroup` exception
        obj (Model | QuerySet): Django's `Model` instance or QuerySet or
            a list of Django `Model` instances or `None` if assigning global permission.
            *Default* is `None`.

    Example:
        ```shell
        >>> from django.contrib.sites.models import Site
        >>> from django.contrib.auth.models import User
        >>> from guardian.shortcuts import assign_perm
        >>> site = Site.objects.get_current()
        >>> user = User.objects.create(username='joe')
        >>> assign_perm("change_site", user, site)
        <UserObjectPermission: example.com | joe | change_site>
        >>> user.has_perm("change_site", site)
        True

        # or we can assign permission for group:

        >>> group = Group.objects.create(name='joe-group')
        >>> user.groups.add(group)
        >>> assign_perm("delete_site", group, site)
        <GroupObjectPermission: example.com | joe-group | delete_site>
        >>> user.has_perm("delete_site", site)
        True
        ```

    Note: Global permissions
        This function may also be used to assign standard, *global* permissions if
        `obj` parameter is omitted. Added Permission would be returned in that

        ```shell
        >>> assign_perm("sites.change_site", user)
        <Permission: sites | site | Can change site>
        ```

    """
    if isinstance(user_or_group, list) and not user_or_group:
        return None

    if isinstance(obj, list) and not obj:
        return None

    user, group = get_identity(user_or_group)
    # If obj is None we try to operate on global permissions
    if obj is None:
        perm = _ensure_permission(perm)
        if user:
            user.user_permissions.add(perm)
            return perm
        if group:
            group.permissions.add(perm)
            return perm

    perm = _normalize_perm(perm)
    if isinstance(obj, (QuerySet, list)):
        if isinstance(user_or_group, (QuerySet, list)):
            raise MultipleIdentityAndObjectError("Only bulk operations on either users/groups OR objects supported")
        if user:
            model = get_user_obj_perms_model(obj[0] if isinstance(obj, list) else obj.model)
            return model.objects.bulk_assign_perm(perm, user, obj)
        if group:
            model = get_group_obj_perms_model(obj[0] if isinstance(obj, list) else obj.model)
            return model.objects.bulk_assign_perm(perm, group, obj)

    if isinstance(user_or_group, (QuerySet, list)):
        if user:
            model = get_user_obj_perms_model(obj)
            return model.objects.assign_perm_to_many(perm, user, obj, ignore_conflicts=True)
        if group:
            model = get_group_obj_perms_model(obj)
            return model.objects.assign_perm_to_many(perm, group, obj, ignore_conflicts=True)

    if user:
        model = get_user_obj_perms_model(obj)
        return model.objects.assign_perm(perm, user, obj)

    if group:
        model = get_group_obj_perms_model(obj)
        return model.objects.assign_perm(perm, group, obj)
    return None


def assign(perm, user_or_group, obj=None):
    """Depreciated function name left in for compatibility"""
    warnings.warn(
        "Shortcut function 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
        DeprecationWarning,
    )
    return assign_perm(perm, user_or_group, obj)


def remove_perm(
    perm: str | Permission,
    user_or_group: Any = None,
    obj: Model | QuerySet | list | None = None,
) -> tuple[int, dict] | None:
    """Removes permission from user/group and object pair.

    Parameters:
        perm (str | Permission): permission to remove for the given `obj`, in format: `app_label.codename` or `codename` or `Permission` instance.
            If `obj` is not given, must be in format `app_label.codename` or `Permission` instance.
        user_or_group (User | AnonymousUser | Group | list | QuerySet):
            instance of `User`, `AnonymousUser`, `Group`,
            list of `User` or `Group`, or queryset of `User` or `Group`;
            passing any other object would raise a `guardian.exceptions.NotUserNorGroup` exception
        obj (Model | QuerySet | None): Django's `Model` instance or QuerySet or
            a list of Django `Model` instances or `None` if removing global permission.
            *Default* is `None`.
    """
    if isinstance(user_or_group, list) and not user_or_group:
        return None

    if obj is None and isinstance(user_or_group, (QuerySet, list)):
        raise MultipleIdentityAndObjectError("Bulk global permissions removal is not supported")

    user, group = get_identity(user_or_group)
    if obj is None:
        perm = _ensure_permission(perm)
        if user:
            user.user_permissions.remove(perm)
            return None
        if group:
            group.permissions.remove(perm)
            return None

    perm = _normalize_perm(perm)
    if isinstance(obj, list) and not obj:
        return None

    if isinstance(obj, (QuerySet, list)):
        if isinstance(user_or_group, (QuerySet, list)):
            raise MultipleIdentityAndObjectError("Only bulk operations on either users/groups OR objects are supported")
        if user:
            model = get_user_obj_perms_model(obj[0] if isinstance(obj, list) else obj.model)
            return model.objects.bulk_remove_perm(perm, user, obj)
        if group:
            model = get_group_obj_perms_model(obj[0] if isinstance(obj, list) else obj.model)
            return model.objects.bulk_remove_perm(perm, group, obj)

    if isinstance(user_or_group, (QuerySet, list)):
        if user:
            model = get_user_obj_perms_model(obj)
            return model.objects.remove_perm_from_many(perm, user, obj)
        if group:
            model = get_group_obj_perms_model(obj)
            return model.objects.remove_perm_from_many(perm, group, obj)

    if user:
        model = get_user_obj_perms_model(obj)
        return model.objects.remove_perm(perm, user, obj)

    if group:
        model = get_group_obj_perms_model(obj)
        return model.objects.remove_perm(perm, group, obj)
    return None


def get_perms(user_or_group: Any, obj: Model) -> list[str]:
    """Get all permissions for given user/group and object pair.

    This function returns a comprehensive list of all permissions that the user or group
    has for the specified object. For users, this includes both direct permissions
    and permissions inherited from groups.

    Args:
        user_or_group: User, AnonymousUser, or Group instance
        obj: Django model instance for which to check permissions

    Returns:
        List of permission codenames (strings) for the given user/group and object pair.

    Note:
        For inactive users (is_active=False), returns empty list [].
        For superusers, returns all available permissions for the object's model.
    """
    check = ObjectPermissionChecker(user_or_group)
    return check.get_perms(obj)


def get_user_perms(user: Any, obj: Model) -> QuerySet:
    """Get permissions assigned DIRECTLY to a user for a specific object.

    This function returns ONLY permissions that are explicitly assigned to the user
    for the given object. It does NOT include permissions inherited from groups.

    Args:
        user: User or AnonymousUser instance
        obj: Django model instance for which to check permissions

    Returns:
        QuerySet of permission codenames (strings) that are directly assigned
        to the user for the given object.

    Note:
        For inactive users (is_active=False), returns empty QuerySet.
        Return type is QuerySet, not list (unlike get_perms()).
    """
    check = ObjectPermissionChecker(user)
    return check.get_user_perms(obj)


def get_group_perms(user_or_group: Any, obj: Model) -> QuerySet[Permission]:
    """Get permissions assigned to groups for a specific object.

    This function returns permissions that are assigned to groups for the given object.
    When called with a user, it returns permissions from ALL groups the user belongs to.
    When called with a group, it returns permissions for that specific group only.

    Args:
        user_or_group: User, AnonymousUser, or Group instance
        obj: Django model instance for which to check permissions

    Returns:
        QuerySet of permission codenames (strings) assigned to the group(s)
        for the given object.

    Note:
        For inactive users (is_active=False), returns empty QuerySet.
        Return type is QuerySet, not list (unlike get_perms()).
        Does NOT include direct user permissions.
    """
    check = ObjectPermissionChecker(user_or_group)
    return check.get_group_perms(obj)


def get_perms_for_model(cls: type[Model] | Model | str) -> QuerySet:
    """Get all permissions for a given model class.

    Returns:
        QuerySet of all Permission objects for the given class.
            It is possible to pass Model as class or instance.
    """
    if isinstance(cls, str):
        app_label, model_name = cls.split(".")
        model = apps.get_model(app_label, model_name)
    else:
        model = cls
    ctype = get_content_type(model)
    return Permission.objects.filter(content_type=ctype)


def _object_permission_rows(perms_model: type[Model], obj: Model, for_update: bool = False) -> QuerySet:
    """Return every object-permission row stored for `obj` in `perms_model`."""
    queryset = perms_model.objects
    if perms_model.objects.is_generic():
        queryset = queryset.filter(content_type=get_content_type(obj), object_pk=obj.pk)
    else:
        queryset = queryset.filter(content_object=obj)
    if for_update and connection.features.has_select_for_update:
        queryset = queryset.select_for_update()
    return queryset


def _read_permission_grants(
    perms_model: type[Model], obj: Model, identity_field: str, for_update: bool = False
) -> PermissionGrantMap:
    """Build an identity-pk -> codenames mapping from the object's stored rows."""
    grants: PermissionGrantMap = defaultdict(set)
    rows = _object_permission_rows(perms_model, obj, for_update=for_update).values(
        f"{identity_field}_id", "permission__codename"
    )
    for row in rows:
        grants[row[f"{identity_field}_id"]].add(row["permission__codename"])
    return dict(grants)


def get_permission_snapshot(obj: Model) -> PermissionSnapshot:
    """Read the complete object-level authorization snapshot for `obj`.

    The returned value is the exact format accepted by
    :func:`sync_object_permissions`: a dictionary with `"users"` and `"groups"`
    keys, each mapping an identity primary key to the set of permission
    codenames granted directly to that identity for this object.

    Group membership and global permissions are not included; only rows stored
    on the object's user and group object-permission models are reported.

    Parameters:
        obj (Model): A persisted Django model instance.

    Returns:
        A snapshot dictionary, e.g.
        `{"users": {1: {"change_post"}}, "groups": {2: {"view_post", "delete_post"}}}`.

    Raises:
        ObjectNotPersisted: If `obj` has not been saved to the database.
    """
    if getattr(obj, "pk", None) is None:
        raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
    user_model = get_user_obj_perms_model(obj)
    group_model = get_group_obj_perms_model(obj)
    return {
        "users": _read_permission_grants(user_model, obj, user_model.objects.user_or_group_field),
        "groups": _read_permission_grants(group_model, obj, group_model.objects.user_or_group_field),
    }


def _coerce_identity_pk(value: Any, section: str) -> Any:
    """Validate one key of a submitted grant mapping and return its pk value."""
    if isinstance(value, Model):
        pk = value.pk
        if pk is None:
            raise ValueError(
                f"Cannot sync permissions for an unsaved {value.__class__.__name__} in section {section!r}"
            )
        return pk
    if isinstance(value, (QuerySet, list, tuple, set, dict)):
        raise ValueError(
            f"Grant keys in section {section!r} must be identity instances or primary keys, got {type(value).__name__}"
        )
    return value


def _normalize_grant_section(section: str, raw_grants: Any, obj: Model, ctype: ContentType) -> PermissionGrantMap:
    """Validate one `users`/`groups` section and normalize it to pk -> codenames."""
    if not isinstance(raw_grants, dict):
        raise ValueError(f"Permission snapshot section {section!r} must be a dict, got {type(raw_grants).__name__}")

    valid_codenames = set(Permission.objects.filter(content_type=ctype).values_list("codename", flat=True))
    normalized: PermissionGrantMap = {}
    for raw_identity, raw_perms in raw_grants.items():
        identity_pk = _coerce_identity_pk(raw_identity, section)
        if not isinstance(raw_perms, (list, tuple, set, frozenset)):
            raise ValueError(
                f"Permissions for {section!r} identity {raw_identity!r} must be a list, tuple or set, "
                f"got {type(raw_perms).__name__}"
            )
        codenames = set()
        for raw_perm in raw_perms:
            if isinstance(raw_perm, Permission):
                if raw_perm.content_type_id != ctype.pk:
                    raise ValueError(
                        f"Permission {raw_perm.codename!r} does not apply to " f"{ctype.app_label}.{ctype.model}"
                    )
                codenames.add(raw_perm.codename)
                continue
            if not isinstance(raw_perm, str):
                raise ValueError(
                    f"Permissions must be codenames or Permission instances, got {type(raw_perm).__name__}"
                )
            codename = raw_perm.split(".", 1)[1] if "." in raw_perm else raw_perm
            if codename not in valid_codenames:
                raise ValueError(
                    f"Unknown permission {raw_perm!r} for {ctype.app_label}.{ctype.model}; "
                    f"valid codenames are {sorted(valid_codenames)}"
                )
            codenames.add(codename)
        normalized[identity_pk] = codenames
    return normalized


def _normalize_permission_snapshot(grants: Any, obj: Model) -> PermissionSnapshot:
    """Validate and normalize a caller-submitted snapshot for `obj`."""
    if not isinstance(grants, dict):
        raise ValueError(f"Permission snapshot must be a dict, got {type(grants).__name__}")
    missing = {"users", "groups"} - grants.keys()
    if missing:
        raise ValueError(
            f"Permission snapshot must contain both 'users' and 'groups' sections; missing {sorted(missing)}"
        )
    ctype = get_content_type(obj)
    return {
        "users": _normalize_grant_section("users", grants["users"], obj, ctype),
        "groups": _normalize_grant_section("groups", grants["groups"], obj, ctype),
    }


def _strip_empty_grants(grants: PermissionSnapshot) -> PermissionSnapshot:
    """Drop identities holding an empty set so equivalent snapshots compare equal."""
    return {
        section: {identity_pk: codenames for identity_pk, codenames in section_grants.items() if codenames}
        for section, section_grants in grants.items()
    }


def _apply_grant_section(
    perms_model: type[Model],
    obj: Model,
    identity_field: str,
    desired: PermissionGrantMap,
    current: PermissionGrantMap,
) -> None:
    """Replace this object's grants of one model with the desired mapping."""
    ctype = get_content_type(obj)
    object_filter = (
        Q(content_type=ctype, object_pk=obj.pk) if perms_model.objects.is_generic() else Q(content_object=obj)
    )
    managed_identity_ids = set(desired) | set(current)
    if not managed_identity_ids:
        return

    rows = perms_model.objects.filter(object_filter, **{f"{identity_field}_id__in": managed_identity_ids})
    if connection.features.has_select_for_update:
        rows = rows.select_for_update()
    existing: dict[tuple[Any, str], int] = {
        (getattr(row, identity_field + "_id"), row.permission.codename): row.pk for row in rows
    }

    desired_pairs = {(identity_pk, codename) for identity_pk, codenames in desired.items() for codename in codenames}
    stale_pks = [pk for pair, pk in existing.items() if pair not in desired_pairs]
    if stale_pks:
        perms_model.objects.filter(pk__in=stale_pks).delete()

    missing_codenames = {codename for _, codename in desired_pairs - set(existing)}
    permissions = {
        perm.codename: perm for perm in Permission.objects.filter(content_type=ctype, codename__in=missing_codenames)
    }
    to_create = [
        perms_model(
            permission=permissions[codename],
            **{
                identity_field + "_id": identity_pk,
                **(
                    {"content_type": ctype, "object_pk": obj.pk}
                    if perms_model.objects.is_generic()
                    else {"content_object": obj}
                ),
            },
        )
        for identity_pk, codename in sorted(desired_pairs - set(existing))
    ]
    if to_create:
        perms_model.objects.bulk_create(to_create, ignore_conflicts=True)


def sync_object_permissions(
    obj: Model,
    grants: PermissionSnapshot,
    expected: PermissionSnapshot | None = None,
) -> PermissionSnapshot:
    """Atomically replace `obj`'s object-level permission grants with a snapshot.

    User and group object permissions for the single object `obj` are replaced
    in one database transaction: every grant present in `grants` is stored and
    every previously stored grant absent from it is removed. If any write is
    rejected the whole transaction is rolled back, leaving the previous
    authorization state intact.

    Parameters:
        obj (Model): A persisted Django model instance whose grants are replaced.
        grants (PermissionSnapshot): The desired authorization state. Must be a
            dictionary with `"users"` and `"groups"` sections; each section maps
            an identity instance or primary key to an iterable of permission
            codenames (or `Permission` instances) granted directly to that
            identity on `obj`. An empty section or empty set clears the
            corresponding grants.
        expected (PermissionSnapshot | None): Optional optimistic-concurrency
            base. When given, it must equal the object's current snapshot (as
            returned by :func:`get_permission_snapshot`); otherwise
            :class:`guardian.exceptions.StalePermissionStateError` is raised and
            nothing is changed. Pass `None` to apply unconditionally.

    Returns:
        The new authorization snapshot, in the same format as
        :func:`get_permission_snapshot`.

    Raises:
        ObjectNotPersisted: If `obj` has not been saved to the database.
        ValueError: If `grants` is malformed or references unknown permissions.
        StalePermissionStateError: If `expected` does not match the stored state.

    Example:
        ```python
        from guardian.shortcuts import get_permission_snapshot, sync_object_permissions

        post = Post.objects.get(pk=1)
        base = get_permission_snapshot(post)
        desired = {
            "users": {**base["users"], editor.pk: {"change_post", "view_post"}},
            "groups": base["groups"],
        }
        sync_object_permissions(post, desired, expected=base)
        ```
    """
    if getattr(obj, "pk", None) is None:
        raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
    desired = _strip_empty_grants(_normalize_permission_snapshot(grants, obj))

    user_model = get_user_obj_perms_model(obj)
    group_model = get_group_obj_perms_model(obj)
    user_field = user_model.objects.user_or_group_field
    group_field = group_model.objects.user_or_group_field

    with transaction.atomic():
        lock_rows = connection.features.has_select_for_update
        current = {
            "users": _read_permission_grants(user_model, obj, user_field, for_update=lock_rows),
            "groups": _read_permission_grants(group_model, obj, group_field, for_update=lock_rows),
        }
        current = _strip_empty_grants(current)

        if expected is not None:
            expected_normalized = _strip_empty_grants(_normalize_permission_snapshot(expected, obj))
            if expected_normalized != current:
                raise StalePermissionStateError(
                    "Permission snapshot for %s has changed since it was read; "
                    "re-read it with get_permission_snapshot() and retry" % obj
                )

        _apply_grant_section(user_model, obj, user_field, desired["users"], current["users"])
        _apply_grant_section(group_model, obj, group_field, desired["groups"], current["groups"])

        return get_permission_snapshot(obj)


def get_users_with_perms(
    obj: Model,
    attach_perms: bool = False,
    with_superusers: bool = False,
    with_group_users: bool = True,
    only_with_perms_in: list[str] | None = None,
) -> Any | list[str]:
    """Get all users with *any* object permissions for the given `obj`.

    Parameters:
        obj (Model): Instance of a Django `Model`.
        attach_perms (bool): If `True`, return a dictionary of `User` instances
            with the permissions' codename as a list of values.
            This fetches users eagerly!
        with_superusers (bool): Wether results should contain superusers.
        with_group_users (bool): Whether results should contain users who
            have only group permissions for given `obj`.
        only_with_perms_in (list[str]): Only return users with these permissions.
    Example:
        ```shell
        >>> from django.contrib.flatpages.models import FlatPage
        >>> from django.contrib.auth.models import User
        >>> from guardian.shortcuts import assign_perm, get_users_with_perms
        >>>
        >>> page = FlatPage.objects.create(title='Some page', path='/some/page/')
        >>> joe = User.objects.create_user('joe', 'joe@example.com', 'joesecret')
        >>> dan = User.objects.create_user('dan', 'dan@example.com', 'dansecret')
        >>> assign_perm('change_flatpage', joe, page)
        >>> assign_perm('delete_flatpage', dan, page)
        >>>
        >>> get_users_with_perms(page)
        [<User: joe>, <User: dan>]
        >>>
        >>> get_users_with_perms(page, attach_perms=True)
        {<User: joe>: [u'change_flatpage'], <User: dan>: [u'delete_flatpage']}
        >>> get_users_with_perms(page, only_with_perms_in=['change_flatpage'])
        [<User: joe>]
        ```
    """
    ctype = get_content_type(obj)
    if not attach_perms:
        # It's much easier without attached perms so we do it first if that is
        # the case
        user_model = get_user_obj_perms_model(obj)
        related_name = user_model.user.field.related_query_name()
        if user_model.objects.is_generic():
            user_filters = {
                "%s__content_type" % related_name: ctype,
                "%s__object_pk" % related_name: obj.pk,
            }
        else:
            user_filters = {"%s__content_object" % related_name: obj}
        qset = Q(**user_filters)
        if only_with_perms_in is not None:
            permission_ids = Permission.objects.filter(content_type=ctype, codename__in=only_with_perms_in).values_list(
                "id", flat=True
            )
            qset &= Q(
                **{
                    "%s__permission_id__in" % related_name: permission_ids,
                }
            )
        if with_group_users:
            group_model = get_group_obj_perms_model(obj)
            if group_model.objects.is_generic():
                group_obj_perm_filters = {
                    "content_type": ctype,
                    "object_pk": obj.pk,
                }
            else:
                group_obj_perm_filters = {
                    "content_object": obj,
                }
            if only_with_perms_in is not None:
                group_obj_perm_filters.update(
                    {
                        "permission_id__in": permission_ids,
                    }
                )
            group_ids = group_model.objects.filter(**group_obj_perm_filters).values("group_id").distinct()
            qset = qset | Q(groups__in=group_ids)
        if with_superusers:
            qset = qset | Q(is_superuser=True)
        return get_user_model().objects.filter(qset).distinct()
    else:
        # TODO: Do not hit db for each user!
        users = {}
        for user in get_users_with_perms(
            obj,
            with_group_users=with_group_users,
            only_with_perms_in=only_with_perms_in,
            with_superusers=with_superusers,
        ):
            # TODO: Support the case of set with_group_users but not with_superusers.
            if with_group_users or with_superusers:
                users[user] = sorted(get_perms(user, obj))
            else:
                users[user] = sorted(get_user_perms(user, obj))
        return users


def get_groups_with_perms(
    obj: Model, attach_perms: bool = False, only_with_perms_in: list[str] | None = None
) -> Group | dict:
    """Get all groups with *any* object permissions for the given `obj`.

    Parameters:
        obj (Model): persisted Django `Model` instance.
        attach_perms (bool): Whether return result as a dict of `Group` instances
            with permissions' codenames list of values.
            This would fetch groups eagerly!
        only_with_perms_in (list[str]): Only return groups with these permissions.

    Returns:
        All `Group` objects with the matching object permissions for the given `obj`.

    Example:
        ```shell
        >>> from django.contrib.flatpages.models import FlatPage
        >>> from guardian.shortcuts import assign_perm, get_groups_with_perms
        >>> from guardian.models import Group
        >>>
        >>> page = FlatPage.objects.create(title='Some page', path='/some/page/')
        >>> admins = Group.objects.create(name='Admins')
        >>> assign_perm('change_flatpage', admins, page)
        >>>
        >>> get_groups_with_perms(page)
        [<Group: admins>]
        >>>
        >>> get_groups_with_perms(page, attach_perms=True)
        {<Group: admins>: [u'change_flatpage']}
        ```
    """
    ctype = get_content_type(obj)
    group_model = get_group_obj_perms_model(obj)

    if not attach_perms:
        # It's much easier without attached perms so we do it first if that is the case
        group_rel_name = group_model.group.field.related_query_name()
        if group_model.objects.is_generic():
            group_filters = {
                "%s__content_type" % group_rel_name: ctype,
                "%s__object_pk" % group_rel_name: obj.pk,
            }
        else:
            group_filters = {"%s__content_object" % group_rel_name: obj}
        if only_with_perms_in is not None:
            permission_ids = Permission.objects.filter(content_type=ctype, codename__in=only_with_perms_in).values_list(
                "id", flat=True
            )
            group_filters.update(
                {
                    "%s__permission_id__in" % group_rel_name: permission_ids,
                }
            )

        group_rel_model = group_model.group.field.related_model
        return group_rel_model.objects.filter(**group_filters).distinct()
    else:
        group_perms_mapping = defaultdict(list)
        groups_with_perms = get_groups_with_perms(obj, only_with_perms_in=only_with_perms_in)
        qs = group_model.objects.filter(group__in=groups_with_perms).prefetch_related("group", "permission")
        if group_model.objects.is_generic():
            qs = qs.filter(object_pk=obj.pk, content_type=ctype)
        else:
            qs = qs.filter(content_object_id=obj.pk)

        for group_perm in qs:
            group_perms_mapping[group_perm.group].append(group_perm.permission.codename)
        return dict(group_perms_mapping)


T = TypeVar("T", bound=Model)


def _compute_codenames_and_ctype(
    perms: str | list[str],
) -> tuple[ContentType | None, set[str]]:
    """Extracts ContentType and codenames from given list of permissions."""
    if isinstance(perms, str):
        perms = [perms]
    ctype = None
    app_label = None
    codenames = set()

    # Compute codenames and set and ctype if possible
    for perm in perms:
        if "." in perm:
            new_app_label, codename = perm.split(".", 1)
            if app_label is not None and app_label != new_app_label:
                raise MixedContentTypeError(f"Given perms must have same app label ({app_label} != {new_app_label})")
            else:
                app_label = new_app_label
        else:
            codename = perm
        codenames.add(codename)
        if app_label is not None:
            new_ctype = _get_ct_cached(app_label, codename)
            if ctype is not None and ctype != new_ctype:
                raise MixedContentTypeError(f"ContentType was once computed to be {ctype} and another one {new_ctype}")
            else:
                ctype = new_ctype

    return ctype, codenames


def _compute_queryset(
    ctype: ContentType | None,
    klass: type[T] | Manager[T] | QuerySet[T] | None,
) -> tuple[ContentType, QuerySet[T]]:
    """Computes QuerySet and ContentType if still missing"""
    if ctype is None and klass is not None:
        queryset = _get_queryset(klass)
        ctype = get_content_type(queryset.model)
    elif ctype is not None and klass is None:
        queryset = _get_queryset(ctype.model_class())
    elif klass is None:
        raise WrongAppError("Cannot determine content type")
    else:
        queryset = _get_queryset(klass)
        if ctype != get_content_type(queryset.model):
            raise MixedContentTypeError("Content type for given perms and klass differs")
    return ctype, queryset


def get_objects_for_user(
    user: Any,
    perms: str | list[str],
    klass: type[T] | Manager[T] | QuerySet[T] | None = None,
    use_groups: bool = True,
    any_perm: bool = False,
    with_superuser: bool = True,
    accept_global_perms: bool = True,
) -> QuerySet[T]:
    """Get objects that a user has *all* the supplied permissions for.

    Parameters:
        user (User | AnonymousUser): user to check for permissions.
        perms (str | list[str]): permission(s) to be checked.
            If `klass` parameter is not given, those should be full permission
            names rather than only codenames (i.e. `auth.change_user`).
            If more than one permission is present within sequence, their content type **must** be
            the same or `MixedContentTypeError` exception would be raised.
        klass (Modal | Manager | QuerySet): If not provided, this parameter would be
            computed based on given `params`.
        use_groups (bool): Whether to check user's groups object permissions.
        any_perm (bool): Whether any of the provided permissions in sequence is accepted.
        with_superuser (bool): if `user.is_superuser`, whether to return the entire queryset.
            Otherwise will only return objects the user has explicit permissions.
            This must be `True` for the `accept_global_perms` parameter to have any affect.
        accept_global_perms (bool): Whether global permissions are taken into account.
            Object based permissions are taken into account if more than one permission is
            provided in in perms and at least one of these perms is not globally set.
            If `any_perm` is `False` then the intersection of matching object is returned.
            Note, that if `with_superuser` is `False`, `accept_global_perms` will be ignored,
            which means that only object permissions will be checked!

    Raises:
        MixedContentTypeError: when computed content type for `perms` and/or `klass` clashes.
        WrongAppError: if cannot compute app label for given `perms` or `klass`.

    Example:
        ```shell
        >>> from django.contrib.auth.models import User
        >>> from guardian.shortcuts import get_objects_for_user
        >>> joe = User.objects.get(username='joe')
        >>> get_objects_for_user(joe, 'auth.change_group')
        []
        >>> from guardian.shortcuts import assign_perm
        >>> group = Group.objects.create('some group')
        >>> assign_perm('auth.change_group', joe, group)
        >>> get_objects_for_user(joe, 'auth.change_group')
        [<Group some group>]

        # The permission string can also be an iterable. Continuing with the previous example:

        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'])
        []
        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'], any_perm=True)
        [<Group some group>]
        >>> assign_perm('auth.delete_group', joe, group)
        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'])
        [<Group some group>]

        # Take global permissions into account:

        >>> jack = User.objects.get(username='jack')
        >>> assign_perm('auth.change_group', jack) # this will set a global permission
        >>> get_objects_for_user(jack, 'auth.change_group')
        [<Group some group>]
        >>> group2 = Group.objects.create('other group')
        >>> assign_perm('auth.delete_group', jack, group2)
        >>> get_objects_for_user(jack, ['auth.change_group', 'auth.delete_group']) # this retrieves intersection
        [<Group other group>]
        >>> get_objects_for_user(jack, ['auth.change_group', 'auth.delete_group'], any_perm) # this retrieves union
        [<Group some group>, <Group other group>]
        ```

    Note:
        If `accept_global_perms` is set to `True`, then all assigned global
        permissions will also be taken into account.

        - Scenario 1: a user has view permissions generally defined on the model
          'books' but no object-based permission on a single book instance:

            - If `accept_global_perms` is `True`: A list of all books will be returned.
            - If `accept_global_perms` is `False`: The list will be empty.

        - Scenario 2: a user has view permissions generally defined on the model
          'books' and also has an object-based permission to view book 'Whatever':

            - If `accept_global_perms` is `True`: A list of all books will be returned.
            - If `accept_global_perms` is `False`: The list will only contain book 'Whatever'.

        - Scenario 3: a user only has object-based permission on book 'Whatever':

            - If `accept_global_perms` is `True`: The list will only contain book 'Whatever'.
            - If `accept_global_perms` is `False`: The list will only contain book 'Whatever'.

        - Scenario 4: a user does not have any permission:

            - If `accept_global_perms` is `True`: An empty list is returned.
            - If `accept_global_perms` is `False`: An empty list is returned.

    Note: Primary key types
        Standard PK types (integer family, ``UUIDField``, ``CharField``) use
        optimised native casts. Non-standard PK types (e.g. ``TextField``,
        PostgreSQL ``macaddr``/``inet``) are automatically handled via a
        ``Cast("pk", CharField())`` fallback, so models with any PK type are
        supported without extra configuration.
    """
    ctype, codenames = _compute_codenames_and_ctype(perms)
    ctype, queryset = _compute_queryset(ctype, klass)

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have `codenames` list

    # First check if user is superuser and if so, return queryset immediately
    if with_superuser and user.is_superuser:
        return queryset

    # Check if the user is anonymous. The
    # django.contrib.auth.models.AnonymousUser object doesn't work for queries
    # and it's nice to be able to pass in request.user blindly.
    if user.is_anonymous:
        user = get_anonymous_user()

    has_global_perms = False
    # a superuser has by default assigned global perms for any
    if accept_global_perms and with_superuser:
        global_perms = {code for code in codenames if user.has_perm(ctype.app_label + "." + code)}
        for code in global_perms:
            codenames.remove(code)
        # prerequisite: there must be elements in global_perms otherwise just follow the procedure for
        # object based permissions only AND
        # 1. codenames is empty, which means that permissions are ONLY set globally, therefore return the full queryset.
        # OR
        # 2. any_perm is True, then the global permission beats the object based permission anyway,
        # therefore return full queryset
        if global_perms and (not codenames or any_perm):
            return queryset
        # Otherwise the remaining codenames must all be granted per object (by user or groups), see below.
        has_global_perms = bool(global_perms and codenames)

    # Only group calls with several remaining codenames hit the all-perms group check the legacy mode skips.
    legacy_group_union = (
        use_groups and len(codenames) > 1 and has_global_perms and guardian_settings.LEGACY_GLOBAL_PERMS_GROUP_UNION
    )
    if legacy_group_union:
        # This feature will be removed in 3.6.0. (GHSA-5729-mvhf-9gq4)
        warnings.warn(
            "GUARDIAN_LEGACY_GLOBAL_PERMS_GROUP_UNION is deprecated and will be removed in 3.6.0. "
            "It makes get_objects_for_user return objects the user lacks a required permission on.",
            DeprecationWarning,
            stacklevel=2,
        )

    # Now we should extract the list of pk values for which we would filter the queryset
    user_model = get_user_obj_perms_model(queryset.model)
    user_obj_perms_queryset = filter_perms_queryset_by_objects(
        user_model.objects.filter(user=user).filter(permission__content_type=ctype), klass
    )
    if codenames:
        user_obj_perms_queryset = user_obj_perms_queryset.filter(permission__codename__in=codenames)
    direct_fields = ["content_object__pk", "permission__codename"]
    generic_fields = ["object_pk", "permission__codename"]
    if user_model.objects.is_generic():
        user_fields = generic_fields
    else:
        user_fields = direct_fields

    if use_groups:
        group_model = get_group_obj_perms_model(queryset.model)
        group_filters = {
            "permission__content_type": ctype,
            "group__in": user.groups.all(),
        }
        if codenames:
            group_filters.update(
                {
                    "permission__codename__in": codenames,
                }
            )
        groups_obj_perms_queryset = filter_perms_queryset_by_objects(group_model.objects.filter(**group_filters), klass)
        if group_model.objects.is_generic():
            group_fields = generic_fields
        else:
            group_fields = direct_fields
        if not any_perm and len(codenames) > 1 and not legacy_group_union:
            user_obj_perms = user_obj_perms_queryset.values_list(*user_fields)
            groups_obj_perms = groups_obj_perms_queryset.values_list(*group_fields)
            data = list(user_obj_perms) + list(groups_obj_perms)
            # sorting/grouping by pk (first in result tuple)
            data = sorted(data, key=_get_first)
            pk_list = []
            for pk, group in groupby(data, _get_first):
                obj_codenames = {e[1] for e in group}
                if codenames.issubset(obj_codenames):
                    pk_list.append(pk)
            objects = queryset.filter(pk__in=pk_list)
            return objects

    if not any_perm and len(codenames) > 1:
        counts = user_obj_perms_queryset.values(user_fields[0]).annotate(object_pk_count=Count(user_fields[0]))
        user_obj_perms_queryset = counts.filter(object_pk_count__gte=len(codenames))

    field_pk = user_fields[0]
    values = user_obj_perms_queryset

    handle_pk_field = _handle_pk_field(queryset)
    use_str_pk_for_user = handle_pk_field is None or (
        user_model.objects.is_generic() and _casts_to_bigint(handle_pk_field)
    )
    if not use_str_pk_for_user:
        values = values.annotate(obj_pk=handle_pk_field(expression=field_pk))
        field_pk = "obj_pk"

    values = values.values_list(field_pk, flat=True)
    str_pk_annotated = False
    if use_str_pk_for_user:
        queryset = queryset.annotate(str_pk=Cast("pk", CharField()))
        str_pk_annotated = True
        q = Q(str_pk__in=values)
    else:
        q = Q(pk__in=values)
    if use_groups:
        field_pk = group_fields[0]
        values = groups_obj_perms_queryset
        use_str_pk_for_group = handle_pk_field is None or (
            group_model.objects.is_generic() and _casts_to_bigint(handle_pk_field)
        )
        if not use_str_pk_for_group:
            values = values.annotate(obj_pk=handle_pk_field(expression=field_pk))
            field_pk = "obj_pk"
        values = values.values_list(field_pk, flat=True)
        if use_str_pk_for_group:
            if not str_pk_annotated:
                queryset = queryset.annotate(str_pk=Cast("pk", CharField()))
            q |= Q(str_pk__in=values)
        else:
            q |= Q(pk__in=values)
    return queryset.filter(q)


def get_objects_for_group(
    group: Group,
    perms: str | list[str],
    klass: type[T] | Manager[T] | QuerySet[T] | None = None,
    any_perm: bool = False,
    accept_global_perms: bool = True,
) -> QuerySet[T]:
    """Get objects that a group has *all* the supplied permissions for.

    Parameters:
        group (Group): `Group` instance for which objects would be returned.
        perms (str | list[str]): permission(s) which should be checked.
            If `klass` parameter is not given, those should be full permission
            names rather than only codenames (i.e. `auth.change_user`).
            If more than one permission is present within sequence,
            their content type **must** be the same or `MixedContentTypeError` exception is raised.
        klass (Model | Manager | QuerySet):  If not provided this parameter is computed
            based on given `params`.
        any_perm (bool): Whether any of permission in sequence is accepted.
        accept_global_perms (bool): Whether global permissions are taken into account.
            If `any_perm` is `False`, then the intersection of matching objects based on
            global and object-based permissionsis returned.

    Returns:
        objects for which a given `group` has *all* permissions in `perms`.

    Raisess:
        MixedContentTypeError: when computed content type for `perms` and/or `klass` clashes.
        WrongAppError: if cannot compute app label for given `perms`/`klass`.

    Example:
        Let's assume we have a `Task` model belonging to the `tasker` app with
        the default add_task, change_task and delete_task permissions provided
        by Django:

        ```shell
        >>> from guardian.shortcuts import get_objects_for_group
        >>> from tasker import Task
        >>> group = Group.objects.create('some group')
        >>> task = Task.objects.create('some task')
        >>> get_objects_for_group(group, 'tasker.add_task')
        []
        >>> from guardian.shortcuts import assign_perm
        >>> assign_perm('tasker.add_task', group, task)
        >>> get_objects_for_group(group, 'tasker.add_task')
        [<Task some task>]

        # The permission string can also be an iterable. Continuing with the previous example:

        >>> get_objects_for_group(group, ['tasker.add_task', 'tasker.delete_task'])
        []
        >>> assign_perm('tasker.delete_task', group, task)
        >>> get_objects_for_group(group, ['tasker.add_task', 'tasker.delete_task'])
        [<Task some task>]

        # Global permissions assigned to the group are also taken into account. Continuing with previous example:

        >>> task_other = Task.objects.create('other task')
        >>> assign_perm('tasker.change_task', group)
        >>> get_objects_for_group(group, ['tasker.change_task'])
        [<Task some task>, <Task other task>]
        >>> get_objects_for_group(group, ['tasker.change_task'], accept_global_perms=False)
        [<Task some task>]
        ```

    Note: Primary key types
        Standard PK types (integer family, ``UUIDField``, ``CharField``) use
        optimised native casts. Non-standard PK types (e.g. ``TextField``,
        PostgreSQL ``macaddr``/``inet``) are automatically handled via a
        ``Cast("pk", CharField())`` fallback, so models with any PK type are
        supported without extra configuration.
    """
    ctype, codenames = _compute_codenames_and_ctype(perms)
    ctype, queryset = _compute_queryset(ctype, klass)

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have `codenames` list

    global_perms = set()
    if accept_global_perms:
        # Only global permissions of the queried model count, as a codename can exist on several models
        global_perm_set = set(
            group.permissions.filter(content_type=ctype, codename__in=codenames).values_list("codename", flat=True)
        )
        for code in codenames:
            if code in global_perm_set:
                global_perms.add(code)
        for code in global_perms:
            codenames.remove(code)
        if global_perms and (not codenames or any_perm):
            return queryset

    # Now we should extract list of pk values for which we would filter
    # queryset
    group_model = get_group_obj_perms_model(queryset.model)
    groups_obj_perms_queryset = filter_perms_queryset_by_objects(
        group_model.objects.filter(group=group).filter(permission__content_type=ctype), klass
    )
    if codenames:
        groups_obj_perms_queryset = groups_obj_perms_queryset.filter(permission__codename__in=codenames)
    if group_model.objects.is_generic():
        fields = ["object_pk", "permission__codename"]
    else:
        fields = ["content_object__pk", "permission__codename"]
    if not any_perm and codenames:
        groups_obj_perms = groups_obj_perms_queryset.values_list(*fields)
        data = list(groups_obj_perms)

        # sorting/grouping by pk (first in result tuple)
        data = sorted(data, key=_get_first)
        pk_list = []
        for pk, group in groupby(data, _get_first):
            obj_codenames = {e[1] for e in group}
            if any_perm or codenames.issubset(obj_codenames):
                pk_list.append(pk)
        objects = queryset.filter(pk__in=pk_list)
        return objects

    field_pk = fields[0]
    values = groups_obj_perms_queryset

    handle_pk_field = _handle_pk_field(queryset)
    use_str_pk = handle_pk_field is None or (group_model.objects.is_generic() and _casts_to_bigint(handle_pk_field))
    if not use_str_pk:
        values = values.annotate(obj_pk=handle_pk_field(expression=field_pk))
        field_pk = "obj_pk"
    else:
        queryset = queryset.annotate(str_pk=Cast("pk", CharField()))

    values = values.values_list(field_pk, flat=True)
    if not use_str_pk:
        return queryset.filter(pk__in=values)
    else:
        return queryset.filter(str_pk__in=values)


def _handle_pk_field(queryset):
    pk = queryset.model._meta.pk

    if isinstance(pk, ForeignKey):
        return _handle_pk_field(pk.target_field)

    if isinstance(pk, IntegerField):
        return partial(Cast, output_field=BigIntegerField())

    if isinstance(pk, UUIDField):
        if connection.features.has_native_uuid_field:
            return partial(Cast, output_field=UUIDField())
        return partial(
            Replace,
            text=Value("-"),
            replacement=Value(""),
            output_field=CharField(),
        )

    return None


def _casts_to_bigint(handle_pk_field):
    return (
        isinstance(handle_pk_field, partial)
        and handle_pk_field.func is Cast
        and isinstance(handle_pk_field.keywords.get("output_field"), BigIntegerField)
    )


def filter_perms_queryset_by_objects(perms_queryset, objects):
    if isinstance(objects, QuerySet):
        field = "content_object__pk"
        if perms_queryset.model.objects.is_generic():
            field = "object_pk"
            handle_pk_field = _handle_pk_field(objects)
            if handle_pk_field is not None:
                if _casts_to_bigint(handle_pk_field):
                    # Keep object_pk untouched to avoid CAST(object_pk AS bigint)
                    # scans on large guardian tables. We only stringify model PKs.
                    objects = objects.annotate(_pk=Cast("pk", output_field=CharField())).values_list("_pk", flat=True)
                    field = "object_pk"
                else:
                    objects = objects.annotate(_pk=Cast(handle_pk_field("pk"), output_field=CharField())).values_list(
                        "_pk", flat=True
                    )
                    # Apply the same transformation to the object_pk field for consistent comparison (#930)
                    perms_queryset = perms_queryset.annotate(
                        _transformed_object_pk=Cast(handle_pk_field(field), output_field=CharField())
                    )
                    field = "_transformed_object_pk"
            else:
                objects = objects.values_list("pk", flat=True)
        else:
            objects = objects.values_list("pk", flat=True)
        return perms_queryset.filter(**{f"{field}__in": objects})
    else:
        return perms_queryset
