"""
Optional target-level authorization helpers for nested and bulk writes.

The regular view permission hooks only see the request and the root object.
Custom ``ListSerializer.update()`` implementations know which concrete rows
and nested objects are about to be written.  They can report those targets to
this module so the existing ``has_object_permission()`` implementations remain
the single source of object-level policy.
"""
from contextlib import contextmanager
from typing import Iterable, Mapping

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.db import transaction
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import ErrorDetail, PermissionDenied
from rest_framework.settings import api_settings


DEFAULT_DENIED_MESSAGE = _('You do not have permission to modify this object.')
DEFAULT_DENIED_CODE = 'permission_denied'


class AdmissionTarget:
    """
    A concrete object that a serializer intends to write.

    ``location`` is a JSON-like path to the target in the request.  Integer
    path parts identify list rows and string parts identify nested fields.
    """

    def __init__(self, obj, location=(), index=None, key=None, label=None):
        self.obj = obj
        if isinstance(location, (str, int)) and not isinstance(location, bool):
            location = (location,)
        elif location is None:
            location = ()
        else:
            location = tuple(location)
        self.location = location

        if index is None:
            for part in reversed(location):
                if isinstance(part, int) and not isinstance(part, bool):
                    index = part
                    break
        self.index = index
        self.key = key if key is not None else getattr(obj, 'pk', None)
        self.label = label

    def __repr__(self):
        return (
            '<AdmissionTarget location={!r} index={!r} key={!r} obj={!r}>'
            .format(self.location, self.index, self.key, self.obj)
        )


# A short, intention-revealing alias for callers describing the write plan.
WriteTarget = AdmissionTarget


class AdmissionFailure:
    def __init__(self, target, permission, detail=None, message=None, code=None):
        self.target = target
        self.obj = target.obj
        self.location = target.location
        self.index = target.index
        self.key = target.key
        self.permission = permission
        if detail is not None:
            self.detail = detail
        else:
            self.detail = ErrorDetail(
                force_str(message or DEFAULT_DENIED_MESSAGE),
                code=code or DEFAULT_DENIED_CODE,
            )

    @property
    def message(self):
        detail = self.detail
        if isinstance(detail, (list, tuple)) and detail:
            detail = detail[0]
        elif isinstance(detail, Mapping):
            detail = detail.get(api_settings.NON_FIELD_ERRORS_KEY, detail)
            if isinstance(detail, (list, tuple)) and detail:
                detail = detail[0]
        return force_str(detail)

    @property
    def code(self):
        return getattr(self.detail, 'code', DEFAULT_DENIED_CODE)


class AdmissionDenied(PermissionDenied):
    """
    Permission failure annotated with the request locations and objects.
    """

    default_detail = _('One or more update targets are not permitted.')
    default_code = DEFAULT_DENIED_CODE

    def __init__(self, failures):
        self.failures = tuple(failures)
        super().__init__(detail=self._build_detail())

    def _build_detail(self):
        detail = {}
        for failure in self.failures:
            node = detail
            for part in failure.location:
                child = node.get(part)
                if not isinstance(child, dict):
                    child = {}
                    node[part] = child
                node = child

            failure_detail = failure.detail
            if isinstance(failure_detail, Mapping):
                for key, value in failure_detail.items():
                    if isinstance(value, list):
                        node.setdefault(key, []).extend(value)
                    else:
                        node[key] = value
            elif isinstance(failure_detail, list):
                node.setdefault(api_settings.NON_FIELD_ERRORS_KEY, []).extend(
                    failure_detail
                )
            else:
                node.setdefault(api_settings.NON_FIELD_ERRORS_KEY, []).append(
                    failure_detail
                )
        return detail

    @property
    def denied_indexes(self):
        return sorted({
            failure.index for failure in self.failures
            if failure.index is not None
        })

    @property
    def denied_keys(self):
        return [failure.key for failure in self.failures]


class AdmissionConfirmation:
    """
    The result of a successful pre-write admission check.

    Keeping this object explicit makes the read/authorization phase distinct
    from the later database write phase.  ``recheck()`` covers policies that
    change between confirmation and the write transaction.
    """

    def __init__(self, targets, permissions, request=None, view=None):
        self.targets = tuple(targets)
        self.permissions = tuple(permissions)
        self.request = request
        self.view = view

    def recheck(self):
        return check_target_admission(
            self.targets,
            request=self.request,
            view=self.view,
            permissions=self.permissions,
        )


def _is_location(value):
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return True
    return (
        isinstance(value, tuple)
        and all(
            isinstance(part, (str, int)) and not isinstance(part, bool)
            for part in value
        )
    )


def normalize_target(entry):
    if isinstance(entry, AdmissionTarget):
        return entry

    if isinstance(entry, Mapping):
        obj = entry.get('obj', entry.get('target', entry.get('instance')))
        if obj is None:
            raise TypeError('Admission target mapping must contain "obj".')
        return AdmissionTarget(
            obj,
            location=entry.get('location', ()),
            index=entry.get('index'),
            key=entry.get('key'),
            label=entry.get('label'),
        )

    if isinstance(entry, tuple) and len(entry) == 2 and _is_location(entry[0]):
        location, obj = entry
        return AdmissionTarget(obj, location=location)

    return AdmissionTarget(entry)


def iter_targets(targets):
    if isinstance(targets, AdmissionTarget):
        yield targets
    elif isinstance(targets, (str, bytes, Mapping)):
        yield normalize_target(targets)
    elif (
        isinstance(targets, tuple)
        and len(targets) == 2
        and _is_location(targets[0])
    ):
        yield normalize_target(targets)
    elif targets is None:
        return
    elif isinstance(targets, Iterable):
        for target in targets:
            yield normalize_target(target)
    else:
        yield normalize_target(targets)


def _instantiate_permission(permission):
    from rest_framework.permissions import BasePermission

    if isinstance(permission, BasePermission):
        return permission
    if callable(permission):
        try:
            instance = permission()
        except TypeError:
            return permission
        if isinstance(instance, BasePermission):
            return instance
    return permission


def resolve_admission_permissions(
    serializer=None, request=None, view=None,
    permission_classes=None, permissions=None,
):
    if permissions is not None:
        return [_instantiate_permission(permission) for permission in permissions]

    if permission_classes is None and serializer is not None:
        for attr in (
            'admission_permission_classes',
            'target_permission_classes',
            'object_permission_classes',
            'permission_classes',
        ):
            permission_classes = getattr(serializer, attr, None)
            if permission_classes is not None:
                break

    if permission_classes is not None:
        return [
            _instantiate_permission(permission)
            for permission in permission_classes
        ]

    if view is not None:
        if hasattr(view, 'get_permissions'):
            return list(view.get_permissions())
        view_classes = getattr(view, 'permission_classes', None)
        if view_classes is not None:
            return [_instantiate_permission(p) for p in view_classes]

    return [
        _instantiate_permission(permission_class)
        for permission_class in api_settings.DEFAULT_PERMISSION_CLASSES
    ]


def _denial_detail_from_exception(exc):
    if isinstance(exc, PermissionDenied):
        return exc.detail

    if isinstance(exc, DjangoPermissionDenied):
        return ErrorDetail(
            force_str(exc) or force_str(DEFAULT_DENIED_MESSAGE),
            code=DEFAULT_DENIED_CODE,
        )

    return None


def check_target_admission(
    targets, *, serializer=None, request=None, view=None,
    permission_classes=None, permissions=None,
):
    """
    Check every concrete write target against existing object permissions.

    All denied targets are collected before raising, allowing a bulk response
    or caller to identify every affected row.
    """
    context = getattr(serializer, 'context', {}) or {}
    request = request if request is not None else context.get('request')
    view = view if view is not None else context.get('view')

    permission_instances = resolve_admission_permissions(
        serializer=serializer,
        request=request,
        view=view,
        permission_classes=permission_classes,
        permissions=permissions,
    )

    normalized_targets = list(iter_targets(targets))
    failures = []

    for target in normalized_targets:
        for permission in permission_instances:
            detail = None
            try:
                allowed = permission.has_object_permission(
                    request, view, target.obj
                )
            except (PermissionDenied, DjangoPermissionDenied) as exc:
                allowed = False
                detail = _denial_detail_from_exception(exc)

            if not allowed:
                if detail is None:
                    message = (
                        getattr(permission, 'message', None)
                        or DEFAULT_DENIED_MESSAGE
                    )
                    code = (
                        getattr(permission, 'code', None)
                        or DEFAULT_DENIED_CODE
                    )
                    detail = ErrorDetail(force_str(message), code=code)
                failures.append(
                    AdmissionFailure(target, permission, detail=detail)
                )
                break

    if failures:
        raise AdmissionDenied(failures)

    return AdmissionConfirmation(
        normalized_targets,
        permission_instances,
        request=request,
        view=view,
    )


def check_object_permissions(
    request, view, targets, *, permission_classes=None, permissions=None,
):
    """
    View-style functional entry point for checking many concrete targets.
    """
    return check_target_admission(
        targets,
        request=request,
        view=view,
        permission_classes=permission_classes,
        permissions=permissions,
    )


@contextmanager
def admission_transaction(using=None):
    """
    Transaction boundary for one admitted bulk/nested write.

    A denial discovered during a row-level recheck, or any persistence error,
    exits this context and rolls the whole write back.
    """
    with transaction.atomic(using=using):
        yield


class TargetAdmissionMixin:
    """
    Serializer helpers for opting custom nested/bulk updates into admission.
    """

    admission_enabled = False
    admission_permission_classes = None
    admission_atomic = True
    admission_preflight = True
    admission_transaction_using = None

    def admission_is_enabled(self):
        if self.admission_enabled:
            return True
        if self.get_admission_permission_classes() is not None:
            return True

        base_getter = TargetAdmissionMixin.get_write_targets
        if type(self).get_write_targets is not base_getter:
            return True

        base_admission_getter = TargetAdmissionMixin.get_admission_targets
        return type(self).get_admission_targets is not base_admission_getter

    def get_admission_permission_classes(self):
        for attr in (
            'admission_permission_classes',
            'target_permission_classes',
            'object_permission_classes',
            'permission_classes',
        ):
            classes = getattr(self, attr, None)
            if classes is not None:
                return classes
        return None

    def get_admission_permissions(self):
        return resolve_admission_permissions(
            serializer=self,
            permission_classes=self.get_admission_permission_classes(),
        )

    def get_write_targets(self):
        """
        Return the concrete objects for the pending update.

        Custom serializers should override this when they want save-time
        preflight admission. Updates can additionally call
        ``check_write_target()`` immediately before each individual write.
        """
        return ()

    def get_admission_targets(self):
        return self.get_write_targets()

    def admit_targets(self, targets=None):
        if targets is None:
            targets = self.get_admission_targets()
        return check_target_admission(targets, serializer=self)

    def admit_target(self, obj, location=(), index=None, key=None):
        return check_target_admission(
            [AdmissionTarget(obj, location=location, index=index, key=key)],
            serializer=self,
        )

    def check_object_permissions(self, *args, **kwargs):
        # Serializer-friendly form: check_object_permissions(targets).
        if not args:
            targets = kwargs.pop('targets', None)
            if targets is None:
                targets = self.get_admission_targets()
            return check_target_admission(targets, serializer=self, **kwargs)

        # View-compatible form: check_object_permissions(request, targets)
        # or the explicit functional form (request, view, targets).
        if len(args) == 3:
            request, view, targets = args
            return check_target_admission(
                targets,
                serializer=self,
                request=request,
                view=view,
                **kwargs,
            )

        if len(args) == 2:
            request, targets = args
            return check_target_admission(
                targets, serializer=self, request=request, **kwargs
            )

        return check_target_admission(args[0], serializer=self, **kwargs)

    @contextmanager
    def admission_boundary(self):
        with admission_transaction(using=self.admission_transaction_using):
            yield

    def save(self, **kwargs):
        """
        Opt-in save boundary used by ``AdmissionListSerializer``.

        The check runs immediately before persistence, after serializer
        validation, so permission revocation during validation is observed.
        """
        self._admission_confirmation = None
        if self.admission_atomic:
            with self.admission_boundary():
                if self.admission_preflight:
                    self._admission_confirmation = self.admit_targets()
                return super().save(**kwargs)

        if self.admission_preflight:
            self._admission_confirmation = self.admit_targets()
        return super().save(**kwargs)

    # Descriptive aliases for application code and alternative naming choices.
    confirm_target_admission = admit_targets
    check_admission = admit_targets
    check_target_admission = admit_targets
    check_targets = admit_targets
    check_write_targets = admit_targets
    check_write_target = admit_target
    check_target_permission = admit_target
    check_object_admission = admit_target
    atomic_write = admission_boundary
    write_transaction = admission_boundary
