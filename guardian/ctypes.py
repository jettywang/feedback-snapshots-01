import inspect
from functools import lru_cache
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.utils.module_loading import import_string

from guardian.conf import settings as guardian_settings


@lru_cache(maxsize=None)
def _accepts_using(get_content_type_function: Any) -> bool:
    """Check whether the configured content type function accepts a `using` argument."""
    return "using" in inspect.signature(get_content_type_function).parameters


def get_content_type(obj: Model | type[Model], using: str | None = None) -> Any:
    """Return the content type for `obj`.

    When `using` is given, the content type is resolved against that
    database. Content type ids are only unique within one database, so
    callers checking permissions for an object must resolve the content
    type against the database that owns the object.

    Custom `GUARDIAN_GET_CONTENT_TYPE` functions are called with the
    `using` keyword argument only when they declare it; otherwise they are
    called exactly as before and resolve against the default database.
    """
    get_content_type_function = import_string(guardian_settings.GET_CONTENT_TYPE)
    if using is not None and _accepts_using(get_content_type_function):
        return get_content_type_function(obj, using=using)
    return get_content_type_function(obj)


def get_default_content_type(obj: Model | type[Model], using: str | None = None) -> ContentType:
    """Get content type for a given object using Django's content type framework.

    Parameters:
        obj (Model | type[Model]): Object for which content type is to be fetched.
        using (str | None): Database alias to resolve the content type
            against. Defaults to the routed (usually default) database.

    Returns:
        Content type for the given object.

    See Also:
        https://docs.djangoproject.com/en/5.1/ref/contrib/contenttypes/

    """
    if using is not None:
        return ContentType.objects.db_manager(using).get_for_model(obj)
    return ContentType.objects.get_for_model(obj)
