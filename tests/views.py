from django.http import HttpResponse
from django.template import engines


def show_user(request, *args, **kwargs):
    content = (
        engines["django"]
        .from_string(
            "{% if user.is_authenticated %}{{ user }}"
            "{% elif user.is_anonymous %}anonymous"
            "{% else %}no user"
            "{% endif %}"
        )
        .render(request=request)
    )
    return HttpResponse(content, content_type="text/plain")


def show_site(request, *args, **kwargs):
    """
    Render the authenticated user and the database and site it came from.

    """
    user = request.user
    site = getattr(request, "sesame_site", None)
    if user.is_authenticated:
        content = f"{user.username}|{user._state.db}|{site}"
    else:
        content = f"anonymous|{site}"
    return HttpResponse(content, content_type="text/plain")
