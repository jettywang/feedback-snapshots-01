from django.http import HttpResponse
from django.template import engines

from sesame.capabilities import get_capability


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


def show_capability(request, *args, **kwargs):
    # State the user and the capability that was granted for this request.
    capability = get_capability(request)
    if request.user.is_authenticated:
        content = f"{request.user.username}|capability:{capability}"
    else:
        content = f"anonymous|capability:{capability}"
    return HttpResponse(content, content_type="text/plain")
