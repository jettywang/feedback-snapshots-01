def site_from_header(request):
    """
    Resolve a site from the ``X-Site`` request header.

    """
    return request.META.get("HTTP_X_SITE") or None


def site_from_host(request):
    """
    Resolve a site from the leftmost label of the host name.

    """
    return request.get_host().split(":")[0].split(".")[0]


def failing_resolver(request):
    raise RuntimeError("routing table unavailable")


def unknown_resolver(request):
    return "site_c"
