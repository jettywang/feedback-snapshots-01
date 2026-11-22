def site_from_header(request):
    """
    Resolve a site from a request header.

    In a real deployment, this would look at the Host header, a tenant column,
    or a reverse proxy header set by each white-label front end.

    """
    return request.META.get("HTTP_X_SITE") or None


def failing_resolver(request):
    """
    Simulate a routing table that cannot be consulted.

    """
    raise RuntimeError("routing table unavailable")
