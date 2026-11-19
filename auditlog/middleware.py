from django.conf import settings
from django.contrib.auth import get_user_model

from auditlog.cid import set_cid
from auditlog.context import set_extra_data

# Request headers that may carry the business ticket identifier.  Only these
# values are considered trusted enough to be persisted on access events.
DEFAULT_TICKET_HEADERS = ("x-auditlog-ticket", "x-ticket-id")

# Never accept a ticket id from a proxy-controlled header such as
# ``X-Forwarded-*``; those values are not business input.
_RESERVED_TICKET_HEADERS = frozenset({"x-forwarded-for", "x-forwarded-port"})


class AuditlogMiddleware:
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the
    signal receiver with the user from the request (or None if the user is not authenticated).
    """

    # Extra context fields that this middleware may store on access events.
    # ``None`` means "use the project policy only".  Custom middleware can set
    # a tuple here or override :meth:`get_extra_fields` to extend the allowlist.
    access_extra_fields = None

    ticket_headers = DEFAULT_TICKET_HEADERS

    def __init__(self, get_response=None):
        self.get_response = get_response
        if not isinstance(settings.AUDITLOG_DISABLE_REMOTE_ADDR, bool):
            raise TypeError("Setting 'AUDITLOG_DISABLE_REMOTE_ADDR' must be a boolean")

    @staticmethod
    def _get_remote_addr(request):
        if settings.AUDITLOG_DISABLE_REMOTE_ADDR:
            return None

        # In case there is no proxy, return the original address
        if not request.headers.get("X-Forwarded-For"):
            return request.META.get("REMOTE_ADDR")

        # In case of proxy, set 'original' address
        remote_addr: str = request.headers.get("X-Forwarded-For").split(",")[0]

        # Remove port number from remote_addr
        if "." in remote_addr and ":" in remote_addr:  # IPv4 with port (`x.x.x.x:x`)
            remote_addr = remote_addr.split(":")[0]
        elif "[" in remote_addr:  # IPv6 with port (`[:::]:x`)
            remote_addr = remote_addr[1:].split("]")[0]

        return remote_addr

    @staticmethod
    def _get_remote_port(request) -> int | None:
        remote_port = request.headers.get("X-Forwarded-Port", "")

        try:
            remote_port = int(remote_port)
        except ValueError:
            remote_port = None

        return remote_port

    @staticmethod
    def _get_actor(request):
        user = getattr(request, "user", None)
        if isinstance(user, get_user_model()) and user.is_authenticated:
            return user
        return None

    def _get_ticket_id(self, request):
        """Return a trusted ticket identifier from an allowlisted header.

        Values injected through other channels (query strings, arbitrary
        headers, request body) are intentionally ignored.  Ticket headers may
        be overridden per middleware instance or through
        ``AUDITLOG_TICKET_HEADERS``.
        """
        headers = getattr(settings, "AUDITLOG_TICKET_HEADERS", None)
        if headers is None:
            single_header = getattr(settings, "AUDITLOG_TICKET_HEADER", None)
            headers = (single_header,) if single_header else self.ticket_headers
        for header in headers or ():
            if not isinstance(header, str):
                continue
            header = header.strip()
            if not header or header.lower() in _RESERVED_TICKET_HEADERS:
                continue
            value = request.headers.get(header)
            if value is None and header.upper().startswith("HTTP_"):
                value = request.META.get(header)
                if value is None:
                    value = request.META.get(header.upper())
            if isinstance(value, str):
                value = value.strip()
                if value:
                    return value
        return None

    def get_extra_data(self, request):
        context_data = {}
        context_data["remote_addr"] = self._get_remote_addr(request)
        context_data["remote_port"] = self._get_remote_port(request)

        context_data["actor"] = self._get_actor(request)

        ticket_id = self._get_ticket_id(request)
        if ticket_id is not None:
            context_data["ticket_id"] = ticket_id

        return context_data

    def get_extra_fields(self, request):
        """Return allowlist entries for context fields stored on access events.

        Subclasses may extend this tuple to persist additional plugin data.
        """
        fields = self.access_extra_fields
        if fields is None:
            fields = getattr(self, "allowed_extra_fields", None)
        if fields is None:
            fields = getattr(self, "extra_fields", None)
        if not fields:
            return ()
        return tuple(fields)

    def get_allowed_extra_fields(self, request):
        """Alias for :meth:`get_extra_fields` for custom middleware."""
        return self.get_extra_fields(request)

    def get_extra_allowlist(self, request):
        """Alias for :meth:`get_extra_fields` for custom middleware."""
        return self.get_extra_fields(request)

    def __call__(self, request):
        set_cid(request)

        with set_extra_data(
            context_data=self.get_extra_data(request),
            extra_fields=self.get_extra_fields(request),
        ):
            return self.get_response(request)
