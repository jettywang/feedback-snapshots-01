from typing import Callable, Optional
from urllib.parse import parse_qs

from .exposition import _bake_output, _generate_output, CONTENT_TYPE_PLAIN_0_0_4
from .registry import Collector, REGISTRY
from .scrape import CollectionBudget, ScrapeBudgetExceeded


class _ASGIApp:
    """ASGI application object wrapping the metrics handler.

    Frameworks such as Starlette and FastAPI treat a plain function passed to
    ``add_route`` as a ``request -> response`` endpoint, but any other callable
    as a raw ASGI application. Returning an instance rather than a bare
    function allows ``app.add_route("/metrics", make_asgi_app())`` to serve
    metrics at ``/metrics`` exactly, without the trailing-slash redirect that
    ``app.mount("/metrics", ...)`` produces.
    """

    def __init__(self, app: Callable) -> None:
        self._app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        await self._app(scope, receive, send)


def make_asgi_app(registry: Collector = REGISTRY, disable_compression: bool = False,
                   budget: Optional[CollectionBudget] = None) -> Callable:
    """Create a ASGI app which serves the metrics from a registry.

    ``budget`` optionally bounds the per-scrape generation time and the total
    number of concurrent scrapes. Collection is offloaded to a worker thread,
    so a slow or blocked custom collector never stalls the event loop. A
    scrape that exceeds the budget is answered with
    ``503 Service Unavailable`` rather than a partial metrics response.
    """

    async def prometheus_app(scope, receive, send):
        assert scope.get("type") == "http"
        # Prepare parameters
        params = parse_qs(scope.get('query_string', b'').decode("utf8"))
        accept_header = ",".join([
            value.decode("utf8") for (name, value) in scope.get('headers')
            if name.decode("utf8").lower() == 'accept'
        ])
        accept_encoding_header = ",".join([
            value.decode("utf8") for (name, value) in scope.get('headers')
            if name.decode("utf8").lower() == 'accept-encoding'
        ])
        # Bake output. The budget is applied exactly once here: with a budget
        # the blocking generation runs on a worker thread via ``arun``, while
        # without one it runs inline on the event loop as before.
        try:
            if budget is None:
                status, headers, output = _bake_output(
                    registry, accept_header, accept_encoding_header, params,
                    disable_compression)
            else:
                output, headers = await budget.arun(
                    lambda: _generate_output(
                        registry, accept_header, accept_encoding_header,
                        params, disable_compression))
                status = '200 OK'
        except ScrapeBudgetExceeded as exceeded:
            status = exceeded.status
            headers = [('Content-Type', CONTENT_TYPE_PLAIN_0_0_4)]
            output = exceeded.body
        formatted_headers = []
        for header in headers:
            formatted_headers.append(tuple(x.encode('utf8') for x in header))
        # Return output
        payload = await receive()
        if payload.get("type") == "http.request":
            await send(
                {
                    "type": "http.response.start",
                    "status": int(status.split(' ')[0]),
                    "headers": formatted_headers,
                }
            )
            await send({"type": "http.response.body", "body": output})

    return _ASGIApp(prometheus_app)
