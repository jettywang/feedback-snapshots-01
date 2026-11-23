Security
========

This covers basic security for protocols you're serving via Channels and
helpers that we provide.


WebSockets
----------

WebSockets start out life as a HTTP request, including all the cookies
and headers, and so you can use the standard :doc:`/topics/authentication`
code in order to grab current sessions and check user IDs.

There is also a risk of cross-site request forgery (CSRF) with WebSockets though,
as they can be initiated from any site on the internet to your domain, and will
still have the user's cookies and session from your site. If you serve private
data down the socket, you should restrict the sites which are allowed to open
sockets to you.

This is done via the ``channels.security.websocket`` package, and the two
ASGI middlewares it contains, ``OriginValidator`` and
``AllowedHostsOriginValidator``.

``OriginValidator`` lets you restrict the valid options for the ``Origin``
header that is sent with every WebSocket to say where it comes from. Just wrap
it around your WebSocket application code like this, and pass it a list of
valid domains as the second argument. You can pass only a single domain (for example,
``.allowed-domain.com``) or a full origin, in the format ``scheme://domain[:port]``
(for example, ``http://allowed-domain.com:80``). Port is optional, but recommended:

.. code-block:: python

    from channels.security.websocket import OriginValidator

    application = ProtocolTypeRouter({

        "websocket": OriginValidator(
            AuthMiddlewareStack(
                URLRouter([
                    ...
                ])
            ),
            [".goodsite.com", "http://.goodsite.com:80", "http://other.site.com"],
        ),
    })

Note: If you want to resolve any domain, then use the origin ``*``.


Often, the set of domains you want to restrict to is the same as the Django
``ALLOWED_HOSTS`` setting, which performs a similar security check for the
``Host`` header, and so ``AllowedHostsOriginValidator`` lets you use this
setting without having to re-declare the list:

.. code-block:: python

    from channels.security.websocket import AllowedHostsOriginValidator

    application = ProtocolTypeRouter({

        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter([
                    ...
                ])
            ),
        ),
    })

``AllowedHostsOriginValidator`` will also automatically allow local connections
through if the site is in ``DEBUG`` mode, much like Django's host validation.


Rejecting a WebSocket handshake
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Internal ASGI servers come in two generations, and a rejected handshake must
follow the convention the deployed server understands:

* Newer servers advertise the ``websocket.http.response`` ASGI extension in the
  connection ``scope["extensions"]`` mapping. They can answer the opening HTTP
  request with an explicit rejection response (the
  ``http.response.start`` / ``http.response.body`` events). This lets a security
  gateway send a public status code and headers explaining the denial.
* Older servers only understand the legacy ``websocket.close`` event, which
  drops the connection without an HTTP response.

``WebsocketDenial`` picks the right convention for the connection it is given
and guarantees that a single connection only ever emits one terminal event:

.. code-block:: python

    from channels.security.websocket import WebsocketDenial

    async def asgi(scope, receive, send):
        denial = WebsocketDenial(scope, send, receive)
        await denial.deny()

When the extension is available, ``deny()`` sends the configured HTTP response;
otherwise it falls back to ``websocket.close``. The status code and header
names of an HTTP rejection must be on the ``approved_statuses`` and
``approved_headers`` allow lists passed to the constructor; anything else
raises ``ValueError`` so a gateway cannot leak arbitrary responses. The defaults
allow a ``403`` response with a ``content-type`` header.

The three situations in which no terminal event can be sent raise distinct
exceptions so callers can tell them apart:

* ``WebsocketHttpResponseUnavailable`` — the server does not advertise the
  extension and an explicit HTTP response was requested.
* ``ConnectionAlreadyAccepted`` — the connection was already accepted, so a
  handshake rejection is no longer possible.
* ``ConnectionDisconnectRaced`` — a ``websocket.disconnect`` event arrived
  before the denial could be sent. Constructing ``WebsocketDenial`` with the
  ``receive`` callable enables this check; any handshake message the probe had
  to read stays available through the ``WebsocketDenial.receive`` wrapper.
* ``DenialAlreadySent`` — a second terminal event was attempted.

``OriginValidator`` uses this machinery automatically, and
``WebsocketDenier`` remains available for code that specifically wants the
legacy close-only behaviour. Source checking and any business-level rejection
stay the responsibility of your existing entry points; a connection that is
rejected at either point never proceeds to business message handling.
