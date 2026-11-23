import json
from urllib.parse import unquote, urlparse

from channels.testing.application import ApplicationCommunicator


class WebsocketCommunicator(ApplicationCommunicator):
    """
    ApplicationCommunicator subclass that has WebSocket shortcut methods.

    It will construct the scope for you, so you need to pass the application
    (uninstantiated) along with the initial connection parameters.
    """

    def __init__(
        self,
        application,
        path,
        headers=None,
        subprotocols=None,
        spec_version=None,
        extensions=None,
    ):
        if not isinstance(path, str):
            raise TypeError("Expected str, got {}".format(type(path)))
        parsed = urlparse(path)
        self.scope = {
            "type": "websocket",
            "path": unquote(parsed.path),
            "query_string": parsed.query.encode("utf-8"),
            "headers": headers or [],
            "subprotocols": subprotocols or [],
        }
        if spec_version:
            self.scope["spec_version"] = spec_version
        if extensions is not None:
            # Accept either a list of extension names or the spec's mapping of
            # extension name to optional settings.
            self.scope["extensions"] = (
                {name: {} for name in extensions}
                if isinstance(extensions, (list, tuple))
                else dict(extensions)
            )
        super().__init__(application, self.scope)
        self.response_headers = None
        self.http_response_status = None
        self.http_response_headers = None
        self.http_response_body = None

    async def connect(self, timeout=1):
        """
        Trigger the connection code.

        On an accepted connection, returns (True, <chosen-subprotocol>)
        On a rejected connection, returns (False, <close-code>). When the
        server scope advertises ``websocket.http.response`` and the
        application rejects the handshake with an HTTP response, the rejection
        is available afterwards as ``http_response_status``,
        ``http_response_headers`` and ``http_response_body`` and the close code
        is ``None``.
        """
        await self.send_input({"type": "websocket.connect"})
        response = await self.receive_output(timeout)
        if response["type"] == "websocket.close":
            return (False, response.get("code", 1000))
        elif response["type"] == "http.response.start":
            self.http_response_status = response["status"]
            self.http_response_headers = response.get("headers", [])
            body = await self.receive_output(timeout)
            assert body["type"] == "http.response.body"
            self.http_response_body = body.get("body", b"")
            return (False, None)
        else:
            assert response["type"] == "websocket.accept"
            self.response_headers = response.get("headers", [])
            return (True, response.get("subprotocol", None))

    async def send_to(self, text_data=None, bytes_data=None):
        """
        Sends a WebSocket frame to the application.
        """
        # Make sure we have exactly one of the arguments
        assert bool(text_data) != bool(
            bytes_data
        ), "You must supply exactly one of text_data or bytes_data"
        # Send the right kind of event
        if text_data:
            assert isinstance(text_data, str), "The text_data argument must be a str"
            await self.send_input({"type": "websocket.receive", "text": text_data})
        else:
            assert isinstance(
                bytes_data, bytes
            ), "The bytes_data argument must be bytes"
            await self.send_input({"type": "websocket.receive", "bytes": bytes_data})

    async def send_json_to(self, data):
        """
        Sends JSON data as a text frame
        """
        await self.send_to(text_data=json.dumps(data))

    async def receive_from(self, timeout=1):
        """
        Receives a data frame from the view. Will fail if the connection
        closes instead. Returns either a bytestring or a unicode string
        depending on what sort of frame you got.
        """
        response = await self.receive_output(timeout)
        # Make sure this is a send message
        assert (
            response["type"] == "websocket.send"
        ), f"Expected type 'websocket.send', but was '{response['type']}'"
        # Make sure there's exactly one key in the response
        assert ("text" in response) != (
            "bytes" in response
        ), "The response needs exactly one of 'text' or 'bytes'"
        # Pull out the right key and typecheck it for our users
        if "text" in response:
            assert isinstance(
                response["text"], str
            ), f"Text frame payload is not str, it is {type(response['text'])}"
            return response["text"]
        else:
            assert isinstance(
                response["bytes"], bytes
            ), f"Binary frame payload is not bytes, it is {type(response['bytes'])}"
            return response["bytes"]

    async def receive_json_from(self, timeout=1):
        """
        Receives a JSON text frame payload and decodes it
        """
        payload = await self.receive_from(timeout)
        assert isinstance(
            payload, str
        ), f"JSON data is not a text frame, it is {type(payload)}"
        return json.loads(payload)

    async def disconnect(self, code=1000, timeout=1):
        """
        Closes the socket
        """
        await self.send_input({"type": "websocket.disconnect", "code": code})
        await self.wait(timeout)
