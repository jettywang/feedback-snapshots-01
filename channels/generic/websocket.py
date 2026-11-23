import asyncio
import json

from asgiref.sync import async_to_sync

from ..consumer import AsyncConsumer, SyncConsumer
from ..db import aclose_old_connections
from ..exceptions import (
    AcceptConnection,
    DenyConnection,
    InvalidChannelLayerError,
    StopConsumer,
)
from ..sessions import save_session as save_scope_session


class _ConnectionConfirmationMixin:
    """
    Optional connection-confirmation phase shared by both WebSocket consumers.

    Set ``connection_confirmation = True`` to make the consumer save its
    session once ``connect()`` has completed, before any WebSocket frame is
    dispatched to the application. ``connect()`` may accept the socket first,
    so an as-yet unauthenticated connection can finish the protocol handshake;
    frames that arrive while the save is in flight stay queued and are only
    dispatched after the save resolves.

    The confirmation runs against ``self.scope`` - the same session instance
    and ``scope["user"]`` that message handlers later see - so a login done in
    ``connect()`` is what the business handlers operate on.

    If the save raises, the connection is closed with
    ``connection_confirmation_failed_close_code`` (a 4000-range application
    code, distinct from a normal ``1000``/``1001`` disconnect) and no message
    handler runs. If the confirmation is cancelled, it is not treated as a
    success: the cancellation propagates and no handler runs.
    """

    #: Opt in to the connection-confirmation phase.
    connection_confirmation = False

    #: Close code sent when the session cannot be saved. The 4000-4999 range
    #: is reserved for application-defined close reasons.
    connection_confirmation_failed_close_code = 4401

    #: Reason sent alongside the failure close code. Keep it generic; details
    #: are available to the application as ``confirmation_error``.
    connection_confirmation_failed_reason = "Connection confirmation failed"

    #: Set to ``True`` once the session save has succeeded.
    connection_confirmed = False

    #: The exception that prevented confirmation, if any.
    confirmation_error = None

    #: Set by ``accept()``; confirmation only runs for an accepted socket.
    _connection_accepted = False

    async def confirm_connection(self):
        """
        Performs the confirmation work. Override to add checks after login.

        The default persists the session in ``self.scope`` using the same
        code path as ``SessionMiddleware``. Raise to reject the connection.
        """
        await save_scope_session(self.scope)

    async def _run_connection_confirmation(self):
        """
        Runs the confirmation hook. Returns ``True`` when confirmed.

        ``CancelledError`` is never converted into success or failure; it is
        allowed to propagate so a cancelled connection cannot be mistaken for
        a confirmed one.
        """
        try:
            await self.confirm_connection()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.confirmation_error = error
            return False
        self.connection_confirmed = True
        return True

    async def _discard_groups_after_failed_confirmation(self):
        """
        Leaves groups joined on connect, since ``StopConsumer`` skips the
        normal ``websocket_disconnect`` cleanup. Best-effort.
        """
        for group in self.groups:
            try:
                await self.channel_layer.group_discard(group, self.channel_name)
            except Exception:
                pass


class WebsocketConsumer(_ConnectionConfirmationMixin, SyncConsumer):
    """
    Base WebSocket consumer. Provides a general encapsulation for the
    WebSocket handling model that other applications can build on.
    """

    groups = None

    def __init__(self, *args, **kwargs):
        if self.groups is None:
            self.groups = []

    def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            for group in self.groups:
                async_to_sync(self.channel_layer.group_add)(group, self.channel_name)
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        try:
            self.connect()
        except AcceptConnection:
            self.accept()
        except DenyConnection:
            self.close()
        if self.connection_confirmation and self._connection_accepted:
            if not async_to_sync(self._run_connection_confirmation)():
                self._fail_connection_confirmation()

    def _fail_connection_confirmation(self):
        # The socket may already have been accepted, so send an explicit close
        # with a code that identifies a confirmation failure.
        self.close(
            code=self.connection_confirmation_failed_close_code,
            reason=self.connection_confirmation_failed_reason,
        )
        async_to_sync(self._discard_groups_after_failed_confirmation)()
        raise StopConsumer()

    def connect(self):
        self.accept()

    def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
        self._connection_accepted = True
        message = {"type": "websocket.accept", "subprotocol": subprotocol}
        if headers:
            message["headers"] = list(headers)

        super().send(message)

    def websocket_receive(self, message):
        """
        Called when a WebSocket frame is received. Decodes it and passes it
        to receive().
        """
        if message.get("text") is not None:
            self.receive(text_data=message["text"])
        else:
            self.receive(bytes_data=message["bytes"])

    def receive(self, text_data=None, bytes_data=None):
        """
        Called with a decoded WebSocket frame.
        """
        pass

    def send(self, text_data=None, bytes_data=None, close=False):
        """
        Sends a reply back down the WebSocket
        """
        if text_data is not None:
            super().send({"type": "websocket.send", "text": text_data})
        elif bytes_data is not None:
            super().send({"type": "websocket.send", "bytes": bytes_data})
        else:
            raise ValueError("You must pass one of bytes_data or text_data")
        if close:
            self.close(close)

    def close(self, code=None, reason=None):
        """
        Closes the WebSocket from the server end
        """
        message = {"type": "websocket.close"}
        if code is not None and code is not True:
            message["code"] = code
        if reason:
            message["reason"] = reason
        super().send(message)

    def websocket_disconnect(self, message):
        """
        Called when a WebSocket connection is closed. Base level so you don't
        need to call super() all the time.
        """
        try:
            for group in self.groups:
                async_to_sync(self.channel_layer.group_discard)(
                    group, self.channel_name
                )
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        self.disconnect(message["code"])
        raise StopConsumer()

    def disconnect(self, code):
        """
        Called when a WebSocket connection is closed.
        """
        pass


class JsonWebsocketConsumer(WebsocketConsumer):
    """
    Variant of WebsocketConsumer that automatically JSON-encodes and decodes
    messages as they come in and go out. Expects everything to be text; will
    error on binary data.
    """

    def receive(self, text_data=None, bytes_data=None, **kwargs):
        if text_data:
            self.receive_json(self.decode_json(text_data), **kwargs)
        else:
            raise ValueError("No text section for incoming WebSocket frame!")

    def receive_json(self, content, **kwargs):
        """
        Called with decoded JSON content.
        """
        pass

    def send_json(self, content, close=False):
        """
        Encode the given content as JSON and send it to the client.
        """
        super().send(text_data=self.encode_json(content), close=close)

    @classmethod
    def decode_json(cls, text_data):
        return json.loads(text_data)

    @classmethod
    def encode_json(cls, content):
        return json.dumps(content)


class AsyncWebsocketConsumer(_ConnectionConfirmationMixin, AsyncConsumer):
    """
    Base WebSocket consumer, async version. Provides a general encapsulation
    for the WebSocket handling model that other applications can build on.
    """

    groups = None

    def __init__(self, *args, **kwargs):
        if self.groups is None:
            self.groups = []

    async def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            for group in self.groups:
                await self.channel_layer.group_add(group, self.channel_name)
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        try:
            await self.connect()
        except AcceptConnection:
            await self.accept()
        except DenyConnection:
            await self.close()
        if self.connection_confirmation and self._connection_accepted:
            if not await self._run_connection_confirmation():
                await self.close(
                    code=self.connection_confirmation_failed_close_code,
                    reason=self.connection_confirmation_failed_reason,
                )
                await self._discard_groups_after_failed_confirmation()
                raise StopConsumer()

    async def connect(self):
        await self.accept()

    async def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
        self._connection_accepted = True
        message = {"type": "websocket.accept", "subprotocol": subprotocol}
        if headers:
            message["headers"] = list(headers)
        await super().send(message)

    async def websocket_receive(self, message):
        """
        Called when a WebSocket frame is received. Decodes it and passes it
        to receive().
        """
        if message.get("text") is not None:
            await self.receive(text_data=message["text"])
        else:
            await self.receive(bytes_data=message["bytes"])

    async def receive(self, text_data=None, bytes_data=None):
        """
        Called with a decoded WebSocket frame.
        """
        pass

    async def send(self, text_data=None, bytes_data=None, close=False):
        """
        Sends a reply back down the WebSocket
        """
        if text_data is not None:
            await super().send({"type": "websocket.send", "text": text_data})
        elif bytes_data is not None:
            await super().send({"type": "websocket.send", "bytes": bytes_data})
        else:
            raise ValueError("You must pass one of bytes_data or text_data")
        if close:
            await self.close(close)

    async def close(self, code=None, reason=None):
        """
        Closes the WebSocket from the server end
        """
        message = {"type": "websocket.close"}
        if code is not None and code is not True:
            message["code"] = code
        if reason:
            message["reason"] = reason
        await super().send(message)

    async def websocket_disconnect(self, message):
        """
        Called when a WebSocket connection is closed. Base level so you don't
        need to call super() all the time.
        """
        try:
            for group in self.groups:
                await self.channel_layer.group_discard(group, self.channel_name)
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        await self.disconnect(message["code"])
        await aclose_old_connections()
        raise StopConsumer()

    async def disconnect(self, code):
        """
        Called when a WebSocket connection is closed.
        """
        pass


class AsyncJsonWebsocketConsumer(AsyncWebsocketConsumer):
    """
    Variant of AsyncWebsocketConsumer that automatically JSON-encodes and decodes
    messages as they come in and go out. Expects everything to be text; will
    error on binary data.
    """

    async def receive(self, text_data=None, bytes_data=None, **kwargs):
        if text_data:
            await self.receive_json(await self.decode_json(text_data), **kwargs)
        else:
            raise ValueError("No text section for incoming WebSocket frame!")

    async def receive_json(self, content, **kwargs):
        """
        Called with decoded JSON content.
        """
        pass

    async def send_json(self, content, close=False):
        """
        Encode the given content as JSON and send it to the client.
        """
        await super().send(text_data=await self.encode_json(content), close=close)

    @classmethod
    async def decode_json(cls, text_data):
        return json.loads(text_data)

    @classmethod
    async def encode_json(cls, content):
        return json.dumps(content)
