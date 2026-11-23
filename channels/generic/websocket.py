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


class WebsocketConsumer(SyncConsumer):
    """
    Base WebSocket consumer. Provides a general encapsulation for the
    WebSocket handling model that other applications can build on.
    """

    groups = None

    def __init__(self, *args, **kwargs):
        if self.groups is None:
            self.groups = []
        # Track every group this instance has attempted to join. A backend may
        # apply a membership even if the group_add() call is cancelled, so the
        # attempt must be recorded before awaiting it.
        self._joined_groups = set()

    def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            for group in self.groups:
                self._add_group(group)
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

    def _add_group(self, group):
        """
        Records and joins a group.
        """
        self._joined_groups.add(group)
        async_to_sync(self.channel_layer.group_add)(group, self.channel_name)

    def _discard_groups(self):
        """
        Leaves every group this instance attempted to join.

        Cleanup is best-effort and idempotent: the tracked set is cleared as
        entries are handled, so repeated disconnects (or a disconnect after a
        cancelled or failed connect) cannot affect another connection.
        """
        async_to_sync(self._discard_groups_async)()

    async def _discard_groups_async(self):
        while self._joined_groups:
            group = self._joined_groups.pop()
            try:
                await self.channel_layer.group_discard(group, self.channel_name)
            except (Exception, asyncio.CancelledError):
                # A cleanup failure must not mask the connection's outcome.
                pass

    async def _cleanup(self):
        # The channel layer API is async, so clean up directly on the event
        # loop. This still runs when the handler thread is stuck before accept.
        await self._discard_groups_async()

    def connect(self):
        self.accept()

    def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
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
            self._discard_groups()
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


class AsyncWebsocketConsumer(AsyncConsumer):
    """
    Base WebSocket consumer, async version. Provides a general encapsulation
    for the WebSocket handling model that other applications can build on.
    """

    groups = None

    def __init__(self, *args, **kwargs):
        if self.groups is None:
            self.groups = []
        # Track every group this instance has attempted to join. A backend may
        # apply a membership even if the group_add() call is cancelled, so the
        # attempt must be recorded before awaiting it.
        self._joined_groups = set()

    async def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            for group in self.groups:
                self._joined_groups.add(group)
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

    async def _cleanup(self):
        """
        Leaves every group this instance attempted to join.

        Cleanup is best-effort and idempotent: the tracked set is cleared as
        entries are handled, so repeated disconnects (or a disconnect after a
        cancelled or failed connect) cannot affect another connection.
        """
        while self._joined_groups:
            group = self._joined_groups.pop()
            try:
                await self.channel_layer.group_discard(group, self.channel_name)
            except (Exception, asyncio.CancelledError):
                # A cleanup failure must not mask the connection's outcome.
                pass

    async def connect(self):
        await self.accept()

    async def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
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
            await self._cleanup()
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
