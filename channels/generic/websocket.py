import inspect
import json

from asgiref.sync import async_to_sync
from django.utils.functional import LazyObject, empty

from ..auth import get_user
from ..consumer import AsyncConsumer, SyncConsumer
from ..db import aclose_old_connections
from ..exceptions import (
    AcceptConnection,
    DenyConnection,
    InvalidChannelLayerError,
    StopConsumer,
)


class _GroupMembershipMixin:
    """
    Shared declaration, authorisation and bookkeeping for group membership.

    ``groups`` are ordinary observing groups and are joined on connect without
    an identity check. ``identity_groups`` are only joined once a reliable user
    is available and ``authorize_group()`` approves them.
    """

    groups = None
    identity_groups = None

    def __init__(self, *args, **kwargs):
        if self.groups is None:
            self.groups = []
        if self.identity_groups is None:
            self.identity_groups = []
        # ``submitted`` is intentionally populated before calling the channel
        # layer, so a backend that commits a membership and is then cancelled
        # can still be cleaned up.
        self._submitted_groups = []
        self._joined_groups = set()
        self._discarded_groups = set()
        self._pending_groups = set()
        self._denied_groups = {}
        self._failed_groups = {}
        self._accepted = False

    @property
    def submitted_groups(self):
        """
        Every group this connection has asked the channel layer to join.
        """
        return list(self._submitted_groups)

    @property
    def joined_groups(self):
        """
        Groups that are currently believed to have this channel as a member.
        """
        return [g for g in self._submitted_groups if g in self._joined_groups]

    @property
    def pending_groups(self):
        """
        Identity groups still waiting for a usable identity/session.
        """
        return list(self._pending_groups)

    @property
    def denied_groups(self):
        """
        Identity groups that were resolved but not authorised, with reasons.
        """
        return dict(self._denied_groups)

    @property
    def failed_groups(self):
        """
        Groups whose join attempt failed, with reasons.
        """
        return dict(self._failed_groups)

    @property
    def group_membership(self):
        """
        A snapshot of declaration and authorisation for this connection.
        """
        return {
            "declared": {
                "groups": list(self.groups),
                "identity_groups": list(self.identity_groups),
            },
            "submitted": self.submitted_groups,
            "joined": self.joined_groups,
            "pending": self.pending_groups,
            "denied": self.denied_groups,
            "failed": self.failed_groups,
        }

    async def _resolve_group_user(self):
        """
        Returns a reliable user for identity group checks, or None.

        An unresolved lazy ``scope["user"]`` falls back to the session; if
        neither can produce a conclusion the caller leaves groups pending.
        """
        user = self.scope.get("user", None)
        if isinstance(user, LazyObject) and user._wrapped is empty:
            user = None
        if user is not None:
            return user
        if "session" in self.scope:
            return await get_user(self.scope)
        return None

    async def _authorize_group(self, group, user):
        result = self.authorize_group(group, user)
        if inspect.isawaitable(result):
            result = await result
        return result

    def authorize_group(self, group, user):
        """
        Decides whether ``user`` may join an identity group.

        Override this hook to implement application policy. The default only
        requires an authenticated user. It may be a normal or async method.
        """
        return True

    def _record_submission(self, group):
        """
        Records an attempted join before the channel layer is called.
        """
        if group not in self._submitted_groups:
            self._submitted_groups.append(group)

    def _mark_joined(self, group):
        self._joined_groups.add(group)


class WebsocketConsumer(_GroupMembershipMixin, SyncConsumer):
    """
    Base WebSocket consumer. Provides a general encapsulation for the
    WebSocket handling model that other applications can build on.
    """

    def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            self._join_observer_groups()
            self._join_identity_groups()
            try:
                self.connect()
            except AcceptConnection:
                self.accept()
            except DenyConnection:
                self.close()
            if not self._accepted:
                self._discard_groups()
        except BaseException:
            # Includes cancellation while a group_add() is in flight. The
            # attempt was recorded before the call, so cleanup covers a
            # backend that applied the membership before being cancelled.
            self._discard_groups()
            raise

    def _join_observer_groups(self):
        """
        Joins groups that do not depend on the connection's identity.

        A group declared in both ``groups`` and ``identity_groups`` is treated
        as identity-gated; it is not joined before authorisation.
        """
        for group in self.groups:
            if group in self.identity_groups:
                continue
            self._add_group(group)

    def _join_identity_groups(self):
        """
        Resolves the connection identity, then joins only approved groups.

        An unresolved identity leaves the declared groups pending: no
        membership is submitted until a reliable session conclusion is
        available. A resolved but unauthorised identity is denied.
        """
        if not self.identity_groups:
            return
        try:
            user = async_to_sync(self._resolve_group_user)()
        except Exception as error:
            for group in self.identity_groups:
                self._failed_groups[group] = str(error) or error.__class__.__name__
            return
        self._apply_identity_groups(user, async_to_sync(self._authorize_group))

    def _apply_identity_groups(self, user, authorize):
        for group in self.identity_groups:
            if user is None:
                self._pending_groups.add(group)
                continue
            if not getattr(user, "is_authenticated", False):
                self._denied_groups[group] = "anonymous"
                continue
            try:
                allowed = authorize(group, user)
            except Exception as error:
                self._failed_groups[group] = str(error) or error.__class__.__name__
                continue
            if not allowed:
                self._denied_groups[group] = "not authorized"
                continue
            self._add_group(group)

    def _add_group(self, group):
        """
        Records and joins a group.
        """
        if group in self._joined_groups:
            return
        self._record_submission(group)
        try:
            async_to_sync(self.channel_layer.group_add)(group, self.channel_name)
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        self._mark_joined(group)

    def _discard_groups(self):
        """
        Leaves every group this connection submitted to the channel layer.

        Best-effort and idempotent: a group is marked discarded before the
        call is attempted, and the remaining active set only contains this
        connection's own channel, so repeated cleanup cannot affect another
        connection.
        """
        for group in list(self._submitted_groups):
            if group in self._discarded_groups:
                continue
            self._discarded_groups.add(group)
            self._joined_groups.discard(group)
            try:
                async_to_sync(self.channel_layer.group_discard)(
                    group, self.channel_name
                )
            except Exception:
                # Cleanup must not mask the connection's real outcome.
                pass

    def connect(self):
        self.accept()

    def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
        self._accepted = True
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


class AsyncWebsocketConsumer(_GroupMembershipMixin, AsyncConsumer):
    """
    Base WebSocket consumer, async version. Provides a general encapsulation
    for the WebSocket handling model that other applications can build on.
    """

    async def websocket_connect(self, message):
        """
        Called when a WebSocket connection is opened.
        """
        try:
            await self._join_observer_groups()
            await self._join_identity_groups()
            try:
                await self.connect()
            except AcceptConnection:
                await self.accept()
            except DenyConnection:
                await self.close()
            if not self._accepted:
                await self._discard_groups()
        except BaseException:
            # Includes cancellation while a group_add() is in flight. The
            # attempt was recorded before the call, so cleanup covers a
            # backend that applied the membership before being cancelled.
            await self._discard_groups()
            raise

    async def _join_observer_groups(self):
        """
        Joins groups that do not depend on the connection's identity.

        A group declared in both ``groups`` and ``identity_groups`` is treated
        as identity-gated; it is not joined before authorisation.
        """
        for group in self.groups:
            if group in self.identity_groups:
                continue
            await self._add_group(group)

    async def _join_identity_groups(self):
        """
        Resolves the connection identity, then joins only approved groups.

        An unresolved identity leaves the declared groups pending: no
        membership is submitted until a reliable session conclusion is
        available. A resolved but unauthorised identity is denied.
        """
        if not self.identity_groups:
            return
        try:
            user = await self._resolve_group_user()
        except Exception as error:
            for group in self.identity_groups:
                self._failed_groups[group] = str(error) or error.__class__.__name__
            return
        for group in self.identity_groups:
            if user is None:
                self._pending_groups.add(group)
                continue
            if not getattr(user, "is_authenticated", False):
                self._denied_groups[group] = "anonymous"
                continue
            try:
                allowed = await self._authorize_group(group, user)
            except Exception as error:
                self._failed_groups[group] = str(error) or error.__class__.__name__
                continue
            if not allowed:
                self._denied_groups[group] = "not authorized"
                continue
            await self._add_group(group)

    async def _add_group(self, group):
        """
        Records and joins a group.
        """
        if group in self._joined_groups:
            return
        self._record_submission(group)
        try:
            await self.channel_layer.group_add(group, self.channel_name)
        except AttributeError:
            raise InvalidChannelLayerError(
                "BACKEND is unconfigured or doesn't support groups"
            )
        self._mark_joined(group)

    async def _discard_groups(self):
        """
        Leaves every group this connection submitted to the channel layer.

        Best-effort and idempotent: a group is marked discarded before the
        call is attempted, and the remaining active set only contains this
        connection's own channel, so repeated cleanup cannot affect another
        connection.
        """
        for group in list(self._submitted_groups):
            if group in self._discarded_groups:
                continue
            self._discarded_groups.add(group)
            self._joined_groups.discard(group)
            try:
                await self.channel_layer.group_discard(group, self.channel_name)
            except Exception:
                # Cleanup must not mask the connection's real outcome.
                pass

    async def connect(self):
        await self.accept()

    async def accept(self, subprotocol=None, headers=None):
        """
        Accepts an incoming socket
        """
        self._accepted = True
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
            await self._discard_groups()
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
