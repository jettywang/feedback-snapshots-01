"""Opt-in WebSocket convention for authorized sequence replay."""

from __future__ import annotations

import inspect
from urllib.parse import parse_qs

from ..replay import (
    ReplayCursor,
    ReplayRequest,
    coerce_sequence_range,
    partition_history_authorization,
    requested_sequence_range,
)
from .websocket import AsyncJsonWebsocketConsumer


_BOUNDARY_KEYS = (
    "after_sequence",
    "since_sequence",
    "last_sequence",
    "ack_sequence",
    "last_seen_sequence",
    "sequence",
    "after",
    "since",
    "last_seen",
)
_ROOM_KEYS = ("room", "room_name", "group", "channel")
_REPLAY_TYPES = {
    "room.replay",
    "replay.request",
    "history.request",
    "room.history",
    "notification.replay",
}
_ACK_TYPES = {"room.ack", "ack", "room.acknowledge", "replay.ack"}


class ReplayWebsocketMixin:
    """
    JSON WebSocket mixin with explicit history authorization.

    History is never sent until ``authorize_history()`` has completed.  Live
    room events carrying a sequence are de-duplicated against the per-room
    cursor, including events that were already included in a replay snapshot.
    """

    room_name = None
    replay_room_argument = "room"
    replay_default_limit = None
    auto_join_room = True
    auto_replay_on_connect = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.replay_cursors = {}

    # Room/principal configuration

    def get_replay_principal(self):
        return self.scope.get("user")

    def resolve_replay_room(self, content=None):
        if content:
            for key in _ROOM_KEYS:
                if content.get(key):
                    return content[key]
        if self.room_name:
            return self.room_name
        route_kwargs = self.scope.get("url_route", {}).get("kwargs", {})
        return route_kwargs.get("room") or route_kwargs.get("room_name")

    def replay_cursor(self, room):
        if room not in self.replay_cursors:
            self.replay_cursors[room] = ReplayCursor()
        return self.replay_cursors[room]

    async def can_subscribe_realtime(self, room, principal=None):
        """Authorize the current live subscription."""
        return True

    async def can_receive_realtime(self, room, event=None, principal=None):
        """Authorize an individual live event delivery."""
        return True

    async def can_read_history(self, room, principal=None, **context):
        """
        Authorize history.

        Override this in applications.  The secure default denies all retained
        history while leaving the normal real-time path available.
        """
        return False

    async def connect(self):
        room = self.resolve_replay_room()
        principal = self.get_replay_principal()
        if room and self.auto_join_room:
            allowed = await self.can_subscribe_realtime(room, principal)
            if not allowed:
                await self.close(code=4403)
                return
            await self.channel_layer.group_add(room, self.channel_name)
        await self.accept()
        if self.auto_replay_on_connect or getattr(self, "replay_on_connect", False):
            await self.replay_from_query_string()

    # Client JSON routing

    async def receive_json(self, content, **kwargs):
        message_type = content.get("type")
        if message_type in _REPLAY_TYPES:
            await self.handle_replay_request(content)
        elif message_type in _ACK_TYPES:
            await self.handle_ack(content)
        else:
            await self.handle_client_message(content, **kwargs)

    async def handle_client_message(self, content, **kwargs):
        """Application JSON messages that are not replay control frames."""

    async def room_notification(self, event):
        replayed = bool(event.get("replayed", False))
        await self.deliver_group_event(event, replayed=replayed)

    async def deliver_group_event(self, event, *, replayed=False):
        room = event.get("room") or self.resolve_replay_room(event)
        principal = self.get_replay_principal()
        if not replayed and not await self.can_receive_realtime(room, event, principal):
            return False

        sequence = event.get("sequence")
        cursor = self.replay_cursor(room)
        if not cursor.admit(sequence):
            return False

        payload = dict(event)
        if room is not None:
            payload["room"] = room
        if sequence is not None:
            payload["sequence"] = sequence
        payload["replayed"] = replayed
        await self.send_json(payload)
        return True

    # Acknowledgements

    def boundary_from_content(self, content):
        for key in _BOUNDARY_KEYS:
            if key in content and content[key] is not None:
                return max(0, int(content[key]))
        return 0

    async def handle_ack(self, content):
        room = self.resolve_replay_room(content)
        sequence = self.boundary_from_content(content)
        if room is not None:
            self.replay_cursor(room).acknowledge(sequence)
        if content.get("receipt"):
            await self.send_json(
                {
                    "type": "room.acknowledged",
                    "room": room,
                    "sequence": sequence,
                }
            )

    # Query-string reconnect support

    def replay_content_from_query(self):
        query = parse_qs(self.scope.get("query_string", b"").decode("utf-8"))
        flat = {key: values[-1] for key, values in query.items() if values}
        if not any(key in flat for key in _BOUNDARY_KEYS):
            return None
        for key in _BOUNDARY_KEYS:
            if key in flat:
                try:
                    flat[key] = int(flat[key])
                except (TypeError, ValueError):
                    pass
                break
        flat["type"] = "room.replay"
        if self.replay_room_argument not in flat:
            room = self.resolve_replay_room()
            if room:
                flat["room"] = room
        return flat

    async def replay_from_query_string(self):
        content = self.replay_content_from_query()
        if content is not None:
            await self.handle_replay_request(content)

    # Authorization hook adaptation

    async def _call_policy_hook(self, hook, request):
        policy_values = {
            "room": request.room,
            "principal": request.principal,
            "user": request.principal,
            "request": request,
            "replay_request": request,
            "content": request.raw,
            "raw": request.raw,
            "event": request.raw,
            "message": request.raw,
            "after_sequence": request.after_sequence,
            "after": request.after_sequence,
            "since": request.after_sequence,
            "sequence": request.after_sequence,
            "boundary": request.after_sequence,
            "context": request,
            "scope": getattr(self, "scope", {}),
            "requested_range": request.requested_range,
            "available_range": request.available_range,
            "limit": request.limit,
        }
        try:
            signature = inspect.signature(hook)
        except (TypeError, ValueError):
            signature = None
        if signature is not None:
            accepts_kwargs = any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
            if not accepts_kwargs:
                policy_values = {
                    key: value
                    for key, value in policy_values.items()
                    if key in signature.parameters
                }
        result = hook(**policy_values)
        if inspect.isawaitable(result):
            result = await result
        return result

    async def authorize_history(self, request):
        """
        Return True, a sequence range, or ranges allowed for this request.

        The default delegates to ``can_read_history()`` and denies access if
        the application has not provided a policy hook under a known name.
        """
        base_hook = ReplayWebsocketMixin.can_read_history
        hook = self.can_read_history
        if getattr(hook, "__func__", hook) is not base_hook:
            return await self._call_policy_hook(hook, request)

        for hook_name in (
            "can_read_history",
            "can_replay_history",
            "check_history_permission",
            "has_history_permission",
            "authorize_room_history",
        ):
            hook = getattr(self, hook_name, None)
            if hook is None:
                continue
            function = getattr(hook, "__func__", hook)
            if function is base_hook:
                continue
            return await self._call_policy_hook(hook, request)
        return False

    # Replay flow

    def _make_request(self, content):
        room = self.resolve_replay_room(content)
        if not room:
            raise ValueError("A replay request requires a room")
        after_sequence = self.boundary_from_content(content)
        limit = content.get("limit", self.replay_default_limit)
        if limit is not None:
            limit = int(limit)
        before_sequence = content.get("before_sequence")
        if before_sequence is not None:
            before_sequence = int(before_sequence)
        return ReplayRequest(
            room=room,
            after_sequence=after_sequence,
            request_id=content.get("request_id") or content.get("id"),
            limit=limit,
            before_sequence=before_sequence,
            principal=self.get_replay_principal(),
            raw=dict(content),
        )

    @staticmethod
    def _range_json(value):
        return value.to_dict() if value is not None else None

    async def _read_allowed_entries(self, request, allowed_range):
        layer = self.channel_layer
        read_history = getattr(layer, "read_history", None)
        if read_history is None:
            return []
        try:
            entries = await read_history(
                request.room,
                from_sequence=allowed_range.first,
                to_sequence=allowed_range.last,
            )
        except TypeError:
            entries = await read_history(
                request.room,
                after_sequence=allowed_range.first - 1,
            )
        return [
            event
            for event in entries
            if coerce_sequence_range(
                event.get("sequence") if isinstance(event, dict) else None
            )
            is not None
            and int(event["sequence"]) in allowed_range
        ]

    async def handle_replay_request(self, content):
        try:
            request = self._make_request(content)
        except (KeyError, TypeError, ValueError) as exc:
            await self.send_json(
                {
                    "type": "room.replay_error",
                    "error": "invalid_request",
                    "detail": str(exc),
                    "request": content,
                }
            )
            return

        layer = self.channel_layer
        history_range = getattr(layer, "history_range", None)
        if history_range is None:
            await self.send_json(
                {
                    "type": "room.replay_error",
                    "request_id": request.request_id,
                    "room": request.room,
                    "error": "history_unsupported",
                }
            )
            return

        # Range metadata is not event content.  Authorization still happens
        # before any retained event is read or transmitted.
        available_range = await history_range(request.room)
        request.available_range = available_range
        request.requested_range = requested_sequence_range(
            available_range,
            request.after_sequence,
            before_sequence=request.before_sequence,
        )

        decision = self.authorize_history(request)
        if inspect.isawaitable(decision):
            decision = await decision

        # Refresh after the policy await.  Events committed while permission
        # was being resolved can therefore belong to the replay snapshot; the
        # per-room cursor suppresses their overlapping live delivery.
        available_range = await history_range(request.room)
        request.available_range = available_range
        request.requested_range = requested_sequence_range(
            available_range,
            request.after_sequence,
            before_sequence=request.before_sequence,
        )

        reason = None
        if isinstance(decision, dict):
            reason = decision.get("reason")
        allowed_ranges, denied_ranges = partition_history_authorization(
            request, decision
        )

        cursor = self.replay_cursor(request.room)
        cursor.acknowledge(request.after_sequence)

        await self.send_json(
            {
                "type": "room.replay_start",
                "request_id": request.request_id,
                "room": request.room,
                "after_sequence": request.after_sequence,
                "available_range": self._range_json(available_range),
                "requested_range": self._range_json(request.requested_range),
                "allowed_ranges": [self._range_json(r) for r in allowed_ranges],
                "denied_ranges": [self._range_json(r) for r in denied_ranges],
                "authorized": bool(allowed_ranges),
            }
        )

        for denied_range in denied_ranges:
            await self.send_json(
                {
                    "type": "room.history_denied",
                    "request_id": request.request_id,
                    "room": request.room,
                    "reason": reason or "history_permission_denied",
                    "range": self._range_json(denied_range),
                    "denied_range": self._range_json(denied_range),
                    "first_sequence": denied_range.first,
                    "last_sequence": denied_range.last,
                }
            )

        delivered_sequences = []
        for allowed_range in allowed_ranges:
            entries = await self._read_allowed_entries(request, allowed_range)
            for event in entries:
                sequence = event.get("sequence")
                if not cursor.should_deliver(sequence):
                    continue
                event["replayed"] = True
                await self.dispatch(event)
                if cursor.has_delivered(sequence):
                    delivered_sequences.append(int(sequence))

        next_sequence = None
        if available_range is not None:
            next_sequence = available_range.last + 1
        await self.send_json(
            {
                "type": "room.replay_complete",
                "request_id": request.request_id,
                "room": request.room,
                "sequences": delivered_sequences,
                "delivered_sequences": delivered_sequences,
                "denied_ranges": [self._range_json(r) for r in denied_ranges],
                "next_sequence": next_sequence,
            }
        )

    replay = handle_replay_request
    replay_history = handle_replay_request
    request_replay = handle_replay_request
    request_history = handle_replay_request
    acknowledge = handle_ack


class AsyncReplayWebsocketConsumer(ReplayWebsocketMixin, AsyncJsonWebsocketConsumer):
    """Async JSON WebSocket consumer with opt-in history replay support."""
