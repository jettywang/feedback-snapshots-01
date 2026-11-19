# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Optional

from .encoder import MessageData
from .errors import EnvelopeMigrationError, UnknownEnvelopeError

#: The version marker used inside an envelope.
ENVELOPE_VERSION_FIELD = "envelope_version"

#: A migration turns a decoded envelope into current-format message fields.
EnvelopeMigration = Callable[[MessageData], MessageData]


@dataclasses.dataclass(frozen=True)
class QuarantinedMessage:
    """A record that could not be handed to an actor and was isolated.

    Parameters:
      queue_name(str): The queue the record was consumed from.
      version(object): The envelope version that could not be handled.
      reason(str): A human-readable explanation of the isolation.
      data(bytes): The raw, undecoded record as it was on the wire.
    """

    queue_name: str
    version: Any
    reason: str
    data: bytes


class EnvelopeMigrator:
    """A bounded migration entry point for versioned message envelopes.

    During a gradual rollout a queue may briefly hold more than one
    JSON task format.  An ``EnvelopeMigrator`` keeps an explicit
    allow-list of the envelope versions a worker understands: every
    registered version is mapped to the current :class:`Message`
    field layout, while records carrying any other version raise
    :class:`UnknownEnvelopeError` so the broker can quarantine them
    instead of crashing the consumer.

    Envelopes are plain JSON objects carrying an
    ``envelope_version`` marker.  Records without that marker are
    treated as the current, unversioned format and pass through
    untouched, so ordinary dramatiq messages keep working.

    Parameters:
      encoder: The encoder used to turn raw records into dicts.
        Defaults to the global dramatiq encoder.
    """

    def __init__(self, *, encoder: Optional[Any] = None) -> None:
        self._migrations: dict[Any, EnvelopeMigration] = {}
        self._encoder = encoder

    def register(self, version: Any, migration: EnvelopeMigration) -> None:
        """Register a migration for an envelope version.

        Registering a version twice replaces its previous migration,
        which makes it easy to tighten a migration in tests.

        Parameters:
          version(object): The value stored under
            ``envelope_version`` that this migration handles.
          migration(Callable): A function taking the decoded envelope
            and returning current-format message fields.
        """
        self._migrations[version] = migration

    def registered_versions(self) -> tuple[Any, ...]:
        """Return the versions this migrator accepts."""
        return tuple(self._migrations)

    def decode(self, data: bytes) -> MessageData:
        """Decode a raw record and migrate it to the current format.

        Parameters:
          data(bytes): The raw record pulled from a queue.

        Raises:
          UnknownEnvelopeError: When the envelope carries a version
            that no registered migration handles.
          EnvelopeMigrationError: When a registered migration fails
            to convert the envelope.
          DecodeError: When the record cannot be decoded at all.

        Returns:
          dict: Message fields suitable for building a
          :class:`Message`.
        """
        from .message import get_encoder

        encoder = self._encoder or get_encoder()
        envelope = encoder.decode(data)

        if not isinstance(envelope, dict):
            raise UnknownEnvelopeError(
                "Envelope is not a JSON object.",
                data,
                version=None,
            )

        if ENVELOPE_VERSION_FIELD not in envelope:
            return envelope

        version = envelope[ENVELOPE_VERSION_FIELD]
        migration = self._migrations.get(version)
        if migration is None:
            raise UnknownEnvelopeError(
                "No migration registered for envelope version %r." % (version,),
                data,
                version,
            )

        try:
            return migration(envelope)
        except UnknownEnvelopeError:
            raise
        except Exception as e:
            raise EnvelopeMigrationError(
                "Failed to migrate envelope version %r." % (version,),
                data,
                version,
                e,
            ) from e
