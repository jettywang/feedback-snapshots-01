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
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

from typing import Optional

from ..errors import DramatiqError


def _describe_task(message, *, scope: Optional[str]) -> str:
    """Build a result-error message containing only task identity.

    Message arguments, keyword arguments and options may contain
    caller data, so they are deliberately left out of the description.
    """
    if not hasattr(message, "message_id"):
        return str(message)

    fields = [
        ("queue_name", getattr(message, "queue_name", None)),
        ("actor_name", getattr(message, "actor_name", None)),
        ("message_id", getattr(message, "message_id", None)),
    ]
    described = ", ".join(f"{name}={value!r}" for name, value in fields)
    if scope is not None:
        described += f", scope={scope!r}"
    return described


class ResultError(DramatiqError):
    """Base class for result errors."""


class _TaskResultError(ResultError):
    def __init__(self, message="", *, scope: Optional[str] = None):  # noqa: B042
        self.scope = scope
        self.queue_name = getattr(message, "queue_name", None)
        self.actor_name = getattr(message, "actor_name", None)
        self.message_id = getattr(message, "message_id", None)
        super().__init__(_describe_task(message, scope=scope))


class ResultTimeout(_TaskResultError):
    """Raised when waiting for a result times out."""


class ResultMissing(_TaskResultError):
    """Raised when a result can't be found."""


class ResultFailure(ResultError):
    """Raised when getting a result from an actor that failed."""

    def __init__(self, message="", orig_exc_type="", orig_exc_msg=""):  # noqa: B042
        super().__init__(message)

        self.orig_exc_type = orig_exc_type
        self.orig_exc_msg = orig_exc_msg
