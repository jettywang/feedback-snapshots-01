#  Copyright 2018-Present The CloudEvents Authors
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""Binding-namespace alias for the high-level receiver API."""

from cloudevents.core.receiver import (
    EventReceiver,
    InMemoryReceiver,
    MemoryReceiver,
    MemorySink,
    Receiver,
    ReceiveResult,
    receive,
    receive_amqp,
    receive_http,
)

__all__ = [
    "EventReceiver",
    "InMemoryReceiver",
    "MemoryReceiver",
    "MemorySink",
    "ReceiveResult",
    "Receiver",
    "receive",
    "receive_amqp",
    "receive_http",
]
