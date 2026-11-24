"""In-memory event sink aliases."""

from cloudevents.core.admission import MemorySink
from cloudevents.core.receiver import InMemoryReceiver, MemoryReceiver

__all__ = ["InMemoryReceiver", "MemoryReceiver", "MemorySink"]
