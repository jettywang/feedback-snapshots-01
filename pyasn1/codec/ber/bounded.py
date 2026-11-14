#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Bounded, forward-only consumption of constructed string payloads.

The general BER decoder in :mod:`pyasn1.codec.ber.decoder` reassembles a
constructed OCTET STRING or BIT STRING into one in-memory object. That is
convenient, but a constructed value can advertise an arbitrarily large
length while only a few header bytes are on the wire, so a security gateway
feeding on an untrusted, possibly non-seekable stream cannot let the framing
alone drive reservation or reassembly.

This module parses the outer TLV itself, never rewinds the stream, and keeps
three independent budgets:

* a total amount of payload that may ever be accumulated
  (:attr:`FragmentBudget.maxTotalSize`),
* a maximum nesting depth of constructed strings
  (:attr:`FragmentBudget.maxNestingDepth`),
* a maximum amount of payload held back (not yet handed to the sink) at any
  one instant (:attr:`FragmentBudget.maxRetainedFragments`).

Logical payload is delivered to a user sink a fragment at a time, and the
sink is told the value is whole only once every framing and padding rule has
been validated. Any failure -- truncation, a wrong inner tag, an exceeded
budget or a raising callback -- raises and never reports completion, and the
stream is left positioned immediately after the last byte that legitimately
belonged to the object being parsed; no byte of the following object is read
ahead.
"""
import sys

from pyasn1 import debug
from pyasn1 import error
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = [
    'FragmentBudget', 'ConsumptionStats', 'FragmentSink',
    'BoundedFragmentDecoder', 'BoundedDecodeError', 'decodeBounded'
]

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_DECODER)

# Only the universal string types are in scope; an implicitly tagged subtype
# changes the tag class and is rejected rather than silently accepted.
_TAG_CLASS_UNIVERSAL = tag.tagClassUniversal

# Universal tag numbers for the two string kinds handled here.
_OCTET_STRING_TAG = univ.OctetString.tagSet[0].tagId
_BIT_STRING_TAG = univ.BitString.tagSet[0].tagId

# Indefinite-length terminator: end-of-contents (0x00 tag, 0x00 length).
_EOC_TAG = 0x00
_INDEFINITE_LENGTH = -1

# Mirror the framing caps enforced by the main BER decoder so a tiny header
# cannot build an unbounded integer here either.
MAX_TAG_OCTETS = 20
MAX_LENGTH_OCTETS = 8

# Default budgets. They are policy values, not protocol limits.
DEFAULT_MAX_TOTAL_SIZE = 1 << 20          # 1 MiB of logical payload
DEFAULT_MAX_NESTING_DEPTH = 100           # mirrors ber.decoder.MAX_NESTING_DEPTH
DEFAULT_MAX_RETAINED_FRAGMENTS = 1 << 16  # 64 KiB held back from the sink


class BoundedDecodeError(error.PyAsn1Error):
    """Raised when bounded fragment consumption cannot complete.

    A subclass of :class:`~pyasn1.error.PyAsn1Error`, so existing handlers
    catching the base pyasn1 exception keep working. Truncation is reported as
    :class:`~pyasn1.error.EndOfStreamError`, itself a ``PyAsn1Error``.
    """


class FragmentBudget(object):
    """The three resource budgets enforced while one object is consumed.

    Parameters
    ----------
    maxTotalSize: :py:class:`int`
        Maximum number of payload octets (OCTET STRING content octets, or
        BIT STRING content including each fragment's initial unused-bits
        octet) that may be accumulated for a single logical value. A declared
        length already past this budget is rejected before its payload is
        read.
    maxNestingDepth: :py:class:`int`
        Maximum number of nested constructed-string encodings.
    maxRetainedFragments: :py:class:`int`
        Maximum number of payload octets that may be retained internally at
        any instant -- the batching buffer for OCTET STRING, plus the single
        pending partial byte of a BIT STRING. Data is flushed to the sink as
        soon as retaining it would cross this bound.
    """

    def __init__(self, maxTotalSize=DEFAULT_MAX_TOTAL_SIZE,
                 maxNestingDepth=DEFAULT_MAX_NESTING_DEPTH,
                 maxRetainedFragments=DEFAULT_MAX_RETAINED_FRAGMENTS):
        if (maxTotalSize < 0 or maxNestingDepth < 0 or
                maxRetainedFragments < 0):
            raise ValueError('budget limits must be non-negative')

        self.maxTotalSize = maxTotalSize
        self.maxNestingDepth = maxNestingDepth
        self.maxRetainedFragments = maxRetainedFragments


class ConsumptionStats(object):
    """Read and retention counters for one completed (or failed) consumption.

    Attributes are plain counters, updated as bytes are pulled from the
    stream. They make the resource behaviour auditable: tests and callers can
    assert on the number of underlying reads, the high-water mark of retained
    payload and how many payload fragments were delivered.
    """

    def __init__(self):
        #: Number of calls made to the underlying stream's ``read``.
        self.readCalls = 0
        #: Total number of bytes pulled from the underlying stream.
        self.bytesRead = 0
        #: Number of payload fragments handed to the sink.
        self.fragmentsDelivered = 0
        #: Running count of payload octets accumulated toward the value.
        self.totalPayloadBytes = 0
        #: High-water mark of payload octets retained internally at once.
        self.peakRetainedBytes = 0

    def __repr__(self):
        return ('ConsumptionStats(readCalls=%d, bytesRead=%d, '
                'fragmentsDelivered=%d, totalPayloadBytes=%d, '
                'peakRetainedBytes=%d)' % (
                    self.readCalls, self.bytesRead,
                    self.fragmentsDelivered, self.totalPayloadBytes,
                    self.peakRetainedBytes))


class FragmentSink(object):
    """Receiver of a logical value delivered a fragment at a time.

    Override :meth:`onFragment` and, optionally, :meth:`onComplete`. Every
    fragment handed to :meth:`onFragment` has already passed the framing and
    budget checks. :meth:`onComplete` is called exactly once, and only after
    the whole value has been validated, so its invocation is the signal that
    the logical value is genuinely complete. A sink that raises aborts the
    decode: the exception propagates and :meth:`onComplete` is never called.
    """

    def onFragment(self, fragment):
        raise NotImplementedError

    def onComplete(self):
        pass


class _BufferedSink(FragmentSink):
    """Reassemble fragments into one value for the convenience wrapper.

    This sink intentionally retains every delivered fragment so it can return
    the complete logical value; its size is therefore bounded by
    :attr:`FragmentBudget.maxTotalSize`, not by the per-instant fragment
    budget. The streaming :class:`BoundedFragmentDecoder` (with a user sink)
    is the entry point that keeps live retention at
    ``maxRetainedFragments``; here we only record the high-water mark.
    """

    def __init__(self):
        self._chunks = []
        self._retained = 0
        self.peakRetainedBytes = 0

    def onFragment(self, fragment):
        if not fragment:
            return
        self._chunks.append(fragment)
        self._retained += len(fragment)
        if self._retained > self.peakRetainedBytes:
            self.peakRetainedBytes = self._retained

    def getvalue(self):
        return b''.join(self._chunks)


class BoundedFragmentDecoder(object):
    """Consume one constructed or primitive string from a forward-only stream.

    The decoder works against any binary stream exposing a blocking
    ``read(n)``; it never calls ``seek`` or ``peek``, so a non-seekable
    source such as a socket wrapper is supported directly.

    Parameters
    ----------
    substrate: :py:class:`io.IOBase`
        Binary stream positioned at the first identifier octet of the value.
    expectedType: :py:class:`type`
        Either :class:`~pyasn1.type.univ.OctetString` or
        :class:`~pyasn1.type.univ.BitString`. Selects the accepted tag and the
        BIT STRING padding rules.
    sink: :class:`FragmentSink`
        Receives validated payload fragments and the completion notification.
    budget: :class:`FragmentBudget`
        Resource budgets. A default budget is used when omitted.
    """

    def __init__(self, substrate, expectedType, sink, budget=None):
        if expectedType is univ.OctetString:
            self._expectedTag = _OCTET_STRING_TAG
            self._isBitString = False
        elif expectedType is univ.BitString:
            self._expectedTag = _BIT_STRING_TAG
            self._isBitString = True
        else:
            raise BoundedDecodeError(
                'Bounded consumption supports OCTET STRING and BIT STRING, '
                'not %s' % (expectedType.__name__,))

        self._substrate = substrate
        self._sink = sink
        self._budget = budget if budget is not None else FragmentBudget()
        self.stats = ConsumptionStats()

        # Full-but-undelivered octets, flushed when the retain budget would
        # be exceeded.
        self._pending = bytearray()
        self._retained = 0

        # BIT STRING only: total number of significant bits accumulated. The
        # current bit offset is derived as ``_bitCount % 8``.
        self._bitCount = 0

    # -- low level reads -------------------------------------------------

    def _readExact(self, count):
        """Read exactly ``count`` bytes without rewinding the stream."""
        if count == 0:
            return b''
        pieces = []
        remaining = count
        while remaining:
            block = self._substrate.read(remaining)
            self.stats.readCalls += 1
            if block is None:
                # A non-blocking source with nothing ready is outside the
                # blocking contract; report it as a truncated stream.
                raise error.EndOfStreamError(
                    'Non-blocking stream returned no data')
            self.stats.bytesRead += len(block)
            if not block:
                raise error.EndOfStreamError(
                    'Truncated BER substrate: expected %d more octets' % (
                        remaining,))
            pieces.append(block)
            remaining -= len(block)
        return b''.join(pieces) if len(pieces) > 1 else pieces[0]

    # -- header parsing ---------------------------------------------------

    def _readTag(self):
        """Return ``(tagClass, isConstructed, tagId)`` for the next TLV."""
        first = self._readExact(1)[0]
        tagClass = first & 0xC0
        constructed = bool(first & 0x20)
        tagId = first & 0x1F

        if tagId != 0x1F:
            return tagClass, constructed, tagId

        # Long-form tag: accumulate under the same octet cap as the main
        # decoder, so a tiny header cannot build an unbounded integer.
        tagId = 0
        octetCount = 0
        while True:
            octet = self._readExact(1)[0]
            octetCount += 1
            if octetCount > MAX_TAG_OCTETS:
                raise BoundedDecodeError(
                    'Tag ID octet count exceeds limit (%d)' % MAX_TAG_OCTETS)
            tagId = (tagId << 7) | (octet & 0x7F)
            if not octet & 0x80:
                return tagClass, constructed, tagId

    def _readLength(self):
        """Return a content length, or -1 for indefinite length."""
        first = self._readExact(1)[0]
        if first < 0x80:
            return first
        if first == 0x80:
            return _INDEFINITE_LENGTH

        size = first & 0x7F
        if size > MAX_LENGTH_OCTETS:
            raise BoundedDecodeError(
                'BER length field size %d exceeds limit (%d)' % (
                    size, MAX_LENGTH_OCTETS))

        length = 0
        for octet in self._readExact(size):
            length = (length << 8) | octet

        if length > sys.maxsize:
            raise BoundedDecodeError(
                'Length %d exceeds maximum readable size %d' % (
                    length, sys.maxsize))
        return length

    # -- budget bookkeeping ----------------------------------------------

    def _charge(self, amount):
        projected = self.stats.totalPayloadBytes + amount
        if projected > self._budget.maxTotalSize:
            raise BoundedDecodeError(
                'Payload total %d exceeds size budget (%d)' % (
                    projected, self._budget.maxTotalSize))
        self.stats.totalPayloadBytes = projected

    def _noteRetention(self):
        if self._retained > self.stats.peakRetainedBytes:
            self.stats.peakRetainedBytes = self._retained

    def _deliver(self, data):
        if data:
            self._sink.onFragment(bytes(data))
            self.stats.fragmentsDelivered += 1

    def _flush(self):
        if self._pending:
            self._deliver(self._pending)
            self._pending = bytearray()
            self._retained = 0
            self._noteRetention()

    def _retain(self, data):
        """Buffer ``data``, flushing whole chunks to stay within the budget.

        A single leaf can be larger than the retain budget, so data is fed in
        pieces: the pending buffer is delivered whenever it reaches
        ``maxRetainedFragments``. With a zero budget every piece is delivered
        immediately and live retention stays at zero.
        """
        limit = self._budget.maxRetainedFragments
        offset = 0
        while offset < len(data):
            if limit:
                room = limit - self._retained
                if room <= 0:
                    self._flush()
                    room = limit
            else:
                room = len(data) - offset
            piece = data[offset:offset + room]
            self._pending.extend(piece)
            self._retained += len(piece)
            offset += len(piece)
            if limit == 0:
                self._flush()
            else:
                self._noteRetention()

    def _flushFullBitBytes(self):
        """Emit every whole byte, keeping only the trailing partial byte."""
        if not self._pending:
            return
        if self._bitCount % 8 == 0:
            self._flush()
            return
        keep = 1
        ready = bytes(self._pending[:-keep])
        self._pending = bytearray(self._pending[-keep:])
        self._retained = len(self._pending)
        self._deliver(ready)
        self._noteRetention()

    # -- payload handling -------------------------------------------------

    def _handleOctetFragment(self, content):
        self._retain(content)

    def _handleBitFragment(self, content):
        # A primitive BIT STRING fragment is one unused-bits octet followed by
        # the content octets.
        unusedBits = content[0]
        if unusedBits > 7:
            raise BoundedDecodeError(
                'Trailing bits overflow %s' % unusedBits)
        payload = content[1:]
        if not payload:
            if unusedBits:
                raise BoundedDecodeError(
                    'Trailing bits overflow %s' % unusedBits)
            # Empty fragment: a legal boundary that contributes no bits.
            return

        if self._bitCount % 8 == 0 and unusedBits == 0:
            # Byte-aligned fast path: whole octets buffer directly.
            self._retain(payload)
            self._bitCount += len(payload) * 8
            if self._retained > self._budget.maxRetainedFragments:
                self._flushFullBitBytes()
            return

        for index, octet in enumerate(payload):
            significantBits = 8
            if index == len(payload) - 1:
                significantBits -= unusedBits
                octet >>= unusedBits

            usedBits = self._bitCount % 8
            if usedBits == 0:
                self._pending.append(octet << (8 - significantBits))
                self._retained += 1
            elif usedBits + significantBits <= 8:
                self._pending[-1] |= octet << (
                    8 - usedBits - significantBits)
            else:
                remainingBits = usedBits + significantBits - 8
                self._pending[-1] |= octet >> remainingBits
                self._pending.append(
                    (octet << (8 - remainingBits)) & 0xff)
                self._retained += 1

            self._bitCount += significantBits
            self._noteRetention()
            if self._retained > self._budget.maxRetainedFragments:
                # Keep only the byte currently being assembled buffered.
                self._flushFullBitBytes()

    def _readPrimitive(self, length):
        if length < 0:
            raise BoundedDecodeError(
                'Primitive encoding must use a definite length')
        # Charge the leaf content extent against the total-size budget before
        # the payload is read, so an oversized leaf never materializes.
        self._charge(length)
        content = self._readExact(length)
        if self._isBitString:
            if length == 0:
                raise BoundedDecodeError('Empty BIT STRING substrate')
            self._handleBitFragment(content)
        else:
            self._handleOctetFragment(content)

    def _readConstructed(self, length, depth):
        if depth > self._budget.maxNestingDepth:
            raise BoundedDecodeError(
                'ASN.1 structure nesting depth exceeds limit (%d)' % (
                    self._budget.maxNestingDepth))

        if length == _INDEFINITE_LENGTH:
            # No declared extent: each leaf is charged as it is encountered.
            while True:
                tagClass, constructed, tagId = self._readTag()
                innerLength = self._readLength()
                if (not constructed and tagId == _EOC_TAG and
                        innerLength == 0):
                    return
                self._verifyInnerTag(tagClass, tagId)
                self._dispatch(constructed, innerLength, depth + 1)
            return

        # A definite frame's length counts nested TLV headers as well as
        # payload, so it cannot be compared directly with the payload-size
        # budget. Instead, the frame bounds iteration (the loop stops exactly
        # at ``frameEnd``) and every leaf charges its own content extent in
        # ``_readPrimitive`` before reading it. An oversized declared length
        # with a truncated body therefore ends in ``EndOfStreamError`` while
        # still inside the frame, and a value whose real payload exceeds the
        # budget is rejected at the offending leaf; in both cases the bytes of
        # the following object are never reached.
        frameEnd = self.stats.bytesRead + length

        while self.stats.bytesRead < frameEnd:
            tagClass, constructed, tagId = self._readTag()
            innerLength = self._readLength()
            self._verifyInnerTag(tagClass, tagId)
            self._dispatch(constructed, innerLength, depth + 1)

        if self.stats.bytesRead != frameEnd:
            # A child over- or under-consumed its declared framing.
            raise BoundedDecodeError(
                'Constructed value framing is inconsistent')

    def _verifyInnerTag(self, tagClass, tagId):
        if tagClass != _TAG_CLASS_UNIVERSAL or tagId != self._expectedTag:
            raise BoundedDecodeError(
                'Unexpected inner tag (class %s, tag %s) while consuming '
                'universal tag %s' % (tagClass, tagId, self._expectedTag))

    def _dispatch(self, constructed, length, depth):
        if constructed:
            self._readConstructed(length, depth)
        else:
            self._readPrimitive(length)

    # -- public entry -----------------------------------------------------

    @property
    def bitCount(self):
        """Number of significant BIT STRING bits consumed (0 for OCTET)."""
        return self._bitCount

    def read(self):
        """Consume exactly one value and notify the sink on success.

        Returns
        -------
        : :class:`ConsumptionStats`
            The counters recorded while consuming this value.

        Raises
        ------
        : :class:`BoundedDecodeError`
            On a framing, tag, padding or budget violation.
        : :class:`~pyasn1.error.EndOfStreamError`
            If the stream ends before the value is complete.
        """
        tagClass, constructed, tagId = self._readTag()
        if tagClass != _TAG_CLASS_UNIVERSAL or tagId != self._expectedTag:
            raise BoundedDecodeError(
                'Expected universal tag %s but found class %s tag %s' % (
                    self._expectedTag, tagClass, tagId))

        length = self._readLength()
        self._dispatch(constructed, length, depth=1)

        # Flush whatever remains; for BIT STRING the trailing byte carries the
        # final, correctly padded, logical bits.
        self._flush()

        if LOG:
            LOG('bounded consumption complete: %r' % (self.stats,))

        self._sink.onComplete()
        return self.stats


def decodeBounded(substrate, expectedType, budget=None):
    """Decode one string from a forward-only stream under explicit budgets.

    This is the convenience wrapper over :class:`BoundedFragmentDecoder` for
    callers that want the reassembled value rather than fragment callbacks. It
    returns a fully validated pyasn1 object only when the logical value is
    complete; truncation, a wrong subtype, an exceeded budget or any other
    failure raises instead, so a partially verified object can never escape.

    Parameters
    ----------
    substrate: :py:class:`io.IOBase`
        Binary stream positioned at the value's first identifier octet. It is
        read forward only and never seeked.
    expectedType: :py:class:`type`
        :class:`~pyasn1.type.univ.OctetString` or
        :class:`~pyasn1.type.univ.BitString`.
    budget: :class:`FragmentBudget`
        Resource budgets (a default budget applies when omitted).

    Returns
    -------
    : :py:class:`tuple`
        A tuple of the decoded pyasn1 object and the
        :class:`ConsumptionStats` describing the reads and retention used.

    Raises
    ------
    : :class:`BoundedDecodeError`, :class:`~pyasn1.error.EndOfStreamError`
        On any failure; in that case no complete object is returned.
    """
    budget = budget if budget is not None else FragmentBudget()
    sink = _BufferedSink()
    consumer = BoundedFragmentDecoder(substrate, expectedType, sink, budget)
    stats = consumer.read()
    raw = sink.getvalue()

    # ``stats`` already carries the engine's live-retention high-water mark,
    # which stays within ``maxRetainedFragments``. The buffered sink holds the
    # full reassembled value by design (its size is bounded by
    # ``maxTotalSize``), so the retention figure reported is the streaming
    # bound, not the final reassembled size.

    if expectedType is univ.BitString:
        internal = univ.BitString.fromOctetString(
            raw, internalFormat=True, padding=(-consumer.bitCount) % 8)
        value = univ.BitString(internal)
    else:
        value = univ.OctetString(raw)

    return value, stats
