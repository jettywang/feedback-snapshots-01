#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Streaming BER encoder for values of unknown total length.

The regular BER ``encode()`` function needs the complete serialisation in
memory before it can emit a single octet: constructed types are framed with
their definite length, which is only known after every component has been
encoded.  This module provides an independent entry point for the opposite
case -- a producer that keeps yielding components, and a consumer that wants
the first octets on the wire before the last component exists.

Only constructed BER indefinite length framing can express that:

    tag | 0x80 | component TLV ... | 0x00 0x00

so every constructed value encoded here is emitted as an indefinite-length
TLV.  Primitive values (INTEGER, OID, ...) keep their definite length, as
X.690 requires; the indefinite form only exists for the constructed encoding.

The entry point is deliberately not wired into ``encode()`` and not inherited
by CER or DER.  ``pyasn1.codec.der.encoder.encodeStream()`` raises: DER is a
canonical encoding, its constructed values must carry a definite length, and
nothing here may silently fall back to BER indefinite framing.

Termination contract
--------------------

Each call to :func:`encodeStream` returns an iterator of octet chunks.  The
iterator yields the indefinite-length header, then the components, and the
end-of-contents octets only after the complete value has been produced
successfully.  It follows that:

* If a component iterator raises, if a type constraint fails, or if the
  iterator is closed before exhaustion, the end-of-contents octets are never
  emitted.  The exception propagates; this module never converts a failed
  encode into what looks like a complete value.
* A consumer that stops reading is responsible for terminating the transport.
  A prefix of a BER TLV has no self-delimiting "abort" representation: the
  peer cannot be told that the value ended there.  Do not append octets to
  make the prefix look complete; close or reset the connection instead.
* :attr:`StreamingEncoder.complete` tells whether the end-of-contents octets
  were produced.  ``False`` after the iterator finished or raised means the
  serialisation is a prefix and the connection must not be reused.

String fragments
----------------

An OCTET STRING (and every character string type) whose value is supplied as
an iterable of ``bytes`` or ``str`` fragments is emitted as a constructed
indefinite-length string:

    <tag> 0x80 | fragment TLV ... | 0x00 0x00

Each fragment becomes an ordinary primitive string TLV.  A fragment is always
encoded as a whole -- multi-octet characters and stateful encodings must not
be split across fragments.  ``maxChunkSize`` splits each produced fragment
further, on character boundaries for ``str`` values.

SequenceOf nesting
------------------

A ``SequenceOf``/``SetOf`` may be given as a pyasn1 value object or as a
plain iterable (including a generator).  Plain iterables are consumed lazily,
one component at a time, and are never materialised first.  The nesting depth
sets the recursion depth; it does not scale the number of octets held in
memory, which is bounded by one encoded component per nesting level.
"""

from pyasn1 import debug
from pyasn1 import error
from pyasn1.codec.ber import encoder
from pyasn1.type import base
from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = ['StreamingEncoder', 'encodeStream', 'encodeStreamTo',
           'StreamingEncodeError', 'StreamingAbortError', 'ShortWriteError']

LOG = debug.registerLoggee(__name__, flags=debug.DEBUG_ENCODER)

noValue = base.noValue

EOC = b'\x00\x00'


class StreamingEncodeError(error.PyAsn1Error):
    """Streaming encode failed after output had been produced.

    The exception carries the number of octets produced so far in
    :attr:`octetsEmitted` and the original failure in :attr:`cause`.

    The exception never means "the value ended here".  The transport carrying
    the output has to be closed or reset by the caller.
    """

    def __init__(self, message, octetsEmitted=0, cause=None):
        error.PyAsn1Error.__init__(self, message)
        self.octetsEmitted = octetsEmitted
        self.__cause = cause

    @property
    def cause(self):
        return self.__cause


class StreamingAbortError(StreamingEncodeError):
    """The consumer abandoned a streaming encode before it completed.

    Raised by the next :meth:`StreamingEncoder.__next__` call after
    :meth:`StreamingEncoder.abort` (or a context-manager exit that had to
    abandon the value).  Closing the iterator never emits the end-of-contents
    octets.
    """


def _isIterable(value):
    try:
        iter(value)

    except TypeError:
        return False

    return True


class StreamingEncoder(object):
    """Encode one ASN.1 value into a stream of BER indefinite-length octets.

    The instance is an iterator of :class:`bytes` chunks.  It is single-use:
    the encoder tracks how many octets were emitted and whether the value was
    completed, and those counters are not meaningful after a second pass.

    Parameters
    ----------
    value: a pyasn1 value object or a plain Python value
        The value to encode.  With *asn1Spec*, plain values are interpreted
        through that schema.  ``SequenceOf``/``SetOf`` values may be any
        iterable; string values inside a string schema may be any iterable of
        fragments.

    asn1Spec: :py:class:`~pyasn1.type.base.PyAsn1Item`
        Schema to guide the encoding.  Required for plain Python values and
        for IMPLICIT tagged values, as with the non-streaming encoder.

    Keyword Args
    ------------
    maxChunkSize: :py:class:`int`
        Maximum number of payload octets in one emitted string fragment
        (0 means no further splitting beyond the fragment the caller gave).

    ``defMode`` is rejected: this entry point exists for indefinite-length
    output only.  Use :func:`pyasn1.codec.ber.encoder.encode` for definite
    length encoding.

    Attributes
    ----------
    octetsEmitted: :py:class:`int`
        Octets produced so far.  For an encoder given an iterable of
        components this grows while that iterable is consumed, which makes it
        usable as a progress counter.

    complete: :py:class:`bool`
        :obj:`True` only after the end-of-contents octets were produced.
        When the iterator finishes (or raises) with this still :obj:`False`,
        the output is an unterminated prefix and the caller must terminate
        the transport.

    aborted: :py:class:`bool`
        :obj:`True` once :meth:`abort` was called or the iterator was closed
        before completion.

    Examples
    --------
    .. code-block:: python

        from pyasn1.codec.ber.streaming_encoder import encodeStream

        encoderInstance = encodeStream(
            (Integer(i) for i in range(1000000)),
            asn1Spec=SequenceOf(componentType=Integer()))

        with encoderInstance:
            for chunk in encoderInstance:
                transport.write(chunk)

        # Leaving the ``with`` block after a failure or a ``break`` does not
        # complete the value; the transport must be closed, not patched.
    """

    def __init__(self, value, asn1Spec=None, **options):
        if 'defMode' in options:
            raise error.PyAsn1Error(
                'Streaming encode always produces indefinite-length BER; '
                'use encoder.encode() for definite-length output')

        self._value = value
        self._asn1Spec = asn1Spec
        self._maxChunkSize = options.get('maxChunkSize', 0)

        self._iterator = None
        self._octetsEmitted = 0
        self._complete = False
        self._aborted = False
        self._closed = False

        size = self._maxChunkSize
        if size is not None and (not isinstance(size, int) or size < 0):
            raise error.PyAsn1Error(
                'maxChunkSize must be a non-negative integer, got %r' % (size,))

    def __iter__(self):
        return self

    def __next__(self):
        if self._aborted:
            raise StreamingAbortError(
                'Streaming encode was aborted before completion; the output '
                'is an unterminated prefix and the transport must be '
                'terminated by the caller',
                octetsEmitted=self._octetsEmitted)

        if self._closed:
            raise StopIteration

        if self._iterator is None:
            self._iterator = self._run()

        try:
            chunk = next(self._iterator)

        except StopIteration:
            self._closed = True
            if not self._complete:
                self._aborted = True
            raise

        except BaseException:
            self._closed = True
            if not self._complete:
                self._aborted = True
            raise

        self._octetsEmitted += len(chunk)
        return chunk

    next = __next__

    @property
    def octetsEmitted(self):
        return self._octetsEmitted

    @property
    def complete(self):
        return self._complete

    @property
    def aborted(self):
        return self._aborted

    def abort(self):
        """Abandon the encode and mark the output as an unterminated prefix.

        This never emits the end-of-contents octets.  The caller owns the
        transport and has to close or reset it; no bytes returned before this
        call constitute a complete BER value.
        """
        if self._complete:
            return

        self._aborted = True
        self._closed = True

        iterator = self._iterator
        self._iterator = None

        if iterator is not None:
            try:
                iterator.close()

            except Exception:
                # A failing producer cleanup must not turn an abort into an
                # error whose only sensible handling is the same abort.
                pass

    def close(self):
        """Alias for :meth:`abort`, for use as a context manager exit."""

        if not self._complete:
            self.abort()

        else:
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, excType, excValue, traceback):
        if excType is not None:
            if not self._complete:
                self.abort()

        elif not self._complete:
            self.abort()

        else:
            self._closed = True

        return False

    @staticmethod
    def _wrapFailure(exc, octetsEmitted):
        if isinstance(exc, StreamingEncodeError):
            return exc

        if isinstance(exc, error.PyAsn1Error):
            message = str(exc)

        elif isinstance(exc, Exception):
            message = '%s: %s' % (exc.__class__.__name__, exc)

        else:
            return exc

        return StreamingEncodeError(
            'Streaming encode failed after %d octets: %s; '
            'the output is an unterminated prefix and the transport must be '
            'terminated by the caller' % (octetsEmitted, message),
            octetsEmitted=octetsEmitted, cause=exc)

    def _run(self):
        octets = 0

        try:
            for chunk in self._encode(
                    self._value, self._asn1Spec, 0, final=True):
                if not chunk:
                    # an untagged empty ANY has no octets at all; never hand
                    # an empty chunk to a write-oriented consumer
                    continue

                octets += len(chunk)
                yield chunk

        except (GeneratorExit, StreamingEncodeError):
            raise

        except Exception as exc:
            if octets == 0:
                raise

            wrapped = self._wrapFailure(exc, octets)
            if wrapped is exc:
                raise
            raise wrapped from exc

        # Every branch marked completion before its last chunk.  This covers
        # a value that legitimately produces no octets at all.
        self._complete = True

    @staticmethod
    def _encodeTag(singleTag, isConstructed):
        return encoder.AbstractItemEncoder.encodeTag(
            encoder.AbstractItemEncoder(), singleTag, isConstructed)

    @staticmethod
    def _encodeLength(length):
        return encoder.AbstractItemEncoder.encodeLength(
            encoder.AbstractItemEncoder(), length, True)

    def _tags(self, value, asn1Spec):
        if asn1Spec is not None:
            return asn1Spec.tagSet

        return value.tagSet

    def _typeId(self, value, asn1Spec):
        if asn1Spec is not None:
            return asn1Spec.typeId

        try:
            return value.typeId

        except AttributeError:
            raise error.PyAsn1Error(
                'Value %r is not ASN.1 type instance '
                'and "asn1Spec" not given' % (value,))

    def _concreteEncoder(self, value, asn1Spec):
        typeId = self._typeId(value, asn1Spec)

        try:
            return encoder.TYPE_MAP[typeId]

        except KeyError:
            tagSet = self._tags(value, asn1Spec)
            baseTagSet = tag.TagSet(tagSet.baseTag, tagSet.baseTag)

            try:
                return encoder.TAG_MAP[baseTagSet]

            except KeyError:
                raise error.PyAsn1Error(
                    'No encoder for %r (%s)' % (value, tagSet))

    def _isFragmentString(self, value, concrete):
        if not isinstance(concrete, encoder.OctetStringEncoder):
            return False

        if isinstance(concrete, encoder.AnyEncoder):
            return False

        if isinstance(value, base.Asn1Item):
            return False

        if isinstance(value, (bytes, bytearray, memoryview, str)):
            # a single string value is only streamed when the caller asked
            # for bounded chunks; otherwise it is a plain primitive value
            return bool(self._maxChunkSize)

        if isinstance(value, (list, tuple)):
            if not value:
                return False

            return all(isinstance(fragment, (bytes, bytearray, memoryview, str))
                       for fragment in value)

        return _isIterable(value)

    def _encode(self, value, asn1Spec, depth=0, final=False):
        """Yield the complete encoding of one item.

        ``final`` marks the top-level item: the branch that emits the last
        octet of the value must set :attr:`complete` just before yielding it,
        so that a consumer which stops on the final EOC sees an accurate
        ``complete``.  Failures never reach that assignment.
        """
        concrete = self._concreteEncoder(value, asn1Spec)

        if isinstance(concrete, encoder.AnyEncoder):
            for chunk in self._encodeAny(value, asn1Spec, final):
                yield chunk

        elif self._isFragmentString(value, concrete):
            for chunk in self._encodeStringFragments(value, asn1Spec, final):
                yield chunk

        elif isinstance(concrete, encoder.SequenceOfEncoder):
            for chunk in self._encodeSequenceOf(
                    value, asn1Spec, depth, final):
                yield chunk

        elif isinstance(concrete, encoder.SequenceEncoder):
            for chunk in self._encodeSequence(value, asn1Spec, depth, final):
                yield chunk

        elif isinstance(concrete, encoder.ChoiceEncoder):
            for chunk in self._encodeChoice(value, asn1Spec, depth, final):
                yield chunk

        else:
            for chunk in self._encodeScalar(value, asn1Spec, final):
                yield chunk

    def _validateScalar(self, value, asn1Spec):
        if asn1Spec is None or isinstance(value, base.Asn1Item):
            return value

        if not isinstance(asn1Spec, base.SimpleAsn1Type):
            return value

        if hasattr(value, '__next__'):
            # container-building generators are dispatched elsewhere and
            # must not be probed by a scalar schema
            return value

        return asn1Spec.clone(value)

    def _encodeScalar(self, value, asn1Spec, final=False):
        # A primitive value is complete in memory, so the regular encoder
        # produces the exact same octets here: definite length, explicit
        # tags wrapped with a definite length as X.690 requires.  Only the
        # value-and-schema constraint check has to be done separately, since
        # the regular encoder does not validate plain Python values.
        validated = self._validateScalar(value, asn1Spec)

        substrate = encoder.encode(validated, asn1Spec=asn1Spec)

        self._markIfFinal(final)

        yield substrate

    def _splitFragment(self, fragment, asn1Spec):
        """Yield payload octets of one logical fragment, at most *maxChunkSize* each.

        ``fragment`` is already in the type's logical domain (``str`` for
        character strings, ``bytes`` for OCTET STRING).  Splitting is lazy:
        a large fragment is not copied into a list of pieces before the first
        piece is emitted, and character strings are split on character
        boundaries, never inside a multi-octet character.
        """
        size = self._maxChunkSize

        if isinstance(fragment, str):
            encoding = 'iso-8859-1'

            if asn1Spec is not None and \
                    isinstance(asn1Spec, char.AbstractCharacterString):
                encoding = asn1Spec.encoding

            encoded = fragment.encode(encoding)

            if not size or len(encoded) <= size:
                yield encoded
                return

            if isinstance(asn1Spec, char.AbstractCharacterString):
                current = []
                currentSize = 0

                for character in fragment:
                    charSize = len(character.encode(encoding))
                    if current and currentSize + charSize > size:
                        yield ''.join(current).encode(encoding)
                        current = [character]
                        currentSize = charSize

                    else:
                        current.append(character)
                        currentSize += charSize

                if current:
                    yield ''.join(current).encode(encoding)

                return

            for pos in range(0, len(encoded), size):
                yield encoded[pos:pos + size]

            return

        view = memoryview(fragment)

        if not size or len(view) <= size:
            if isinstance(fragment, bytes):
                # hand the caller's own object through, no copy
                yield fragment

            else:
                yield bytes(view)

            return

        for pos in range(0, len(view), size):
            yield bytes(view[pos:pos + size])

    @staticmethod
    def _characterText(fragment, asn1Spec):
        if isinstance(fragment, str):
            return fragment

        if isinstance(fragment, base.Asn1Item):
            return str(fragment)

        return asn1Spec.prettyIn(fragment)

    @staticmethod
    def _logicalValue(fragment, asn1Spec):
        """Return the fragment in the type's own logical-value domain.

        For character strings that is ``str`` (so ``len()`` counts
        characters, which is what a size constraint means); for OCTET STRING
        it is ``bytes``.
        """
        if isinstance(asn1Spec, char.AbstractCharacterString):
            return StreamingEncoder._characterText(fragment, asn1Spec)

        if isinstance(fragment, (bytes, bytearray, memoryview)):
            return bytes(fragment)

        if isinstance(fragment, base.Asn1Item):
            return fragment.asOctets()

        return asn1Spec.prettyIn(fragment)

    @staticmethod
    def _validateFragment(fragment, asn1Spec):
        """Validate one fragment against the string schema.

        Constraints that apply to a single fragment (permitted alphabet,
        element value, ...) are checked here.  Whole-string size constraints
        span fragments and are checked by :meth:`_encodeStringFragments`
        after every fragment has been seen, so they are skipped here.
        """
        if isinstance(fragment, base.Asn1Item):
            # An ASN.1 value object carries its own validation; mirror the
            # regular encoders and do not re-clone it.
            return

        if isinstance(fragment, str):
            converted = asn1Spec.prettyIn(fragment)

        elif isinstance(fragment, (bytes, bytearray, memoryview)):
            converted = asn1Spec.prettyIn(bytes(fragment))

        else:
            raise error.PyAsn1Error(
                'String fragment %r is not a bytes or str object' % (fragment,))

        for item in StreamingEncoder._sizeConstraints(
                getattr(asn1Spec, 'subtypeSpec', None)):
            if isinstance(item, constraint.ValueSizeConstraint):
                continue

            item(converted)

    @staticmethod
    def _sizeConstraints(subtypeSpec):
        """Yield every constraint reachable through intersections."""
        if not subtypeSpec:
            return

        pending = [subtypeSpec]

        while pending:
            item = pending.pop()

            if isinstance(item, constraint.ConstraintsIntersection):
                pending.extend(item)

            else:
                yield item

    def _encodeStringFragments(self, value, asn1Spec, final=False):
        if asn1Spec is None:
            raise error.PyAsn1Error(
                'String fragments require an ASN.1 schema to guide them')

        tagSet = asn1Spec.tagSet
        superTags = tagSet.superTags

        if not superTags:
            raise error.PyAsn1Error(
                'String fragments require a tagged ASN.1 string type')

        effectiveTag = superTags[0]
        naturalTagSet = type(asn1Spec).tagSet

        if naturalTagSet:
            fragmentTag = naturalTagSet.superTags[-1]

        else:
            fragmentTag = effectiveTag

        outerTag = tag.Tag(effectiveTag.tagClass,
                           tag.tagFormatConstructed, effectiveTag.tagId)

        explicitTags = superTags[1:]

        for singleTag in reversed(explicitTags):
            yield bytes(self._encodeTag(singleTag, True)) + b'\x80'

        yield bytes(self._encodeTag(outerTag, True)) + b'\x80'

        lower, upper = self._sizeBounds(getattr(asn1Spec, 'subtypeSpec', None))
        totalSize = 0

        if isinstance(value, (bytes, bytearray, memoryview, str)):
            fragments = (value,)

        else:
            fragments = value

        for fragment in fragments:
            self._validateFragment(fragment, asn1Spec)

            logicalValue = self._logicalValue(fragment, asn1Spec)
            fragmentSize = len(logicalValue)

            if upper is not None and totalSize + fragmentSize > upper:
                raise error.PyAsn1Error(
                    'String value exceeds size constraint (max %s)' % upper)

            # each fragment is encoded as one or more primitive TLVs; the
            # logical value is never retained after its last piece
            for piece in self._splitFragment(logicalValue, asn1Spec):
                # header and payload are emitted separately so that a large
                # fragment is never copied into a single joined buffer
                yield bytes(self._encodeTag(fragmentTag, False))
                yield bytes(self._encodeLength(len(piece)))
                yield piece

            totalSize += fragmentSize

        if lower is not None and totalSize < lower:
            raise error.PyAsn1Error(
                'String value violates size constraint (min %s)' % lower)

        for chunk in self._emitEocs(1 + len(explicitTags), final):
            yield chunk

    def _markIfFinal(self, final):
        if final:
            self._complete = True

    def _emitEocs(self, count, final):
        """Yield *count* end-of-contents markers, innermost first.

        Completion is marked just before the outermost (last) marker, so a
        consumer that stops on that chunk sees a complete value while one
        that stops on an inner marker does not.
        """
        for idx in range(count):
            if idx == count - 1:
                self._markIfFinal(final)

            yield EOC

    def _encodeAny(self, value, asn1Spec, final=False):
        if asn1Spec is None:
            substrate = value.asOctets()

        elif isinstance(value, (bytes, bytearray, memoryview)):
            substrate = bytes(value)

        else:
            substrate = asn1Spec.clone(value).asOctets()

        tagSet = self._tags(value, asn1Spec)

        if not tagSet:
            self._markIfFinal(final)

            yield substrate
            return

        # A tagged ANY is a constructed indefinite-length wrapper around the
        # already encoded blob, which is what the regular encoder emits for
        # defMode=False.
        for chunk in self._framedConstructed(
                tagSet, iter((substrate,)), final):
            yield chunk

    @staticmethod
    def _sizeBounds(subtypeSpec):
        lower = None
        upper = None

        if not subtypeSpec:
            return lower, upper

        pending = [subtypeSpec]

        while pending:
            item = pending.pop()

            if isinstance(item, constraint.ConstraintsIntersection):
                pending.extend(item)

                continue

            if not isinstance(item, constraint.ValueSizeConstraint):
                continue

            start = getattr(item, 'start', None)
            stop = getattr(item, 'stop', None)

            if start is not None:
                lower = start if lower is None else max(lower, start)

            if stop is not None:
                upper = stop if upper is None else min(upper, stop)

        return lower, upper

    def _sequenceOfComponents(self, value, asn1Spec):
        if asn1Spec is not None:
            containerSpec = asn1Spec
            componentSpec = containerSpec.componentType

            if isinstance(value, base.ConstructedAsn1Type):
                inconsistency = value.isInconsistent
                if inconsistency:
                    raise error.PyAsn1Error(
                        'ASN.1 object %s is inconsistent: %s' % (
                            value.__class__.__name__, inconsistency))

        else:
            containerSpec = value
            componentSpec = value.componentType

        lower, upper = self._sizeBounds(
            getattr(containerSpec, 'subtypeSpec', None))

        if isinstance(value, univ.SequenceOfAndSetOfBase):
            count = len(value)

            if lower is not None and count < lower or \
                    upper is not None and count > upper:
                raise error.PyAsn1Error(
                    'ASN.1 object %s violates size constraint %s..%s' % (
                        value.__class__.__name__, lower, upper))

            for idx in range(count):
                component = value.getComponentByPosition(
                    idx, instantiate=False)

                if component is noValue:
                    raise error.PyAsn1Error(
                        'Component %d of %r is not present' % (idx, value))

                yield component, componentSpec

            return

        if not _isIterable(value):
            raise error.PyAsn1Error(
                'SequenceOf value %r is not iterable' % (value,))

        count = 0

        for component in value:
            count += 1

            if upper is not None and count > upper:
                raise error.PyAsn1Error(
                    'SequenceOf value exceeds size constraint (max %s)' % upper)

            yield component, componentSpec

        if lower is not None and count < lower:
            raise error.PyAsn1Error(
                'SequenceOf value violates size constraint (min %s)' % lower)

    def _encodeSequenceOf(self, value, asn1Spec, depth, final=False):
        if isinstance(value, univ.SequenceOfAndSetOfBase):
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.PyAsn1Error(
                    'ASN.1 object %s is inconsistent: %s' % (
                        value.__class__.__name__, inconsistency))

            lower, upper = self._sizeBounds(
                getattr(value, 'subtypeSpec', None))
            count = len(value)

            if lower is not None and count < lower or \
                    upper is not None and count > upper:
                raise error.PyAsn1Error(
                    'ASN.1 object %s violates size constraint %s..%s' % (
                        value.__class__.__name__, lower, upper))

        tagSet = self._tags(value, asn1Spec)

        payload = self._sequenceOfPayload(value, asn1Spec, depth)

        if not tagSet:
            for chunk in payload:
                yield chunk

            self._markIfFinal(final)
            return

        for chunk in self._framedConstructed(tagSet, payload, final):
            yield chunk

    def _sequenceOfPayload(self, value, asn1Spec, depth):
        for component, componentSpec in self._sequenceOfComponents(
                value, asn1Spec):
            for chunk in self._encode(component, componentSpec, depth + 1):
                yield chunk

    def _encodeSequence(self, value, asn1Spec, depth, final=False):
        if asn1Spec is None:
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.PyAsn1Error(
                    'ASN.1 object %s is inconsistent: %s' % (
                        value.__class__.__name__, inconsistency))

        elif isinstance(value, base.ConstructedAsn1Type):
            inconsistency = value.isInconsistent
            if inconsistency:
                raise error.PyAsn1Error(
                    'ASN.1 object %s is inconsistent: %s' % (
                        value.__class__.__name__, inconsistency))

        # Structural problems must surface before the header, not after it:
        # they do not depend on a producer and there is nothing to stream yet.
        self._checkSequenceComplete(value, asn1Spec)

        tagSet = self._tags(value, asn1Spec)
        payload = self._sequencePayload(value, asn1Spec, depth)

        if not tagSet:
            for chunk in payload:
                yield chunk

            self._markIfFinal(final)
            return

        for chunk in self._framedConstructed(tagSet, payload, final):
            yield chunk

    @staticmethod
    def _checkSequenceComplete(value, asn1Spec):
        if asn1Spec is None:
            if not isinstance(value, base.ConstructedAsn1Type) or \
                    not value.componentType:
                return

            namedTypes = value.componentType

        else:
            namedTypes = asn1Spec.componentType

        if isinstance(value, base.ConstructedAsn1Type) and \
                not isinstance(value, univ.Choice):
            for namedType in namedTypes.namedTypes:
                if namedType.isOptional or namedType.isDefaulted:
                    continue

                component = value.getComponentByName(
                    namedType.name, instantiate=False)

                if component is noValue:
                    raise error.PyAsn1Error(
                        'Mandatory component "%s" of %r is not present' % (
                            namedType.name, value))

            return

        if isinstance(value, dict):
            for namedType in namedTypes.namedTypes:
                if namedType.isOptional or namedType.isDefaulted:
                    continue

                if namedType.name not in value:
                    raise error.PyAsn1Error(
                        'Component name "%s" not found in %r' % (
                            namedType.name, value))

    def _openTypeComponent(self, component, namedType, valuePath):
        """Encode an open type component.

        Open type components are complete blobs (either an already encoded
        TLV or a container of them), so the regular encoder is used; there is
        nothing left to stream.  The semantics mirror SequenceEncoder.
        """
        wrapType = namedType.asn1Object

        if wrapType.typeId in (univ.SetOf.typeId,
                               univ.SequenceOf.typeId):
            options = dict(defMode=False, wrapType=wrapType.componentType)

            if valuePath:
                return encoder.encode(component, **options)

            return encoder.encode(component, asn1Spec=wrapType, **options)

        if valuePath:
            chunk = encoder.encode(component, defMode=False)

        else:
            chunk = encoder.encode(component, asn1Spec=wrapType, defMode=False)

        if wrapType.isSameTypeWith(component):
            return chunk

        return encoder.encode(chunk, asn1Spec=wrapType, defMode=False)

    def _sequencePayload(self, value, asn1Spec, depth):
        if asn1Spec is None:
            namedTypes = value.componentType
            containerSpec = value

            if not namedTypes:
                namedTypes = None

            for idx in range(value._componentTypeLen or
                             len(value._dynamicNames)):
                component = value.getComponentByPosition(
                    idx, instantiate=False)

                namedType = namedTypes[idx] if namedTypes else None

                if component is noValue:
                    if namedType is None or namedType.isOptional or \
                            namedType.isDefaulted:
                        continue

                    raise error.PyAsn1Error(
                        'Mandatory component %r of %r is not present' % (
                            namedType, value))

                if namedType is not None:
                    if namedType.isDefaulted and \
                            component == namedType.asn1Object:
                        continue

                    if namedType.isOptional and not component.isValue:
                        continue

                    if namedType.openType:
                        yield self._openTypeComponent(
                            component, namedType, containerSpec)
                        continue

                    componentSpec = namedType.asn1Object

                else:
                    componentSpec = None

                for chunk in self._encode(component, componentSpec, depth + 1):
                    yield chunk

            return

        # plain Python mapping + schema, or a pyasn1 value object with a
        # schema.  A pyasn1 value is read by position with instantiate=False
        # so that absent OPTIONAL/DEFAULT components are not materialised.
        containerIsValue = isinstance(value, base.ConstructedAsn1Type)

        for idx, namedType in enumerate(
                asn1Spec.componentType.namedTypes):
            name = namedType.name

            if containerIsValue:
                component = value.getComponentByPosition(
                    idx, instantiate=False)

                if component is noValue:
                    if namedType.isOptional or namedType.isDefaulted:
                        continue

                    raise error.PyAsn1Error(
                        'Mandatory component "%s" of %r is not present' % (
                            name, value))

                if namedType.isDefaulted and \
                        component == namedType.asn1Object:
                    continue

                if namedType.isOptional and not component.isValue:
                    continue

            else:
                try:
                    component = value[name]

                except (KeyError, TypeError):
                    if namedType.isOptional or namedType.isDefaulted:
                        continue

                    raise error.PyAsn1Error(
                        'Component name "%s" not found in %r' % (name, value))

                if namedType.isOptional and name not in value:
                    continue

                if namedType.isDefaulted and \
                        component == namedType.asn1Object:
                    continue

            if namedType.openType:
                yield self._openTypeComponent(
                    component, namedType, asn1Spec)
                continue

            componentSpec = namedType.asn1Object

            for chunk in self._encode(component, componentSpec, depth + 1):
                yield chunk

    def _encodeChoice(self, value, asn1Spec, depth, final=False):
        if asn1Spec is None:
            component = value.getComponent()
            componentSpec = None

        else:
            names = [namedType.name
                     for namedType in asn1Spec.componentType.namedTypes
                     if namedType.name in value]

            if len(names) != 1:
                raise error.PyAsn1Error(
                    '%s components for Choice at %r' % (
                        len(names) and 'Multiple ' or 'None ', value))

            name = names[0]
            component = value[name]
            componentSpec = asn1Spec[name]

        tagSet = self._tags(value, asn1Spec)
        payload = self._encode(
            component, componentSpec, depth + 1, final=not tagSet and final)

        if not tagSet:
            for chunk in payload:
                yield chunk

            return

        for chunk in self._framedConstructed(tagSet, payload, final):
            yield chunk

    def _framedConstructed(self, tagSet, payload, final=False):
        superTags = tagSet.superTags

        if not superTags:
            for chunk in payload:
                yield chunk

            return

        explicitTags = superTags[1:]

        for singleTag in reversed(explicitTags):
            yield bytes(self._encodeTag(singleTag, True)) + b'\x80'

        yield bytes(self._encodeTag(superTags[0], True)) + b'\x80'

        for chunk in payload:
            yield chunk

        for chunk in self._emitEocs(1 + len(explicitTags), final):
            yield chunk


def encodeStream(value, asn1Spec=None, **options):
    """Create an iterator of BER indefinite-length octets for *value*.

    This is the streaming counterpart of
    :func:`~pyasn1.codec.ber.encoder.encode`.  It never consumes an iterable
    value in advance: ``SequenceOf``/``SetOf`` values may be generators, and
    string values may be iterables of fragments.  Each octet chunk is produced
    as soon as the corresponding component has been encoded.

    Parameters
    ----------
    value: a pyasn1 value object or a plain Python value
        Value to encode.

    asn1Spec: :py:class:`~pyasn1.type.base.PyAsn1Item`
        Schema to guide encoding of plain Python values.

    Keyword Args
    ------------
    maxChunkSize: :py:class:`int`
        Maximum number of payload octets in one emitted string fragment.

    Returns
    -------
    : :class:`StreamingEncoder`
        Iterator of :class:`bytes` chunks.  The end-of-contents octets are
        emitted only when the value was produced completely; if a component
        iterator raises or a constraint fails, the exception propagates and no
        terminator is emitted.

    Raises
    ------
    : :py:class:`~pyasn1.error.PyAsn1Error`
        On invalid arguments.  Failures after output started are raised as
        :class:`StreamingEncodeError`, which records the partial output count.

    Examples
    --------
    Encode a SEQUENCE OF produced by a generator:

    .. code-block:: pycon

        >>> chunks = encodeStream(
        ...     (Integer(i) for i in range(3)),
        ...     asn1Spec=SequenceOf(componentType=Integer()))
        >>> b''.join(chunks)
        b'0\\x80\\x02\\x01\\x00\\x02\\x01\\x01\\x02\\x01\\x02\\x00\\x00'

    Encode a string from fragments:

    .. code-block:: pycon

        >>> chunks = encodeStream(
        ...     [b'quick ', b'brown'],
        ...     asn1Spec=OctetString())
        >>> b''.join(chunks)
        b'$\\x80\\x04\\x06quick \\x04\\x05brown\\x00\\x00'
    """
    return StreamingEncoder(value, asn1Spec=asn1Spec, **options)


class ShortWriteError(StreamingEncodeError):
    """A sink accepted fewer octets than it was offered.

    ``write()`` may consume less than the whole chunk (a non-blocking socket
    or an intentionally short test double).  The unconsumed remainder has not
    been transmitted; the encoder cannot retry it, so this is a hard failure
    and the caller owns the transport termination.
    """


def encodeStreamTo(sink, value, asn1Spec=None, **options):
    """Push BER indefinite-length octets to *sink* as they are produced.

    This is the same encoding as :func:`encodeStream`, with the iterator
    consumed against an object exposing ``write(bytes) -> int``.  A ``write``
    returning fewer octets than offered is treated as a failure (see
    :class:`ShortWriteError`); a ``write`` raising propagates the exception
    with the same termination contract as the iterator form.

    Parameters
    ----------
    sink: object with a ``write`` method
        Receives the octets in production order.

    value, asn1Spec: see :func:`encodeStream`.

    Returns
    -------
    : :class:`int`
        Number of octets written.

    Raises
    ------
    : :class:`StreamingEncodeError`
        If any failure occurs after output started; no end-of-contents
        octets are emitted in that case.
    """
    encoderInstance = StreamingEncoder(
        value, asn1Spec=asn1Spec, **options)

    write = getattr(sink, 'write', None)

    if write is None:
        raise error.PyAsn1Error(
            'Sink %r has no write() method' % (sink,))

    written = 0

    try:
        for chunk in encoderInstance:
            accepted = write(chunk)

            if accepted is None:
                accepted = len(chunk)

            if accepted != len(chunk):
                raise ShortWriteError(
                    'Sink accepted %r octets out of %r offered; the value is '
                    'incomplete and the transport must be terminated by the '
                    'caller' % (accepted, len(chunk)),
                    octetsEmitted=written)

            written += accepted

    except GeneratorExit:
        encoderInstance.abort()
        raise

    except BaseException as exc:
        if not encoderInstance.complete:
            encoderInstance.abort()

        # A raising write() may have consumed part or all of the chunk, so
        # the encoder cannot state that nothing reached the transport; the
        # caller owns termination either way.
        if not isinstance(exc, StreamingEncodeError):
            raise StreamingEncodeError(
                'Streaming encode to sink failed after %d octets: %s; '
                'the output is an unterminated prefix and the transport '
                'must be terminated by the caller' % (written, exc),
                octetsEmitted=written, cause=exc) from exc

        raise

    return written
