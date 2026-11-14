from collections import namedtuple

from noise.encoding import Decoder, encode_bytes, encode_bytes_list
from noise.exceptions import NoiseNegotiationError


_MAGIC = b'NOISE-NEGOTIATION-RECORD\x00\x01'


def _normalise_bytes(value, field_name):
    if isinstance(value, str):
        try:
            return value.encode('ascii')
        except UnicodeEncodeError:
            raise NoiseNegotiationError('{} must contain ASCII characters only'.format(field_name))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise NoiseNegotiationError('{} must be bytes or an ASCII string'.format(field_name))


def _normalise_offers(offers, field_name):
    if isinstance(offers, (str, bytes, bytearray, memoryview)):
        raise NoiseNegotiationError('{} must be a sequence of protocol names'.format(field_name))
    try:
        return tuple(_normalise_bytes(offer, field_name) for offer in offers)
    except TypeError:
        raise NoiseNegotiationError('{} must be a sequence of protocol names'.format(field_name))


class NegotiationRecord(namedtuple(
        '_NegotiationRecord',
        'initiator_choice responder_choice initiator_offers responder_offers')):
    """
    Immutable result of the pre-handshake protocol negotiation.

    Both selections and both offer lists are part of the encoded prologue. This
    prevents a transcript from merely recording the local final algorithm name
    while omitting which alternatives the two parties actually agreed on.
    """
    __slots__ = ()

    def __new__(cls, initiator_choice, responder_choice, initiator_offers=(), responder_offers=()):
        return super(NegotiationRecord, cls).__new__(
            cls,
            _normalise_bytes(initiator_choice, 'initiator_choice'),
            _normalise_bytes(responder_choice, 'responder_choice'),
            _normalise_offers(initiator_offers, 'initiator_offers'),
            _normalise_offers(responder_offers, 'responder_offers'),
        )

    @property
    def initiator(self):
        return self.initiator_choice

    @property
    def responder(self):
        return self.responder_choice

    def to_bytes(self):
        """
        Canonical, unambiguous encoding suitable for use as Noise prologue data.

        Every variable-length field is length-prefixed, so a separator byte can
        never make two different records encode identically.
        """
        return b''.join([
            _MAGIC,
            encode_bytes(self.initiator_choice),
            encode_bytes(self.responder_choice),
            encode_bytes_list(self.initiator_offers),
            encode_bytes_list(self.responder_offers),
        ])

    @classmethod
    def from_bytes(cls, encoded):
        try:
            encoded = bytes(encoded)
            if not encoded.startswith(_MAGIC):
                raise ValueError('Unknown negotiation record encoding')
            decoder = Decoder(encoded[len(_MAGIC):])
            record = cls(
                decoder.read_bytes(),
                decoder.read_bytes(),
                decoder.read_bytes_list(),
                decoder.read_bytes_list(),
            )
            decoder.ensure_exhausted()
            return record
        except (TypeError, ValueError) as exc:
            raise NoiseNegotiationError('Malformed negotiation record: {}'.format(exc))

    def replace(self, **changes):
        values = self._asdict()
        values.update(changes)
        return type(self)(**values)

    def __reduce__(self):
        return (type(self), (self.initiator_choice, self.responder_choice,
                             self.initiator_offers, self.responder_offers))


def negotiate(initiator_offers, responder_offers):
    """
    Deterministically select the first initiator-preferred common protocol.

    Both peers call this with the same, role-labelled offer lists and therefore
    derive byte-identical records, including the complete offers from each side.
    """
    initiator_offers = _normalise_offers(initiator_offers, 'initiator_offers')
    responder_offers = _normalise_offers(responder_offers, 'responder_offers')
    if not initiator_offers or not responder_offers:
        raise NoiseNegotiationError('Both parties must advertise at least one protocol')

    responder_set = set(responder_offers)
    for offer in initiator_offers:
        if offer in responder_set:
            return NegotiationRecord(offer, offer, initiator_offers, responder_offers)
    raise NoiseNegotiationError('No protocol supported by both parties')
