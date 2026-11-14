import binascii
import json

import six

from pymacaroons import utils
from pymacaroons.exceptions import MacaroonDeserializationException


# Keys allowed at the top level of each JSON format and inside its caveats.
# Anything else is unconsumed data and must be rejected rather than ignored,
# otherwise two parsers could accept different fields from one token.
_V1_TOP_LEVEL_KEYS = frozenset(('identifier', 'signature', 'location',
                                'caveats'))
_V1_CAVEAT_KEYS = frozenset(('cid', 'vid', 'cl'))
_V2_TOP_LEVEL_KEYS = frozenset(('i', 'i64', 's', 's64', 'l', 'l64', 'c'))
_V2_CAVEAT_KEYS = frozenset(('i', 'i64', 'v', 'v64', 'l', 'l64'))


class JsonSerializer(object):
    """Serializer used to produce JSON macaroon format v1.
    """

    def serialize(self, m):
        """Serialize the macaroon in JSON format indicated by the version
        field.

        @param m the macaroon to serialize.
        @return JSON macaroon.
        """
        from pymacaroons import macaroon
        if m.version == macaroon.MACAROON_V1:
            return self._serialize_v1(m)
        return self._serialize_v2(m)

    def _serialize_v1(self, macaroon):
        """Serialize the macaroon in JSON format v1.

        @param macaroon the macaroon to serialize.
        @return JSON macaroon.
        """
        serialized = {
            'identifier': utils.convert_to_string(macaroon.identifier),
            'signature': macaroon.signature,
        }
        if macaroon.location:
            serialized['location'] = macaroon.location
        if macaroon.caveats:
            serialized['caveats'] = [
                _caveat_v1_to_dict(caveat) for caveat in macaroon.caveats
            ]
        return json.dumps(serialized)

    def _serialize_v2(self, macaroon):
        """Serialize the macaroon in JSON format v2.

        @param macaroon the macaroon to serialize.
        @return JSON macaroon in v2 format.
        """
        serialized = {}
        _add_json_binary_field(macaroon.identifier_bytes, serialized, 'i')
        _add_json_binary_field(binascii.unhexlify(macaroon.signature_bytes),
                               serialized, 's')

        if macaroon.location:
            serialized['l'] = macaroon.location
        if macaroon.caveats:
            serialized['c'] = [
                _caveat_v2_to_dict(caveat) for caveat in macaroon.caveats
            ]
        return json.dumps(serialized)

    def deserialize(self, serialized):
        """Deserialize a JSON macaroon depending on the format.

        @param serialized the macaroon in JSON format.
        @return the macaroon object.
        """
        try:
            deserialized = json.loads(
                serialized, object_pairs_hook=_reject_duplicate_keys)
        except MacaroonDeserializationException:
            raise
        except ValueError as exc:
            raise MacaroonDeserializationException(
                'cannot decode JSON macaroon: {exc}'.format(exc=exc))
        if not isinstance(deserialized, dict):
            raise MacaroonDeserializationException(
                'JSON macaroon must be an object')
        has_v1 = _has_field(deserialized, 'identifier')
        has_v2 = (_has_field(deserialized, 'i')
                  or _has_field(deserialized, 's'))
        if has_v1 and has_v2:
            raise MacaroonDeserializationException(
                'macaroon mixes v1 and v2 JSON fields')
        if has_v2:
            return self._deserialize_v2(deserialized)
        if has_v1:
            return self._deserialize_v1(deserialized)
        raise MacaroonDeserializationException(
            'JSON macaroon is missing an identifier')

    def _deserialize_v1(self, serialized):
        """Deserialize a JSON macaroon in v1 format.

        @param serialized the macaroon in v1 JSON format.
        @return the macaroon object.
        """
        from pymacaroons.macaroon import Macaroon, MACAROON_V1
        from pymacaroons.caveat import Caveat

        _reject_unknown_keys(serialized, _V1_TOP_LEVEL_KEYS, 'macaroon')

        identifier = serialized.get('identifier')
        if not isinstance(identifier, six.string_types) or identifier == '':
            raise MacaroonDeserializationException(
                'v1 macaroon requires a string identifier')
        signature = serialized.get('signature')
        if not isinstance(signature, six.string_types) or signature == '':
            raise MacaroonDeserializationException(
                'v1 macaroon requires a string signature')
        location = serialized.get('location')
        if location is not None and not isinstance(location, six.string_types):
            raise MacaroonDeserializationException(
                'v1 macaroon location must be a string')

        raw_caveats = serialized.get('caveats', [])
        if not isinstance(raw_caveats, list):
            raise MacaroonDeserializationException(
                'v1 macaroon caveats must be an array')

        caveats = []
        for raw_caveat in raw_caveats:
            if not isinstance(raw_caveat, dict):
                raise MacaroonDeserializationException(
                    'v1 caveat must be an object')
            _reject_unknown_keys(raw_caveat, _V1_CAVEAT_KEYS, 'caveat')
            caveat_id = raw_caveat.get('cid')
            if not isinstance(caveat_id, six.string_types) or caveat_id == '':
                raise MacaroonDeserializationException(
                    'v1 caveat requires a string cid')
            vid = raw_caveat.get('vid')
            if vid is not None and not isinstance(vid, six.string_types):
                raise MacaroonDeserializationException(
                    'v1 caveat vid must be a string')
            caveat_location = raw_caveat.get('cl')
            if caveat_location is not None and \
                    not isinstance(caveat_location, six.string_types):
                raise MacaroonDeserializationException(
                    'v1 caveat cl must be a string')
            caveat = Caveat(
                caveat_id=caveat_id,
                verification_key_id=(
                    utils.raw_b64decode(vid) if vid else None
                ),
                location=caveat_location if caveat_location else None,
                version=MACAROON_V1
            )
            caveats.append(caveat)

        return Macaroon(
            location=location,
            identifier=identifier,
            caveats=caveats,
            signature=signature,
            version=MACAROON_V1
        )

    def _deserialize_v2(self, serialized):
        """Deserialize a JSON macaroon v2.

        @param serialized the macaroon in JSON format v2.
        @return the macaroon object.
        """
        from pymacaroons.macaroon import Macaroon, MACAROON_V2
        from pymacaroons.caveat import Caveat

        _reject_unknown_keys(serialized, _V2_TOP_LEVEL_KEYS, 'macaroon')

        identifier = _read_required_json_binary_field(
            serialized, 'i', 'identifier')
        signature = _read_required_json_binary_field(
            serialized, 's', 'signature')
        location = _read_json_binary_field(serialized, 'l')

        raw_caveats = serialized.get('c', [])
        if not isinstance(raw_caveats, list):
            raise MacaroonDeserializationException(
                'v2 macaroon caveats must be an array')

        caveats = []
        for raw_caveat in raw_caveats:
            if not isinstance(raw_caveat, dict):
                raise MacaroonDeserializationException(
                    'v2 caveat must be an object')
            _reject_unknown_keys(raw_caveat, _V2_CAVEAT_KEYS, 'caveat')
            caveat_id = _read_required_json_binary_field(
                raw_caveat, 'i', 'caveat identifier')
            verification_key_id = _read_json_binary_field(raw_caveat, 'v')
            caveat_location = _read_json_binary_field(raw_caveat, 'l')
            caveat = Caveat(
                caveat_id=caveat_id,
                verification_key_id=verification_key_id,
                location=caveat_location,
                version=MACAROON_V2
            )
            caveats.append(caveat)
        return Macaroon(
            location=location,
            identifier=identifier,
            caveats=caveats,
            signature=binascii.hexlify(signature),
            version=MACAROON_V2
        )


def _caveat_v1_to_dict(c):
    """ Return a caveat as a dictionary for export as the JSON
    macaroon v1 format.
    """
    serialized = {}
    if len(c.caveat_id) > 0:
        serialized['cid'] = c.caveat_id
    if c.verification_key_id:
        serialized['vid'] = utils.raw_urlsafe_b64encode(
            c.verification_key_id).decode('utf-8')
    if c.location:
        serialized['cl'] = c.location
    return serialized


def _caveat_v2_to_dict(c):
    """ Return a caveat as a dictionary for export as the JSON
    macaroon v2 format.
    """
    serialized = {}
    if len(c.caveat_id_bytes) > 0:
        _add_json_binary_field(c.caveat_id_bytes, serialized, 'i')
    if c.verification_key_id:
        _add_json_binary_field(c.verification_key_id, serialized, 'v')
    if c.location:
        serialized['l'] = c.location
    return serialized


def _add_json_binary_field(b, serialized, field):
    """ Set the given field to the given val (a bytearray) in the serialized
    dictionary.

    If the value isn't valid utf-8, we base64 encode it and use field+"64"
    as the field name.
    """
    try:
        val = b.decode("utf-8")
        serialized[field] = val
    except UnicodeDecodeError:
        val = utils.raw_urlsafe_b64encode(b).decode('utf-8')
        serialized[field + '64'] = val


def _reject_duplicate_keys(pairs):
    """ json.loads hook that refuses objects containing duplicate keys.

    A duplicate key leaves the choice of which value to use to each parser,
    so a token carrying the same field twice is ambiguous and must be
    rejected at the authorization boundary.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise MacaroonDeserializationException(
                'duplicate JSON key: {key}'.format(key=key))
        seen.add(key)
    return dict(pairs)


def _reject_unknown_keys(deserialized, allowed, context):
    unknown = set(deserialized) - allowed
    if unknown:
        raise MacaroonDeserializationException(
            'unexpected {context} key(s): {keys}'.format(
                context=context, keys=', '.join(sorted(unknown))))


def _has_field(deserialized, field):
    return field in deserialized or field + '64' in deserialized


def _read_json_binary_field(deserialized, field):
    """ Read the value of a JSON field that may be string or base64-encoded.

    Supplying both the plain and the base64 spellings is rejected because the
    two encodings could otherwise disagree about the field's value.
    """
    plain_present = field in deserialized
    encoded_present = field + '64' in deserialized
    if plain_present and encoded_present:
        raise MacaroonDeserializationException(
            'field {field} supplied as both {field} and {field}64'.format(
                field=field))
    val = deserialized.get(field)
    if val is not None:
        if not isinstance(val, six.string_types):
            raise MacaroonDeserializationException(
                'field {field} must be a string'.format(field=field))
        return utils.convert_to_bytes(val)
    val = deserialized.get(field + '64')
    if val is None:
        return None
    if not isinstance(val, six.string_types):
        raise MacaroonDeserializationException(
            'field {field}64 must be a string'.format(field=field))
    try:
        return utils.raw_urlsafe_b64decode(val)
    except Exception as exc:
        raise MacaroonDeserializationException(
            'cannot base64-decode field {field}64: {exc}'.format(
                field=field, exc=exc))


def _read_required_json_binary_field(deserialized, field, description):
    value = _read_json_binary_field(deserialized, field)
    if value is None or len(value) == 0:
        raise MacaroonDeserializationException(
            'missing required {description}'.format(description=description))
    return value
