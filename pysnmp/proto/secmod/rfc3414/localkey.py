#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
import secrets
from hashlib import md5, sha1

from pyasn1.type import univ


def hash_passphrase(passphrase, hashFunc) -> univ.OctetString:
    """Return hash of passphrase using hashFunc hash function."""
    passphrase = univ.OctetString(passphrase).asOctets()
    # noinspection PyDeprecation,PyCallingNonCallable
    hasher = hashFunc()
    ringBuffer = passphrase * (64 // len(passphrase) + 1)
    # noinspection PyTypeChecker
    ringBufferLen = len(ringBuffer)
    count = 0
    mark = 0
    while count < 16384:
        e = mark + 64
        if e < ringBufferLen:
            hasher.update(ringBuffer[mark:e])
            mark = e
        else:
            hasher.update(
                ringBuffer[mark:ringBufferLen] + ringBuffer[0 : e - ringBufferLen]
            )
            mark = e - ringBufferLen
        count += 1
    digest = hasher.digest()
    return univ.OctetString(digest)


def password_to_key(passphrase, snmpEngineId, hashFunc) -> univ.OctetString:
    """Return key from password."""
    return localize_key(hash_passphrase(passphrase, hashFunc), snmpEngineId, hashFunc)


def localize_key(passKey, snmpEngineId, hashFunc) -> univ.OctetString:
    """Localize passKey with snmpEngineId using hashFunc hash function."""
    passKey = univ.OctetString(passKey).asOctets()
    # noinspection PyDeprecation,PyCallingNonCallable
    digest = hashFunc(passKey + snmpEngineId.asOctets() + passKey).digest()
    return univ.OctetString(digest)


# RFC 3414 A.5.1 & KeyChange TEXTUAL-CONVENTION (SNMP-USER-BASED-SM-MIB)
#
# A KeyChange value is the concatenation of a "random" component (as long
# as the key being changed) and a "delta" component. The delta component
# is produced by repeatedly hashing the old key (chained through the
# intermediate digests) with the random component and XOR-ing the digest
# with the new key. This way the new key never travels over the wire.


def produce_key_change(oldKey, newKey, hashFunc, rand=None) -> univ.OctetString:
    """Create a KeyChange value transforming oldKey into newKey.

    This is the manager-side operation: given the existing localized key
    *oldKey* and the desired localized key *newKey*, produce the opaque
    KeyChange value to send to the authoritative SNMP engine. The *rand*
    component is generated randomly unless explicitly given.
    """
    oldKey = univ.OctetString(oldKey).asOctets()
    newKey = univ.OctetString(newKey).asOctets()
    if rand is None:
        rand = secrets.token_bytes(len(oldKey))
    else:
        rand = univ.OctetString(rand).asOctets()
    temp = oldKey
    delta = b""
    offset = 0
    while offset < len(newKey):
        temp = hashFunc(temp + rand).digest()
        chunk = newKey[offset : offset + len(temp)]
        delta += bytes(x ^ y for x, y in zip(temp, chunk))
        offset += len(temp)
    return univ.OctetString(rand + delta)


def resolve_key_change(oldKey, keyChange, hashFunc) -> univ.OctetString:
    """Recover the new key from a KeyChange value.

    This is the receiver-side operation: given the existing localized key
    *oldKey* and a KeyChange value (random || delta), compute the new
    localized key via the same one-way transform the manager used.
    """
    oldKey = univ.OctetString(oldKey).asOctets()
    keyChange = univ.OctetString(keyChange).asOctets()
    rand = keyChange[: len(oldKey)]
    delta = keyChange[len(oldKey) :]
    temp = oldKey
    newKey = b""
    offset = 0
    while offset < len(delta):
        temp = hashFunc(temp + rand).digest()
        chunk = delta[offset : offset + len(temp)]
        newKey += bytes(x ^ y for x, y in zip(temp, chunk))
        offset += len(temp)
    return univ.OctetString(newKey)


# RFC3414: A.2.1
def hash_passphrase_md5(passphrase) -> univ.OctetString:
    """Return MD5 hash of passphrase."""
    return hash_passphrase(passphrase, md5)


# RFC3414: A.2.2
def hash_passphrase_sha(passphrase) -> univ.OctetString:
    """Return SHA-1 hash of passphrase."""
    return hash_passphrase(passphrase, sha1)


def password_to_key_md5(passphrase, snmpEngineId) -> univ.OctetString:
    """Return MD5 key from password."""
    return localize_key(hash_passphrase_md5(passphrase), snmpEngineId, md5)


def password_to_key_sha(passphrase, snmpEngineId) -> univ.OctetString:
    """Return SHA-1 key from password."""
    return localize_key(hash_passphrase_sha(passphrase), snmpEngineId, sha1)


def localize_key_md5(passKey, snmpEngineId) -> univ.OctetString:
    """Localize passKey with snmpEngineId using MD5 hash function."""
    return localize_key(passKey, snmpEngineId, md5)


def localize_key_sha(passKey, snmpEngineId) -> univ.OctetString:
    """Localize passKey with snmpEngineId using SHA1 hash function."""
    return localize_key(passKey, snmpEngineId, sha1)
