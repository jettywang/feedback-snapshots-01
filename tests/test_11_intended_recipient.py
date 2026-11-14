""" Demonstrate Intended Recipient (signature subpacket 0x23) sign/receive policies.

Two recipients (Alice and Bob) each hold a local primary key plus an encryption subkey.
Every scenario reports three properties separately:

  - decryptable:  the message can be decrypted with the recipient's local key
  - signature_valid:  the sender's signature over the message verifies
  - recipient_ok:  the Intended Recipient constraint is satisfied under the chosen policy
"""
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPUID
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import IntendedRecipientPolicy
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPError

STRICT = IntendedRecipientPolicy.Strict
COMPAT = IntendedRecipientPolicy.Compat
IGNORE = IntendedRecipientPolicy.Ignore


def new_identity(name, email):
    """A primary key for signing/certifying, plus an encryption subkey."""
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new(name, email=email)
    key.add_uid(uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.Uncompressed])
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    return key


def enc_subkey(key):
    """The (public, if key is public) encryption subkey of a key, with its parent linkage intact."""
    return next(iter(key.subkeys.values()))


def signed_message(sender, text, intended_recipients=None):
    msg = PGPMessage.new(text, compression=CompressionAlgorithm.Uncompressed)
    prefs = {}
    if intended_recipients is not None:
        prefs['intended_recipients'] = intended_recipients
    msg |= sender.sign(msg, **prefs)
    return msg


def receive(recipient, sender_pub, encmsg, policy):
    """Receive an encrypted, signed message; report each security property separately."""
    report = {'decryptable': False, 'signature_valid': False, 'recipient_ok': False}
    try:
        decmsg = recipient.decrypt(encmsg)
    except PGPError:
        return report
    report['decryptable'] = True

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        report['signature_valid'] = bool(sender_pub.verify(decmsg))

    # the key the message was actually encrypted to: never trust the key id alone,
    # check_intended_recipient verifies the subkey binding before attributing the primary
    ids = set(encmsg.encrypters)
    if recipient.fingerprint.keyid in ids:
        deckey = recipient
    else:
        skid = next(iter(set(recipient.subkeys) & ids))
        deckey = recipient.subkeys[skid]

    sig = next(iter(decmsg.signatures))
    report['recipient_ok'] = deckey.check_intended_recipient(sig, policy)
    return report


def show(scenario, recipient_name, policy, report):
    print('\n[{s}] 接收人={r} 策略={p}: 加密可解={decryptable} 签名有效={signature_valid} 收件人约束满足={recipient_ok}'
          ''.format(s=scenario, r=recipient_name, p=policy.name, **report))


@pytest.fixture(scope='module')
def sender():
    return new_identity('Sender', 'sender@example.org')


@pytest.fixture(scope='module')
def alice():
    return new_identity('Alice', 'alice@example.org')


@pytest.fixture(scope='module')
def bob():
    return new_identity('Bob', 'bob@example.org')


# keep strong references to the public halves: subkey parent linkage is weakly referenced
@pytest.fixture(scope='module')
def sender_pub(sender):
    return sender.pubkey


@pytest.fixture(scope='module')
def alice_pub(alice):
    return alice.pubkey


@pytest.fixture(scope='module')
def bob_pub(bob):
    return bob.pubkey


def test_original_recipient_accepted(sender, sender_pub, alice, alice_pub, bob):
    # sender binds Alice's full primary fingerprint into the signed (hashed) area
    msg = signed_message(sender, 'meet at dawn', intended_recipients=[alice_pub])
    enc = enc_subkey(alice_pub).encrypt(msg)

    report = receive(alice, sender_pub, enc, STRICT)
    show('场景1 原接收', 'Alice', STRICT, report)
    assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': True}


def test_forwarded_message_rejected(sender, sender_pub, alice, alice_pub, bob, bob_pub):
    # Alice is the legitimate recipient...
    msg = signed_message(sender, 'meet at dawn', intended_recipients=[alice_pub])
    enc = enc_subkey(alice_pub).encrypt(msg)
    decmsg = alice.decrypt(enc)

    # ...but when she decrypts and re-encrypts the still-validly-signed message to Bob,
    # Bob's strict policy must reject it: the signature only names Alice
    fwd = enc_subkey(bob_pub).encrypt(decmsg)

    report = receive(bob, sender_pub, fwd, STRICT)
    show('场景2 转发重加密', 'Bob', STRICT, report)
    assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': False}

    # Compat does not help a forwarded message either: the subpacket is present and mismatched
    report = receive(bob, sender_pub, fwd, COMPAT)
    show('场景2 转发重加密', 'Bob', COMPAT, report)
    assert report['recipient_ok'] is False


def test_multi_recipient_accepted(sender, sender_pub, alice, alice_pub, bob, bob_pub):
    # a legitimate multi-recipient message names both primaries in the hashed area
    msg = signed_message(sender, 'meet at dawn', intended_recipients=[alice_pub, bob_pub])
    # both PKESK packets must wrap the same session key
    sessionkey = SymmetricKeyAlgorithm.AES256.gen_key()
    enc = enc_subkey(alice_pub).encrypt(msg, sessionkey=sessionkey)
    enc = enc_subkey(bob_pub).encrypt(enc, sessionkey=sessionkey)

    for key, name in ((alice, 'Alice'), (bob, 'Bob')):
        report = receive(key, sender_pub, enc, STRICT)
        show('场景3 合法多收件人', name, STRICT, report)
        assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': True}


def test_legacy_message_respects_selected_policy(sender, sender_pub, alice, alice_pub):
    # a legacy message carries no Intended Recipient subpacket at all
    msg = signed_message(sender, 'meet at dawn')
    enc = enc_subkey(alice_pub).encrypt(msg)

    # strict mode must not silently treat it as satisfying the recipient constraint
    report = receive(alice, sender_pub, enc, STRICT)
    show('场景4 无子包旧消息', 'Alice', STRICT, report)
    assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': False}

    # the caller may explicitly select the compatibility policy for legacy messages
    report = receive(alice, sender_pub, enc, COMPAT)
    show('场景4 无子包旧消息', 'Alice', COMPAT, report)
    assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': True}

    report = receive(alice, sender_pub, enc, IGNORE)
    show('场景4 无子包旧消息', 'Alice', IGNORE, report)
    assert report['recipient_ok'] is True


def test_unhashed_subpacket_cannot_escalate(sender, sender_pub, alice, alice_pub, bob, bob_pub):
    # a message legitimately intended for Alice only
    msg = signed_message(sender, 'meet at dawn', intended_recipients=[alice_pub])

    # an attacker appends an Intended Recipient subpacket for Bob to the *unhashed* area
    sig = next(iter(msg.signatures))
    sig._signature.subpackets.addnew('IntendedRecipient', hashed=False, version=4,
                                     intended_recipient=bob.fingerprint)

    # round-trip through the wire format so the tampered packet is what a receiver would parse
    msg = PGPMessage.from_blob(bytes(msg))
    sig = next(iter(msg.signatures))

    # only signature-covered (hashed) claims are visible to the receive policy
    assert list(sig.intended_recipients) == [alice.fingerprint]

    enc = enc_subkey(bob_pub).encrypt(msg)
    for policy in (STRICT, COMPAT):
        report = receive(bob, sender_pub, enc, policy)
        show('场景5 unhashed 扩权尝试', 'Bob', policy, report)
        assert report == {'decryptable': True, 'signature_valid': True, 'recipient_ok': False}


def test_subkey_binding_must_verify(sender):
    victor = new_identity('Victor', 'victor@example.org')
    victor_pub = victor.pubkey
    msg = signed_message(sender, 'meet at dawn', intended_recipients=[victor_pub])
    sig = next(iter(msg.signatures))

    subkey = enc_subkey(victor)

    # an orphan subkey cannot be attributed to any primary by key id alone
    subkey._parent = None
    with pytest.raises(PGPError):
        subkey.check_intended_recipient(sig, STRICT)

    # a rogue primary that merely claims the subkey's key id, without a valid
    # subkey binding signature, is rejected as well
    rogue = new_identity('Mallory', 'mallory@example.org')
    rogue |= subkey
    with pytest.raises(PGPError):
        subkey.check_intended_recipient(sig, STRICT)

    print('\n[场景6 子钥绑定] 孤儿子钥与伪造绑定均被拒绝（抛出 PGPError），不匹配短 ID')
