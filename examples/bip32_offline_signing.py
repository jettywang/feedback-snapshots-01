#!/usr/bin/env python3
"""BIP32 offline signing vs. watch-only permissions, on secp256k1.

The example separates two roles:

* the signing side holds an extended private key below a hardened account
  boundary and can create signatures;
* the observation side holds only the account extended public key and can
  derive non-hardened receive keys, but cannot sign and cannot cross the
  hardened boundary.

It also demonstrates the known BIP32 risk that a parent extended public key
plus any non-hardened child private key reveals the parent private key.  This
is a property of BIP32, not something this example or the library hides.

Run with::

    python examples/bip32_offline_signing.py
"""

import hashlib

from ecdsa.bip32 import HARDENED, ExtendedPublicKey, master_from_seed

# A fixed seed makes the example reproducible.  Never deploy a published
# seed; use a CSPRNG and keep the seed offline.
SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ACCOUNT = 0
EXTERNAL_CHAIN = 0


def main():
    master = master_from_seed(SEED)
    account = master.derive(HARDENED + ACCOUNT)
    signing_node = account.derive(EXTERNAL_CHAIN)

    # The observation node gets only the account xpub.  The hardened account
    # boundary means it cannot climb back to the master or other accounts.
    watch_node = ExtendedPublicKey.from_base58(account.neuter().to_base58())

    print("signing side (extended private key)")
    print("  account xprv: {0}".format(account.to_base58()))
    print("  sign node:    {0}".format(signing_node.to_base58()))
    print(
        "  public key:   {0}".format(
            signing_node.public_key.to_string("compressed").hex()
        )
    )
    print()

    print("observation side (extended public key only)")
    print("  account xpub: {0}".format(watch_node.to_base58()))
    derived = watch_node.derive(EXTERNAL_CHAIN)
    print(
        "  external /0:  {0}".format(
            derived.public_key.to_string("compressed").hex()
        )
    )
    print(
        "  matches signer's external /0 public key: {0}".format(
            derived.public_key == signing_node.public_key
        )
    )
    print()

    message = b"offline-signed withdrawal request"
    signature = signing_node.private_key.sign_deterministic(
        message, hashfunc=hashlib.sha256
    )
    print("signature produced by signing node")
    print("  signature:   {0}".format(signature.hex()))
    try:
        watch_node.private_key
    except AttributeError:
        print("  observation side has no private_key: signing is impossible")
    assert derived.public_key.verify(
        signature, message, hashfunc=hashlib.sha256
    )
    print("  watch node verified the signature with the derived public key")
    print()

    print("hardened boundary")
    try:
        watch_node.derive(HARDENED + 1)
    except Exception as e:
        print("  watch node cannot derive hardened child: {0}".format(e))
    print(
        "  sign node can derive hardened child: {0}".format(
            signing_node.derive(HARDENED + 1).child_number == HARDENED + 1
        )
    )
    print()

    print("known risk: parent xpub + non-hardened child private key")
    child_private = signing_node.private_key.privkey.secret_multiplier
    # The example recovers the parent scalar only by using the parent chain
    # code, which is public, and the child's derivation index, which is public.
    from ecdsa.bip32 import _hmac_sha512, _ser32
    from ecdsa.curves import SECP256k1

    data = watch_node.public_key.to_string("compressed") + _ser32(
        EXTERNAL_CHAIN
    )
    tweak = int.from_bytes(
        _hmac_sha512(watch_node.chain_code, data)[:32], "big"
    )
    recovered = (child_private - tweak) % SECP256k1.order
    recovered_matches = (
        recovered == account.private_key.privkey.secret_multiplier
    )
    print(
        "  account xpub + one non-hardened child xprv recovers account "
        "private key: {0}".format(recovered_matches)
    )
    print(
        "  conclusion: the observation node must be kept as a public-only "
        "service; this is not hardware isolation."
    )


if __name__ == "__main__":
    main()
