"""Test-only signing subprocess for SubprocessSigner tests.

Signs with a fake, throwaway key passed via environment variables. The mode
(argv[1]) selects normal operation or one of several misbehaviors used to
exercise the SubprocessSigner safeguards. Do not use outside tests.

Environment:
    SSL_TEST_SIGNER_KEY: PEM/PKCS8 private key used for signing.
    SSL_TEST_WRONG_KEY: PEM/PKCS8 private key used in "wrong-key" mode.
    SSL_TEST_SIGNER_DELAY: response delay in seconds for "slow" mode.
"""

import base64
import json
import os
import sys
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.signer import CryptoSigner, SSlibKey


def _load_signer(env_var):
    private_key = load_pem_private_key(os.environ[env_var].encode(), None)
    public_key = SSlibKey.from_crypto(private_key.public_key())
    return CryptoSigner(private_key, public_key)


def _respond(response, mode):
    line = (json.dumps(response) + "\n").encode()
    if mode == "fragmented":
        # Dribble the response out in tiny chunks.
        for i in range(0, len(line), 7):
            sys.stdout.buffer.write(line[i : i + 7])
            sys.stdout.buffer.flush()
            time.sleep(0.01)
    else:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

    if mode == "die":
        # Simulate a helper that exits before doing any work.
        sys.exit(1)

    key_var = "SSL_TEST_WRONG_KEY" if mode == "wrong-key" else "SSL_TEST_SIGNER_KEY"
    signer = _load_signer(key_var)

    if mode == "noisy":
        # Log pollution: stderr must not take part in the protocol.
        print("helper starting up, loading fake key material", file=sys.stderr)

    for line in sys.stdin.buffer:
        try:
            request = json.loads(line)
        except ValueError:
            continue

        if mode == "slow":
            time.sleep(float(os.environ.get("SSL_TEST_SIGNER_DELAY", "5")))

        response_id = request["id"] + 1 if mode == "desync" else request["id"]
        signature = signer.sign(base64.b64decode(request["payload"]))
        _respond({"id": response_id, "sig": signature.signature}, mode)

        if mode == "noisy":
            print(f"signed request {request['id']}", file=sys.stderr)


if __name__ == "__main__":
    main()
