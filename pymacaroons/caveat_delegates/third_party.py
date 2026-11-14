from __future__ import unicode_literals
import binascii

from nacl.secret import SecretBox

from pymacaroons import Caveat
from pymacaroons.utils import (
    convert_to_bytes,
    truncate_or_pad,
    generate_derived_key,
    sign_third_party_caveat,
)
from pymacaroons.exceptions import (
    MacaroonInvalidSignatureException,
    MacaroonUnmetCaveatException,
)
from .base_third_party import (
    BaseThirdPartyCaveatDelegate,
    BaseThirdPartyCaveatVerifierDelegate,
)


class ThirdPartyCaveatDelegate(BaseThirdPartyCaveatDelegate):

    def __init__(self, *args, **kwargs):
        super(ThirdPartyCaveatDelegate, self).__init__(*args, **kwargs)

    def add_third_party_caveat(self,
                               macaroon,
                               location,
                               key,
                               key_id,
                               **kwargs):
        derived_key = truncate_or_pad(
            generate_derived_key(convert_to_bytes(key))
        )
        old_key = truncate_or_pad(binascii.unhexlify(macaroon.signature_bytes))
        box = SecretBox(key=old_key)
        verification_key_id = box.encrypt(
            derived_key, nonce=kwargs.get('nonce')
        )
        caveat = Caveat(
            caveat_id=key_id,
            location=location,
            verification_key_id=verification_key_id,
            version=macaroon.version
        )
        macaroon.caveats.append(caveat)
        encode_key = binascii.unhexlify(macaroon.signature_bytes)
        macaroon.signature = sign_third_party_caveat(
            encode_key,
            caveat._verification_key_id,
            caveat._caveat_id
        )
        return macaroon


class ThirdPartyCaveatVerifierDelegate(BaseThirdPartyCaveatVerifierDelegate):

    def __init__(self, discharge_macaroons=None, *args, **kwargs):
        super(ThirdPartyCaveatVerifierDelegate, self).__init__(*args, **kwargs)
        self.discharge_macaroons = {}
        for macaroon in discharge_macaroons or []:
            self.discharge_macaroons.setdefault(
                macaroon.identifier_bytes, []
            ).append(macaroon)

    def verify_third_party_caveat(self,
                                  verifier,
                                  caveat,
                                  root,
                                  macaroon,
                                  signature):
        caveat_key = self._extract_caveat_key(signature, caveat)
        candidates = list(self.discharge_macaroons.get(
            caveat.caveat_id_bytes, []
        ))
        if not candidates:
            raise MacaroonUnmetCaveatException(
                'Caveat not met. No discharge macaroon found for identifier: '
                '{}'.format(caveat.caveat_id_bytes)
            )

        # Multiple organizations may use the same short caveat identifier.
        # A discharge macaroon is authenticated by the caveat key, so try
        # each candidate instead of letting insertion order decide.  Restore
        # the available set after a failed attempt so retries do not consume
        # nested discharges.
        last_error = None
        for candidate in candidates:
            snapshot = self._snapshot()
            self._remove(caveat.caveat_id_bytes, candidate)
            caveat_met = False
            try:
                try:
                    caveat_met = verifier.verify_discharge(
                        root,
                        candidate,
                        caveat_key,
                    )
                except MacaroonInvalidSignatureException as error:
                    last_error = error
                except MacaroonUnmetCaveatException as error:
                    last_error = error
            finally:
                if not caveat_met:
                    self._restore(snapshot)
            if caveat_met:
                return True

        if last_error is not None:
            raise last_error
        raise MacaroonUnmetCaveatException(
            'Caveat not met. No matching discharge macaroon found for '
            'identifier: {}'.format(caveat.caveat_id_bytes)
        )

    def _snapshot(self):
        return {
            caveat_id: list(macaroons)
            for caveat_id, macaroons in self.discharge_macaroons.items()
        }

    def _restore(self, snapshot):
        self.discharge_macaroons = {
            caveat_id: list(macaroons)
            for caveat_id, macaroons in snapshot.items()
        }

    def _remove(self, caveat_id, candidate):
        remaining = [
            macaroon for macaroon in self.discharge_macaroons.get(
                caveat_id, []
            ) if macaroon is not candidate
        ]
        if remaining:
            self.discharge_macaroons[caveat_id] = remaining
        else:
            self.discharge_macaroons.pop(caveat_id, None)

    def update_signature(self, signature, caveat):
        return binascii.unhexlify(
            sign_third_party_caveat(
                signature,
                caveat._verification_key_id,
                caveat._caveat_id
            )
        )

    def _extract_caveat_key(self, signature, caveat):
        key = truncate_or_pad(signature)
        box = SecretBox(key=key)
        decrypted = box.decrypt(caveat._verification_key_id)
        return decrypted
