import abc
from typing import Optional, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import DecryptOp, EncryptOp
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosemessage import CoseMessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK


class EncCommon(CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """ Getter for the context of the message. """

        raise NotImplementedError()

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):
        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

    def decrypt(self, *args, **kwargs) -> bytes:
        """
        Decrypts the payload.

        :raises CoseException: When the key is not of type 'SymmetricKey'.
        :returns: plaintext as bytes
        """

        alg = self.get_attr(headers.Algorithm)
        nonce = self._get_nonce()

        if self.key is None:
            raise CoseException("Key cannot be None")

        self.key.verify(SymmetricKey, alg, [DecryptOp])

        return alg.decrypt(key=self.key, ciphertext=self.payload, aad=self._enc_structure, nonce=nonce)

    def encrypt(self, *args, **kwargs) -> bytes:
        """
        Encrypts the payload.

        :raises CoseException: When the key is not of type 'SymmetricKey'.
        :returns: ciphertext as bytes
        """

        # first check if key is set (since a part of the nonce can be stored in the key)
        if self.key is None:
            raise CoseException("Key cannot be None")

        alg = self.get_attr(headers.Algorithm)
        nonce = self._get_nonce()

        self.key.verify(SymmetricKey, alg, [EncryptOp])

        return alg.encrypt(key=self.key, data=self.payload, aad=self._enc_structure, nonce=nonce)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

    def _get_nonce(self):
        nonce = self.get_attr(headers.IV)

        if nonce is None and self.key.base_iv != b'':
            partial_iv = self.get_attr(headers.PartialIV)
            if partial_iv is None:
                raise CoseException('No IV found')

            # RFC 9052, Section 3.1: left-pad the Partial IV with zeros to the
            # IV length and XOR it with the Context IV.  The result must keep
            # that full length; trimming leading zero bytes would silently
            # shorten the nonce for algorithms with long all-zero prefixes.
            iv_length = getattr(self.get_attr(headers.Algorithm), 'get_nonce_length', None)
            iv_length = iv_length() if iv_length is not None else len(self.key.base_iv)

            if len(self.key.base_iv) != iv_length:
                raise CoseException(
                    f"Context IV must be {iv_length} bytes, found {len(self.key.base_iv)} bytes")
            if len(partial_iv) > iv_length:
                raise CoseException(
                    f"Partial IV cannot be longer than the {iv_length}-byte IV, found {len(partial_iv)} bytes")

            padded_partial_iv = partial_iv.rjust(iv_length, b'\x00')
            nonce = bytes(a ^ b for a, b in zip(padded_partial_iv, self.key.base_iv))

        if nonce is None and self.key.base_iv == b'':
            raise CoseException('No IV found')

        return nonce
