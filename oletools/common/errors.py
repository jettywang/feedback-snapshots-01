"""
Errors used in several tools to avoid duplication

.. codeauthor:: Intra2net AG <info@intra2net.com>
"""

class CryptoErrorBase(ValueError):
    """Base class for crypto-based exceptions.

    Instances raised during nested decryption may carry the per-invocation
    :class:`oletools.crypto.DecryptionReport` and the layer that failed, so
    callers can report exactly where processing stopped without exposing any
    password or plaintext.
    """

    #: Optional report object (see :mod:`oletools.crypto`)
    report = None

    #: Optional :class:`oletools.crypto.DecryptionLayer` describing the failure
    layer = None

    #: Machine-readable outcome, e.g. ``wrong_password`` or ``corrupt``
    outcome = None

    def attach_report(self, report, layer=None, outcome=None):
        """Attach diagnostic context without changing the exception message."""
        self.report = report
        if layer is not None:
            self.layer = layer
        if outcome is not None:
            self.outcome = outcome
        if report is not None:
            report.mark_stopped_from_exception(self)
        return self


class CryptoLibNotImported(CryptoErrorBase, ImportError):
    """Exception thrown if msoffcrypto is needed but could not be imported."""

    def __init__(self):
        super(CryptoLibNotImported, self).__init__(
            'msoffcrypto-tools is not installed. Please run "pip install msoffcrypto-tool" or see https://github.com/nolze/msoffcrypto-tool')


class UnsupportedEncryptionError(CryptoErrorBase):
    """Exception thrown if file is encrypted and cannot deal with it."""
    def __init__(self, filename=None, detail=None):
        self.detail = detail
        message = 'Office file {}is encrypted, not yet supported'.format(
            '' if filename is None else filename + ' ')
        if detail:
            message += ' ({})'.format(detail)
        super(UnsupportedEncryptionError, self).__init__(message)


class WrongEncryptionPassword(CryptoErrorBase):
    """Exception thrown if encryption could be handled but passwords wrong."""
    def __init__(self, filename=None):
        super(WrongEncryptionPassword, self).__init__(
            'Given passwords could not decrypt office file{}, use option -p to specify the password'
            .format('' if filename is None else ' ' + filename))


class CorruptedEncryptionError(CryptoErrorBase):
    """Exception thrown if the encrypted container structure is damaged."""

    def __init__(self, filename=None, detail=None):
        self.detail = detail
        message = 'Encrypted office file {}is corrupt or malformed'.format(
            '' if filename is None else filename + ' ')
        if detail:
            message += ' ({})'.format(detail)
        super(CorruptedEncryptionError, self).__init__(message)


class MaxCryptoNestingReached(CryptoErrorBase):
    """
    Exception thrown if decryption is too deeply layered.

    (...or decrypt code creates inf loop)
    """
    def __init__(self, n_layers, filename=None):
        super(MaxCryptoNestingReached, self).__init__(
            'Encountered more than {} layers of encryption for office file{}'
            .format(n_layers, '' if filename is None else ' ' + filename))


class MaxDecryptionAttemptsReached(CryptoErrorBase):
    """Exception thrown if the per-invocation password attempt budget is used up."""

    def __init__(self, n_attempts, filename=None):
        super(MaxDecryptionAttemptsReached, self).__init__(
            'Encountered more than {} decryption attempts for office file{}'
            .format(n_attempts, '' if filename is None else ' ' + filename))
