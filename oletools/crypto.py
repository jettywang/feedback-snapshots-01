#!/usr/bin/env python
"""
crypto.py

Module to be used by other scripts and modules in oletools, that provides
information on encryption in OLE files.

Uses :py:mod:`msoffcrypto-tool` to decrypt if it is available. Otherwise
decryption will fail with an ImportError.

Encryption/Write-Protection can be realized in many different ways. They range
from setting a single flag in an otherwise unprotected file to embedding a
regular file (e.g.  xlsx) in an EncryptedStream inside an OLE file. That means
that (1) that lots of bad things are accesible even if no encryption password
is known, and (2) even basic attributes like the file type can change by
decryption. Therefore I suggest the following general routine to deal with
potentially encrypted files::

    def script_main_function(input_file, passwords, crypto_nesting=0, args):
        '''Wrapper around main function to deal with encrypted files.'''
        initial_stuff(input_file, args)
        result = None
        try:
            result = do_your_thing_assuming_no_encryption(input_file)
            if not crypto.is_encrypted(input_file):
                return result
        except Exception:
            if not crypto.is_encrypted(input_file):
                raise
        # we reach this point only if file is encrypted
        # check if this is an encrypted file in an encrypted file in an ...
        if crypto_nesting >= crypto.MAX_NESTING_DEPTH:
            raise crypto.MaxCryptoNestingReached(crypto_nesting, filename)
        decrypted_file = None
        try:
            decrypted_file, correct_password = crypto.decrypt(input_file, passwords, decrypted_dir)
            if decrypted_file is None:
                raise crypto.WrongEncryptionPassword(input_file)
            # might still be encrypted, so call this again recursively
            result = script_main_function(decrypted_file, passwords,
                                          crypto_nesting+1, args)
        except Exception:
            raise
        finally:     # clean up
            try:     # (maybe file was not yet created)
                os.unlink(decrypted_file)
            except Exception:
                pass

(Realized e.g. in :py:mod:`oletools.msodde`).
That means that caller code needs another wrapper around its main function. I
did try it another way first (a transparent on-demand unencrypt) but for the
above reasons I believe this is the better way. Also, non-top-level-code can
just assume that it works on unencrypted data and fail with an exception if
encrypted data makes its work impossible. No need to check `if is_encrypted()`
at the start of functions.

Nested decryption is tracked by a :class:`DecryptionContext`, which must be
created once per top-level document and passed to every recursive layer.  It
records a :class:`DecryptionReport` with one :class:`DecryptionLayer` per
container and enforces both a nesting and a password-attempt budget.  Layers
are identified by the SHA-256 digest of their actual content, never by file
name.  Passwords are only referenced by candidate index, and decrypted bytes
are never stored in the report, so the report remains safe for logs::

    with crypto.decryption_context() as ctx:
        decrypted, password = crypto.decrypt(path, passwords, context=ctx)
        ...
        print(ctx.report.to_dict())

.. seealso:: [MS-OFFCRYPTO]
.. seealso:: https://github.com/nolze/msoffcrypto-tool

crypto is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

# === LICENSE =================================================================

# crypto is copyright (c) 2014-2021 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# -----------------------------------------------------------------------------
# CHANGELOG:
# 2019-02-14 v0.01 CH: - first version with encryption check from oleid
# 2019-04-01 v0.54 PL: - fixed bug in is_encrypted_ole
# 2019-05-23       PL: - added DEFAULT_PASSWORDS list
# 2021-05-22 v0.60 PL: - added PowerPoint transparent password
#                        '/01Hannes Ruescher/01' (issue #627)
# 2019-05-24       CH: - use log_helper

__version__ = '0.60'

import sys
import struct
import os
import shutil
import hashlib
import logging
from contextlib import contextmanager
from os.path import splitext, isfile, basename
from tempfile import mkstemp
import zipfile

from olefile import OleFileIO

try:
    import msoffcrypto
except ImportError:
    msoffcrypto = None

# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from oletools.common.errors import CryptoErrorBase, WrongEncryptionPassword, \
    UnsupportedEncryptionError, MaxCryptoNestingReached, CryptoLibNotImported, \
    CorruptedEncryptionError, MaxDecryptionAttemptsReached
from oletools.common.log_helper import log_helper


#: if there is an encrypted file embedded in an encrypted file,
#: how deep down do we go
MAX_NESTING_DEPTH = 10

#: how many password attempts may be spent while decrypting one document
#: (all layers together).  This is deliberately independent of the number of
#: nesting levels: callers can cap work even for highly nested documents.
MAX_DECRYPT_ATTEMPTS = 100

# === LOGGING =================================================================

# a global logger object used for debugging:
log = log_helper.get_or_create_silent_logger('crypto')


def enable_logging():
    """
    Enable logging for this module (disabled by default).

    For use by third-party libraries that import `crypto` as module.

    This will set the module-specific logger level to NOTSET, which
    means the main application controls the actual logging level.
    """
    log.setLevel(log_helper.NOTSET)


def is_encrypted(some_file):
    """
    Determine whether document contains encrypted content.

    This should return False for documents that are just write-protected or
    signed or finalized. It should return True if ANY content of the file is
    encrypted and can therefore not be analyzed by other oletools modules
    without given a password.

    Exception: there are way to write-protect an office document by embedding
    it as encrypted stream with hard-coded standard password into an otherwise
    empty OLE file. From an office user point of view, this is no encryption,
    but regarding file structure this is encryption, so we return `True` for
    these.

    This should not raise exceptions needlessly.

    This implementation is rather simple: it returns True if the file contains
    streams with typical encryption names (c.f. [MS-OFFCRYPTO]). It does not
    test whether these streams actually contain data or whether the ole file
    structure contains the necessary references to these. It also checks the
    "well-known property" PIDSI_DOC_SECURITY if the SummaryInformation stream
    is accessible (c.f. [MS-OLEPS] 2.25.1)

    :param some_file: File name or an opened OleFileIO
    :type some_file: :py:class:`olefile.OleFileIO` or `str`
    :returns: True if (and only if) the file contains encrypted content
    """
    # ask msoffcrypto if possible
    if check_msoffcrypto():
        log.debug('Checking for encryption using msoffcrypto')
        file_handle = None
        file_pos = None
        try:
            if isinstance(some_file, OleFileIO):
                # TODO: hacky, replace once msoffcrypto-tools accepts OleFileIO
                file_handle = some_file.fp
                file_pos = file_handle.tell()
                file_handle.seek(0)
            elif hasattr(some_file, 'read') and hasattr(some_file, 'seek'):
                file_handle = some_file
                file_pos = file_handle.tell()
                file_handle.seek(0)
            else:
                file_handle = open(some_file, 'rb')

            return msoffcrypto.OfficeFile(file_handle).is_encrypted()

        except Exception as exc:
            # TODO: this triggers unnecessary warnings for non OLE files
            log.info('msoffcrypto failed to parse file or determine '
                        'whether it is encrypted: {}'
                        .format(exc))
            # TODO: here we are ignoring some exceptions that should be raised, for example
            #       "unknown file format" for Excel 5.0/95 files

        finally:
            try:
                if file_pos is not None:   # input was OleFileIO or file-like
                    file_handle.seek(file_pos)
                else:                      # input was file name
                    file_handle.close()
            except Exception as exc:
                log.warning('Ignoring error during clean up: {}'.format(exc))

    # if that failed, try ourselves with older and less accurate code
    try:
        if isinstance(some_file, OleFileIO):
            return _is_encrypted_ole(some_file)
        if zipfile.is_zipfile(some_file):
            return _is_encrypted_zip(some_file)
        # otherwise assume it is the name of an ole file
        with OleFileIO(some_file) as ole:
            return _is_encrypted_ole(ole)
    except Exception as exc:
        # TODO: this triggers unnecessary warnings for non OLE files
        log.info('Failed to check {} for encryption ({}); assume it is not '
                    'encrypted.'.format(some_file, exc))

    return False


def _is_encrypted_zip(filename):
    """Specialization of :py:func:`is_encrypted` for zip-based files."""
    log.debug('Checking for encryption in zip file')
    # TODO: distinguish OpenXML from normal zip files
    # try to decrypt a few bytes from first entry
    with zipfile.ZipFile(filename, 'r') as zipper:
        first_entry = zipper.infolist()[0]
        try:
            with zipper.open(first_entry, 'r') as reader:
                reader.read(min(16, first_entry.file_size))
            return False
        except RuntimeError as rt_err:
            return 'crypt' in str(rt_err)


def _is_encrypted_ole(ole):
    """Specialization of :py:func:`is_encrypted` for ole files."""
    log.debug('Checking for encryption in OLE file')
    # check well known property for password protection
    # (this field may be missing for Powerpoint2000, for example)
    # TODO: check whether password protection always implies encryption. Could
    #       write-protection or signing with password trigger this as well?
    if ole.exists("\x05SummaryInformation"):
        suminfo_data = ole.getproperties("\x05SummaryInformation")
        if 0x13 in suminfo_data and (suminfo_data[0x13] & 1):
            return True

    # check a few stream names
    # TODO: check whether these actually contain data and whether other
    # necessary properties exist / are set
    if ole.exists('EncryptionInfo'):
        log.debug('found stream EncryptionInfo')
        return True
    # or an encrypted ppt file
    if ole.exists('EncryptedSummary') and \
            not ole.exists('SummaryInformation'):
        return True

    # Word-specific old encryption:
    if ole.exists('WordDocument'):
        # check for Word-specific encryption flag:
        stream = None
        try:
            stream = ole.openstream(["WordDocument"])
            # pass header 10 bytes
            stream.read(10)
            # read flag structure:
            temp16 = struct.unpack("H", stream.read(2))[0]
            f_encrypted = (temp16 & 0x0100) >> 8
            if f_encrypted:
                return True
        finally:
            if stream is not None:
                stream.close()

    # no indication of encryption
    return False


#: one way to achieve "write protection" in Excel files is to encrypt the file
#: using this password
# ref: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/6b4a08cb-195a-442e-b31c-7c94624a8c29#Appendix_A_25
# ref: https://twitter.com/BouncyHat/status/1308897568773083138
EXCEL_TRANSPARENT_PASSWORD = 'VelvetSweatshop'

# PowerPoint password which is transparent for the user:
# ref: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/57fc02f0-c1de-4fc6-908f-d146104662f5
# ref: https://twitter.com/BouncyHat/status/1308897932389896192
POWERPOINT_TRANSPARENT_PASSWORD = '/01Hannes Ruescher/01'

#: list of common passwords to be tried by default, used by malware
DEFAULT_PASSWORDS = [EXCEL_TRANSPARENT_PASSWORD, POWERPOINT_TRANSPARENT_PASSWORD,
                     '123', '1234', '12345', '123456', '4321']


# === DECRYPTION REPORT =======================================================

# Outcomes used in :class:`DecryptionLayer`
OUTCOME_ANALYZED = 'analyzed'
OUTCOME_DECRYPTED = 'decrypted'            # decrypted, but not possible to analyze here
OUTCOME_WRONG_PASSWORD = 'wrong_password'
OUTCOME_UNSUPPORTED = 'unsupported_algorithm'
OUTCOME_CORRUPT = 'corrupt'
OUTCOME_NESTING_LIMIT = 'nesting_limit'
OUTCOME_ATTEMPT_LIMIT = 'attempt_limit'
OUTCOME_NOT_ENCRYPTED = 'not_encrypted'
OUTCOME_UNKNOWN = 'unknown_error'


def _digest(data):
    """Return a short, stable content digest for in-memory container data."""
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    try:
        return hashlib.sha256(data).hexdigest()
    except TypeError:
        return None


def _file_digest(filename):
    """Return the content digest of a file on disk, or None if unreadable."""
    digest = hashlib.sha256()
    try:
        with open(filename, 'rb') as reader:
            for block in iter(lambda: reader.read(65536), b''):
                digest.update(block)
        return digest.hexdigest()
    except (IOError, OSError, TypeError):
        return None


def _classify_exception(exc):
    """Map a decrypting-library failure to one of the ``OUTCOME_*`` values.

    Only the exception type and a normalized message are considered; the
    returned outcome never contains a password or payload bytes.
    """
    if exc is None:
        return OUTCOME_UNKNOWN
    if isinstance(exc, MaxCryptoNestingReached):
        return OUTCOME_NESTING_LIMIT
    if isinstance(exc, MaxDecryptionAttemptsReached):
        return OUTCOME_ATTEMPT_LIMIT
    if isinstance(exc, UnsupportedEncryptionError):
        return OUTCOME_UNSUPPORTED
    if isinstance(exc, CorruptedEncryptionError):
        return OUTCOME_CORRUPT
    if isinstance(exc, WrongEncryptionPassword):
        return OUTCOME_WRONG_PASSWORD
    if isinstance(exc, CryptoLibNotImported):
        return OUTCOME_UNSUPPORTED

    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if 'invalidkey' in name or 'invalid key' in message:
        return OUTCOME_WRONG_PASSWORD
    if 'unsupported encryption' in message or 'extensible' in message \
            or 'not yet supported' in message:
        return OUTCOME_UNSUPPORTED
    if 'unrecognized file format' in message or \
            'unsupported file format' in message:
        # The bytes are not a readable Office container; for a file that
        # claimed to be encrypted this is a structural problem.
        return OUTCOME_CORRUPT
    if 'parse' in name or 'fileformat' in name or 'corrupt' in message \
            or 'malformed' in message or 'truncated' in message \
            or 'cannot be parsed' in message or 'incomplete' in message \
            or 'unsupported file format' in message:
        if 'unsupported encryption' in message:
            return OUTCOME_UNSUPPORTED
        return OUTCOME_CORRUPT
    if 'decryptionerror' in name:
        return OUTCOME_CORRUPT
    return OUTCOME_UNKNOWN


def _short_exception(exc):
    """Return a sanitized one-line description of a decryption failure."""
    text = str(exc or '')
    # Keep the report useful without echoing arbitrary library output.
    text = ' '.join(text.split())
    if len(text) > 160:
        text = text[:157] + '...'
    return text


def _container_kind(filename=None, data=None):
    """Best-effort container name for the report (never includes a password)."""
    source = data
    if source is None and filename:
        try:
            with open(filename, 'rb') as reader:
                source = reader.read(8)
        except (IOError, OSError, TypeError):
            source = None
    if source:
        head = source[:8]
        if head.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            return 'ole'
        if head.startswith(b'PK\x03\x04'):
            return 'zip'
        if head.startswith(b'{\\rtf'):
            return 'rtf'
    if filename:
        ext = splitext(filename)[1].lower()
        if ext:
            return ext.lstrip('.')
    return 'unknown'


class DecryptionLayer(object):
    """One layer of a (possibly nested) decryption attempt.

    All fields are safe for diagnostic output: they contain no password and no
    decrypted bytes, only identities and status.
    """

    def __init__(self, depth, container=None, identity=None, source=None,
                 encrypted=None):
        self.depth = depth
        self.container = container or 'unknown'
        self.identity = identity
        self.source = source
        self.encrypted = encrypted
        self.outcome = OUTCOME_UNKNOWN
        self.password_index = None
        self.attempts = 0
        self.detail = None
        self.analysis_complete = None

    @property
    def decrypted(self):
        return self.outcome in (OUTCOME_ANALYZED, OUTCOME_DECRYPTED)

    @property
    def analyzable(self):
        return self.outcome == OUTCOME_ANALYZED and self.analysis_complete is not False

    @property
    def stopped(self):
        return self.outcome not in (OUTCOME_ANALYZED, OUTCOME_DECRYPTED,
                                    OUTCOME_NOT_ENCRYPTED)

    def to_dict(self):
        result = {
            'depth': self.depth,
            'container': self.container,
            'identity': self.identity,
            'encrypted': self.encrypted,
            'outcome': self.outcome,
            'decrypted': self.decrypted,
            'analyzable': self.analyzable,
            'attempts': self.attempts,
        }
        if self.source:
            # Display name only; identity above is what actually distinguishes
            # same-named containers.
            result['source'] = self.source
        if self.password_index is not None:
            # Only the candidate's position is exposed, never its value.
            result['password_index'] = self.password_index
        if self.detail:
            result['detail'] = self.detail
        if self.analysis_complete is not None:
            result['analysis_complete'] = self.analysis_complete
        return result

    def __repr__(self):
        return '<DecryptionLayer depth={0.depth} container={0.container!r} ' \
               'outcome={0.outcome!r}>'.format(self)


class DecryptionReport(object):
    """Per-invocation record of nested decryption.

    A new report must be created for every top-level document.  It intentionally
    holds no module-level cache, so a repeated call can never inherit state from
    a previous document.
    """

    def __init__(self, max_nesting=MAX_NESTING_DEPTH,
                 max_attempts=MAX_DECRYPT_ATTEMPTS):
        self.max_nesting = max_nesting
        self.max_attempts = max_attempts
        self.layers = []
        self.attempts = 0
        self.attempted_keys = set()
        self.stopped_at = None
        self.stopped_reason = None
        self.complete = True

    # -- bookkeeping -----------------------------------------------------
    def add_layer(self, layer):
        self.layers.append(layer)
        return layer

    def note_attempt(self, identity, password_index):
        """Count one password attempt; return False if the budget is exhausted."""
        if self.attempts >= self.max_attempts:
            return False
        self.attempts += 1
        if identity is not None:
            self.attempted_keys.add((identity, password_index))
        return True

    def already_attempted(self, identity, password_index):
        """True if this identity/candidate pair was tried in this invocation.

        Without a content identity we cannot safely deduplicate: two documents
        with the same name may contain different bytes, so an attempt for one
        must not suppress the other.
        """
        if identity is None:
            return False
        return (identity, password_index) in self.attempted_keys

    def stop(self, depth, reason, detail=None, layer=None):
        """Record the layer where processing stopped and mark the run partial."""
        self.complete = False
        if self.stopped_at is None:
            self.stopped_at = depth
            self.stopped_reason = reason
            self.stopped_detail = detail
        if layer is None:
            # Fall back to depth matching; callers that know the exact
            # container should pass it so same-depth layers stay distinct.
            for candidate in reversed(self.layers):
                if candidate.depth == depth:
                    layer = candidate
                    break
        if layer is not None and detail:
            layer.detail = detail
        return layer

    def mark_stopped_from_exception(self, exc):
        outcome = getattr(exc, 'outcome', None) or _classify_exception(exc)
        layer = getattr(exc, 'layer', None)
        depth = layer.depth if layer is not None else (len(self.layers) - 1)
        self.stop(depth, outcome, getattr(exc, 'detail', None), layer=layer)

    # -- summaries -------------------------------------------------------
    @property
    def success(self):
        return self.complete and all(layer.outcome in
                                     (OUTCOME_ANALYZED, OUTCOME_NOT_ENCRYPTED)
                                     for layer in self.layers)

    def to_dict(self):
        result = {
            'complete': self.complete,
            'success': self.success,
            'max_depth': self.max_nesting,
            'max_attempts': self.max_attempts,
            'attempts': self.attempts,
            'layer_count': len(self.layers),
            'layers': [layer.to_dict() for layer in self.layers],
        }
        if self.stopped_at is not None:
            result['stopped_at'] = self.stopped_at
            result['stopped_reason'] = self.stopped_reason
            if getattr(self, 'stopped_detail', None):
                result['stopped_detail'] = self.stopped_detail
        return result

    def __repr__(self):
        return '<DecryptionReport layers={0} attempts={1} complete={2}>' \
            .format(len(self.layers), self.attempts, self.complete)


# === DECRYPTION CONTEXT ======================================================


class DecryptionContext(object):
    """State shared by all layers of one top-level analysis.

    Pass the same context through recursive ``process_maybe_encrypted`` /
    ``process_file`` calls.  It bounds depth and password attempts, and owns
    the report that describes which layer was decrypted and which was not.
    """

    def __init__(self, report=None, max_nesting=None, max_attempts=None):
        if report is None:
            report = DecryptionReport(
                max_nesting=max_nesting or MAX_NESTING_DEPTH,
                max_attempts=max_attempts or MAX_DECRYPT_ATTEMPTS)
        self.report = report
        self.active_depth = 0
        self._temp_files = []

    # -- temp file hygiene -----------------------------------------------
    def register_temp_file(self, path):
        if path:
            self._temp_files.append(path)
        return path

    def forget_temp_file(self, path):
        """Stop tracking a temp file (e.g. after the caller removed it)."""
        try:
            self._temp_files.remove(path)
        except (ValueError, AttributeError):
            pass

    def cleanup_temp_files(self):
        """Remove any plaintext temp files still tracked by this context."""
        for path in list(self._temp_files):
            try:
                if path and isfile(path):
                    os.unlink(path)
            except OSError:
                log.debug('Could not remove temp file', exc_info=True)
            finally:
                try:
                    self._temp_files.remove(path)
                except ValueError:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup_temp_files()
        return False

    # -- reporting -------------------------------------------------------
    def stop(self, depth, reason, detail=None, layer=None):
        """Record where processing stopped and mark the whole run partial."""
        self.report.stop(depth, reason, detail, layer=layer)

    def attempt_password(self, identity, password_index, filename=None):
        """Consume one attempt; raise when the attempt budget is exceeded."""
        if not self.report.note_attempt(identity, password_index):
            exc = MaxDecryptionAttemptsReached(self.report.max_attempts,
                                               filename)
            exc.attach_report(self.report, outcome=OUTCOME_ATTEMPT_LIMIT)
            raise exc
        return True


@contextmanager
def decryption_context(report=None, max_nesting=None, max_attempts=None):
    """Context manager creating and cleaning up a :class:`DecryptionContext`."""
    context = DecryptionContext(report=report, max_nesting=max_nesting,
                                max_attempts=max_attempts)
    try:
        yield context
    finally:
        context.cleanup_temp_files()


def _check_msoffcrypto():
    """Raise a :py:class:`CryptoLibNotImported` if msoffcrypto not imported."""
    if msoffcrypto is None:
        raise CryptoLibNotImported()


def check_msoffcrypto():
    """Return `True` iff :py:mod:`msoffcrypto` could be imported."""
    return msoffcrypto is not None


class _PasswordRedactionFilter(logging.Filter):
    """Drop password material from third-party log records during decryption."""

    def __init__(self, secrets):
        super(_PasswordRedactionFilter, self).__init__()
        self.secrets = tuple(secret for secret in secrets
                             if isinstance(secret, str) and secret)

    def filter(self, record):
        if not self.secrets:
            return True
        try:
            message = record.getMessage()
        except Exception:
            return True
        for secret in self.secrets:
            if secret in message:
                record.msg = '[redacted log message containing a password]'
                record.args = ()
                break
        return True


def _normalize_passwords(passwords):
    """Return a list of password candidates without modifying the input."""
    if isinstance(passwords, str):
        return [passwords]
    if not passwords:
        return list(DEFAULT_PASSWORDS)
    return list(passwords)


def _open_crypto_file(reader, filename):
    """Create an msoffcrypto file object, mapping format failures to our errors."""
    try:
        return msoffcrypto.OfficeFile(reader)
    except Exception as exc:
        outcome = _classify_exception(exc)
        if outcome == OUTCOME_UNSUPPORTED:
            log.debug('Unsupported encryption while opening file')
            raise UnsupportedEncryptionError(filename, _short_exception(exc))
        if outcome == OUTCOME_CORRUPT:
            log.debug('Corrupt container while opening file')
            raise CorruptedEncryptionError(filename, _short_exception(exc))
        raise


#: magic signatures a successfully decrypted Office payload may start with
_CONTAINER_MAGIC = (
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',   # OLE / nested encrypted container
    b'PK\x03\x04',                               # OOXML / zip
    b'{\\rtf',                                   # RTF
)


def _looks_like_document(data):
    """True if data begins with a recognizable Office container header."""
    if not data:
        return False
    return any(data.startswith(magic) for magic in _CONTAINER_MAGIC)


def _decrypt_ooxml_payload(crypto_file, verified_password):
    """Decrypt an OOXML payload, returning the plaintext bytes.

    ``msoffcrypto``'s own OOXML decryptor rejects payloads that are not zip
    files.  A nested encrypted container is, however, a valid payload: it is
    an OLE file that must be decrypted again.  Therefore the low-level cipher
    is used here.

    If the password verifier could be checked, the output is trusted to be the
    real plaintext.  If the document has a broken verifier (some transparently
    encrypted files do), the output must at least look like an Office
    container before it is accepted.
    """
    if crypto_file.type == 'agile':
        from msoffcrypto.method.ecma376_agile import ECMA376Agile
        with crypto_file.file.openstream('EncryptedPackage') as stream:
            plaintext = ECMA376Agile.decrypt(
                crypto_file.secret_key,
                crypto_file.info['keyDataSalt'],
                crypto_file.info['keyDataHashAlgorithm'],
                stream)
    elif crypto_file.type == 'standard':
        from msoffcrypto.method.ecma376_standard import ECMA376Standard
        with crypto_file.file.openstream('EncryptedPackage') as stream:
            plaintext = ECMA376Standard.decrypt(crypto_file.secret_key, stream)
    else:
        raise UnsupportedEncryptionError(detail='encryption type {!r}'
                                         .format(crypto_file.type))

    if not verified_password and not _looks_like_document(plaintext):
        raise WrongEncryptionPassword('The file could not be decrypted with '
                                      'this password')
    return plaintext


def _decrypt_with_password(crypto_file, password, write_handle):
    """Load a key and write decrypted bytes; raises on failure."""
    verified_password = False
    try:
        crypto_file.load_key(password=password, verify_password=True)
        verified_password = True
    except TypeError as exc:
        # Older msoffcrypto format handlers verify the password inside
        # load_key and do not accept `verify_password`.
        if 'verify_password' not in str(exc):
            raise
        crypto_file.load_key(password=password)
        verified_password = True
    except CorruptedEncryptionError:
        raise
    except Exception as exc:
        # Some valid documents (notably transparently encrypted ones) have
        # an unusable verifier. Fall back to the legacy behaviour and decide
        # correctness from the decrypted payload instead.
        if _classify_exception(exc) != OUTCOME_WRONG_PASSWORD:
            raise
        crypto_file.load_key(password=password)

    if type(crypto_file).__name__ == 'OOXMLFile':
        plaintext = _decrypt_ooxml_payload(crypto_file, verified_password)
        write_handle.write(plaintext)
    else:
        crypto_file.decrypt(write_handle)


def decrypt(filename, passwords=None, decrypted_dir=None, context=None,
            report=None, depth=None, identity=None, container=None,
            **temp_file_args):
    """
    Try to decrypt an encrypted file

    This function tries to decrypt the given file using a given set of
    passwords. If no password is given, tries the standard password for write
    protection. Creates a file with decrypted data whose file name is returned.
    If the decryption fails, None is returned.

    All attempts for a (possibly nested) document are bounded by an optional
    :class:`DecryptionContext`.  Pass the same context to every layer; it
    records which containers were decrypted and which could not be analyzed.
    Password candidates are identified by index only, and neither passwords
    nor decrypted bytes are logged.

    :param str filename: path to an ole file on disc
    :param passwords: list/set/tuple/... of passwords or a single password or
                      None
    :type passwords: iterable or str or None
    :param temp_file_args: arguments for :py:func:`tempfile.mkstemp` e.g.,
                           `dirname` or `prefix`. `suffix` will default to
                           suffix of input `filename`, `prefix` defaults to
                           `oletools-decrypt-`; `text` will be ignored
    :param decrypted_dir: folder to store the decrypted file in case you want
                            to preserve it
    :param context: optional :class:`DecryptionContext` shared across layers.
                    Created implicitly (and discarded) when omitted.
    :param report: optional :class:`DecryptionReport` shorthand for `context`.
    :param depth: nesting depth used in the report (default: context depth).
    :param identity: optional pre-computed content digest; must identify the
                     actual bytes, not just a filename.
    :param container: optional container type hint for the report.
    :returns: a tuple with the name of the decrypted temporary file (type str) or `None`
              and the correct password or 'None'
    :raises: :py:class:`ImportError` if :py:mod:`msoffcrypto-tools` not found
    :raises: :py:class:`ValueError` if the given file is not encrypted
    """
    _check_msoffcrypto()

    if context is None:
        context = DecryptionContext(report=report)

    if depth is None:
        depth = context.active_depth
    if identity is None:
        identity = identify(filename)

    layer = _layer_for(context, depth, filename, identity, container)
    if layer is not None and layer.outcome in (None, OUTCOME_UNKNOWN):
        # Only reset bookkeeping for a layer that has not been concluded yet;
        # otherwise this is a repeat call for the same container.
        layer.attempts = 0

    passwords = _normalize_passwords(passwords)

    # check temp file args
    if 'prefix' not in temp_file_args:
        temp_file_args['prefix'] = 'oletools-decrypt-'
    if 'suffix' not in temp_file_args:
        temp_file_args['suffix'] = splitext(filename)[1] \
            if isinstance(filename, str) else ''
    temp_file_args['text'] = False

    redaction = _PasswordRedactionFilter(passwords)
    msoffcrypto_logger = logging.getLogger('msoffcrypto')
    msoffcrypto_logger.addFilter(redaction)
    oletools_logger = logging.getLogger('oletools')
    oletools_logger.addFilter(redaction)

    decrypt_file = None
    correct_password = None
    unsupported_error = None
    corrupt_error = None
    try:
        reader = open(filename, 'rb')
    except (IOError, OSError) as exc:
        context.cleanup_temp_files()
        raise CorruptedEncryptionError(filename, type(exc).__name__)

    try:
        try:
            crypto_file = _open_crypto_file(reader, filename)
        except CryptoErrorBase as exc:
            if layer is not None:
                layer.outcome = _classify_exception(exc)
                layer.detail = _short_exception(exc)
            exc.attach_report(context.report, layer,
                              outcome=_classify_exception(exc))
            raise
        except Exception as exc:
            if layer is not None:
                layer.outcome = OUTCOME_CORRUPT
                layer.detail = _short_exception(exc)
            error = CorruptedEncryptionError(filename, type(exc).__name__)
            error.attach_report(context.report, layer, outcome=OUTCOME_CORRUPT)
            raise error

        try:
            is_encrypted = crypto_file.is_encrypted()
        except Exception as exc:
            is_encrypted = False
            if layer is not None:
                layer.outcome = OUTCOME_CORRUPT
                layer.detail = _short_exception(exc)

        if layer is not None:
            layer.encrypted = bool(is_encrypted)
        if not is_encrypted:
            if layer is not None:
                layer.outcome = OUTCOME_NOT_ENCRYPTED
            raise ValueError('Given input file {} is not encrypted!'
                             .format(filename))

        for password_index, password in enumerate(passwords):
            if context.report.already_attempted(identity, password_index):
                log.debug('Skipping previously attempted password %d for '
                          'container %s', password_index, identity)
                continue

            # Raising here preserves the attempt budget; no temp file exists.
            context.attempt_password(identity, password_index, filename)
            if layer is not None:
                layer.attempts += 1

            log.debug('Trying password candidate %d for container %s',
                      password_index, identity)
            write_descriptor = None
            write_handle = None
            candidate_file = None
            try:
                write_descriptor, candidate_file = mkstemp(**temp_file_args)
                context.register_temp_file(candidate_file)
                write_handle = os.fdopen(write_descriptor, 'wb')
                write_descriptor = None

                _decrypt_with_password(crypto_file, password, write_handle)

                write_handle.close()
                write_handle = None
                decrypt_file = candidate_file
                correct_password = password
                if layer is not None:
                    layer.outcome = OUTCOME_DECRYPTED
                    layer.password_index = password_index
                    layer.detail = None
                break
            except MaxDecryptionAttemptsReached:
                raise
            except Exception as exc:
                log.debug('Password candidate %d failed for container %s (%s)',
                          password_index, identity, _classify_exception(exc))

                if write_handle:
                    write_handle.close()
                    write_handle = None
                elif write_descriptor is not None:
                    os.close(write_descriptor)
                    write_descriptor = None
                if candidate_file and isfile(candidate_file):
                    try:
                        os.unlink(candidate_file)
                    except OSError:
                        log.debug('Could not remove failed temp file',
                                  exc_info=True)
                context.forget_temp_file(candidate_file)

                outcome = _classify_exception(exc)
                if outcome == OUTCOME_UNSUPPORTED:
                    unsupported_error = exc
                    break
                if outcome == OUTCOME_CORRUPT and \
                        'could not be decrypted' not in str(exc).lower():
                    corrupt_error = exc
                    break
                # A wrong password is the expected failure for a candidate.
    finally:
        try:
            reader.close()
        except Exception:
            pass
        msoffcrypto_logger.removeFilter(redaction)
        oletools_logger.removeFilter(redaction)
        if decrypt_file is None:
            # Failure or budget exception: never leave plaintext behind.
            context.cleanup_temp_files()

    if decrypt_file and correct_password:
        log.debug('Decrypted container %s using password candidate %d',
                  identity, layer.password_index if layer else -1)
        if decrypted_dir:
            if os.path.isdir(decrypted_dir) and os.access(decrypted_dir, os.W_OK):
                log.info('Saving decrypted file in: %s', decrypted_dir)
                shutil.copy(decrypt_file, decrypted_dir)
    else:
        if unsupported_error is not None:
            outcome = OUTCOME_UNSUPPORTED
            detail = _short_exception(unsupported_error)
        elif corrupt_error is not None:
            outcome = OUTCOME_CORRUPT
            detail = _short_exception(corrupt_error)
        else:
            outcome = OUTCOME_WRONG_PASSWORD
            detail = 'no password candidate matched'
        if layer is not None:
            layer.outcome = outcome
            layer.detail = detail
        context.stop(depth, outcome, detail)
        log.info('All password candidates failed for container %s', identity)

    return decrypt_file, correct_password


def mark_layer_analyzed(context, depth, complete=True, identity=None):
    """Mark a decrypted layer as fully analyzed.

    Called by tools once they have processed the decrypted payload (possibly
    after recursively peeling more layers).
    """
    if context is None:
        return None
    layer = get_layer(context, depth, identity=identity)
    layer.analysis_complete = bool(complete)
    if complete:
        layer.outcome = OUTCOME_ANALYZED
    else:
        # The payload was decrypted, but processing stopped in a deeper
        # layer; report it as decrypted-only so callers do not mistake it
        # for fully analyzed content.
        layer.outcome = OUTCOME_DECRYPTED
        context.report.complete = False
    return layer


def identify(filename):
    """Return the content identity (SHA-256) of a file or file-like object."""
    try:
        if hasattr(filename, 'read') and hasattr(filename, 'seek'):
            position = filename.tell()
            filename.seek(0)
            identity = _digest(filename.read())
            filename.seek(position)
            return identity
        return _file_digest(filename)
    except Exception:
        return None


def layer_for(context, depth, filename):
    """Return the report layer bound to this actual file content."""
    if context is None:
        return None
    identity = identify(filename)
    if identity is None:
        return get_layer(context, depth)
    for layer in reversed(context.report.layers):
        if layer.depth == depth and layer.identity == identity:
            return layer
    return None


def _layer_for(context, depth, filename, identity, container):
    """Find or create the report layer for the current container.

    Layers are matched by depth *and* content identity.  Two different inner
    containers that happen to share a display name therefore never share a
    layer (or its attempt bookkeeping).
    """
    if context is None:
        return None
    for layer in reversed(context.report.layers):
        if layer.depth == depth and layer.identity == identity:
            return layer
    source = None
    if isinstance(filename, str):
        name = basename(filename)
        # Do not report random temp-file names created by an outer decryption
        # step; they would look like meaningful document names.
        if not name.startswith('oletools-decrypt-'):
            source = name
    return context.report.add_layer(DecryptionLayer(
        depth=depth,
        container=container or _container_kind(filename),
        identity=identity,
        source=source,
        encrypted=True))


def get_layer(context, depth, identity=None):
    """Return the report layer for `depth` (and optional identity).

    When identity is given, only a layer bound to the same actual container is
    returned; same-named documents with different content are kept apart.
    """
    if context is None:
        return None
    for layer in reversed(context.report.layers):
        if layer.depth == depth and (identity is None or
                                     layer.identity == identity):
            return layer
    return context.report.add_layer(DecryptionLayer(depth=depth))



