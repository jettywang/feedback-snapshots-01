#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
import datetime
import hashlib
import sys
import unittest

from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc4055
from pyasn1_modules import rfc6486
from pyasn1_modules import rfc6486_manifest_view


CHECKED_AT = '20261115000000Z'
THIS_UPDATE = '20261114000000Z'
NEXT_UPDATE = '20261121000000Z'


def sha256(content):
    return hashlib.sha256(content).digest()


def make_manifest(number, files, hash_alg=rfc4055.id_sha256,
                  this_update=THIS_UPDATE, next_update=NEXT_UPDATE,
                  version=None):
    manifest = rfc6486.Manifest()
    if version is not None:
        manifest['version'] = version
    manifest['manifestNumber'] = number
    manifest['thisUpdate'] = this_update
    manifest['nextUpdate'] = next_update
    manifest['fileHashAlg'] = hash_alg

    file_list = manifest['fileList'].clone()
    file_list.clear()
    for name, digest in files:
        entry = file_list.componentType.clone()
        entry['file'] = name
        entry['hash'] = digest
        file_list.append(entry)
    manifest['fileList'] = file_list
    return manifest


def encode_manifest(manifest):
    return der_encoder(manifest)


def digest_bitstring(content, bytes_only=False):
    if bytes_only:
        return univ.BitString.fromOctetString(sha256(content))
    return univ.BitString.fromOctetString(sha256(content))


class ManifestHelperMixin(object):
    authority = b'authority ee certificate'
    crl1 = b'crl generation one'
    crl2 = b'crl generation two'
    obj1 = b'signed object generation one'
    obj2 = b'signed object generation two'

    def generation_one(self, number=1):
        return encode_manifest(make_manifest(number, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ]))

    def generation_two(self, number=2):
        return encode_manifest(make_manifest(number, [
            ('a.cer', digest_bitstring(self.authority)),
            ('crl.cer', digest_bitstring(self.crl2)),
            ('n.cer', digest_bitstring(self.obj2)),
        ]))

    def directory_one(self):
        return {'a.cer': self.authority, 'b.cer': self.obj1,
                'crl.cer': self.crl1}

    def directory_two(self):
        return {'a.cer': self.authority, 'crl.cer': self.crl2,
                'n.cer': self.obj2}

    def interleaved(self):
        # b.cer only exists in generation one; crl.cer only in two.
        return {'a.cer': self.authority, 'b.cer': self.obj1,
                'crl.cer': self.crl2, 'n.cer': self.obj2}


class CompleteGenerationTestCase(ManifestHelperMixin, unittest.TestCase):

    def testCompleteGenerationIsConsumable(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), self.directory_one(),
            checked_at=CHECKED_AT)

        self.assertEqual('verified', view.state)
        self.assertEqual([], view.issues)
        self.assertEqual([], view.missing)
        self.assertEqual([], view.extra)
        self.assertEqual(self.directory_one(), view.files)
        self.assertEqual(
            ['a.cer', 'b.cer', 'crl.cer'], sorted(view.files))

    def testUnlistedCandidateIsNotTrusted(self):
        candidates = dict(self.directory_one())
        candidates['unlisted.cer'] = b'smuggled object'

        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), candidates, checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertNotIn('unlisted.cer', view.files)
        self.assertEqual({}, view.files)
        self.assertEqual(['unlisted.cer'], view.extra)
        self.assertEqual(
            ['directory_extra_file'],
            [issue.code for issue in view.issues])

    def testEmptyFileListIsRejected(self):
        payload = encode_manifest(make_manifest(1, []))

        view = rfc6486_manifest_view.evaluate(
            payload, {}, checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual(
            ['manifest_filelist_empty'],
            [issue.code for issue in view.issues])


class InterleavedSyncTestCase(ManifestHelperMixin, unittest.TestCase):

    def testInterleavedFilesAreEachLegitimateButGenerationIsNot(self):
        directory = self.interleaved()

        one = rfc6486_manifest_view.evaluate(
            self.generation_one(), directory, checked_at=CHECKED_AT)
        two = rfc6486_manifest_view.evaluate(
            self.generation_two(), directory, checked_at=CHECKED_AT)

        # Every present file is individually valid under one of them...
        self.assertTrue(
            all(content in (self.authority, self.crl2, self.obj2,
                            self.obj1)
                for content in directory.values()))

        # ...but neither manifest covers the whole directory.
        self.assertEqual('rejected', one.state)
        self.assertEqual('rejected', two.state)
        self.assertEqual(['n.cer'], one.extra)
        self.assertEqual(['b.cer'], two.extra)
        self.assertEqual({}, one.files)
        self.assertEqual({}, two.files)

        generation = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one(), self.generation_two()],
            directory, checked_at=CHECKED_AT)

        self.assertEqual('rejected', generation.state)
        self.assertEqual({}, generation.files)
        self.assertIsNone(generation.consumable)
        self.assertEqual(
            {1: {'missing': [], 'extra': ['n.cer']},
             2: {'missing': [], 'extra': ['b.cer']}},
            generation.gaps)
        self.assertEqual(2, generation.current_number)
        self.assertEqual([], generation.complete_numbers)
        self.assertEqual(
            ['generation_current_manifest_incomplete'],
            [issue.code for issue in generation.issues
             if issue.code.startswith('generation_')])

    def testOlderMatchingManifestDoesNotMaskIncompleteCurrent(self):
        # The directory exactly matches generation one, but a valid
        # generation two manifest is also present.  Generation two is
        # current, so generation one must not be substituted even though
        # it would match.
        generation = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one(), self.generation_two()],
            self.directory_one(), checked_at=CHECKED_AT)

        self.assertEqual('rejected', generation.state)
        self.assertEqual({}, generation.files)
        self.assertEqual(2, generation.current_number)
        self.assertEqual([1], generation.complete_numbers)
        self.assertEqual(
            1,
            len([issue for issue in generation.issues
                 if issue.code == 'generation_current_manifest_incomplete']))

    def testSameNameDifferentContentIsNormalAcrossGenerations(self):
        # A CRL is republished under the same file name with new content.
        # This must not be treated as a manifest error; the generation
        # current-number ordering decides which one applies.
        manifest_two = make_manifest(2, [
            ('a.cer', digest_bitstring(self.authority)),
            ('n.cer', digest_bitstring(self.obj2)),
            ('crl.cer', digest_bitstring(self.crl2)),
        ])
        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest_two), self.directory_two(),
            previous=self.generation_one(), checked_at=CHECKED_AT)

        self.assertEqual('verified', view.state)
        self.assertEqual([], view.issues)

    def testDuplicateNameAcrossManifestsIsDetected(self):
        one = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])
        two = make_manifest(2, [
            ('a.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])
        generation = rfc6486_manifest_view.evaluate_generation(
            [encode_manifest(one), encode_manifest(two)],
            {'a.cer': self.authority, 'crl.cer': self.crl1},
            checked_at=CHECKED_AT)

        self.assertEqual('rejected', generation.state)
        self.assertEqual(2, generation.current_number)
        self.assertEqual(
            ['generation_current_manifest_incomplete'],
            [issue.code for issue in generation.issues])
        self.assertEqual(
            ['a.cer'],
            [issue.filename for issue in generation.views[1].issues
             if issue.code == 'directory_hash_mismatch'])

    def testGapDetailIsPreservedForCurrentManifest(self):
        generation = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one(), self.generation_two()],
            self.interleaved(), checked_at=CHECKED_AT)

        self.assertEqual(2, generation.current_number)
        self.assertEqual(
            {'missing': [], 'extra': ['b.cer']},
            generation.gaps[2])

    def testEitherCompleteGenerationIsConsumableOnItsOwn(self):
        one = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one()], self.directory_one(),
            checked_at=CHECKED_AT)
        two = rfc6486_manifest_view.evaluate_generation(
            [self.generation_two()], self.directory_two(),
            checked_at=CHECKED_AT)

        self.assertEqual('verified', one.state)
        self.assertEqual('verified', two.state)
        self.assertEqual(sorted(self.directory_one()), sorted(one.files))
        self.assertEqual(sorted(self.directory_two()), sorted(two.files))


class ManifestFieldTestCase(ManifestHelperMixin, unittest.TestCase):

    def _view(self, manifest, candidates=None, **kwargs):
        return rfc6486_manifest_view.evaluate(
            encode_manifest(manifest),
            self.directory_one() if candidates is None else candidates,
            checked_at=kwargs.pop('checked_at', CHECKED_AT), **kwargs)

    def testStaleManifest(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], next_update='20261115000000Z')

        view = self._view(manifest, checked_at='20261115000000Z')

        self.assertEqual('rejected', view.state)
        self.assertEqual('manifest_stale', view.issues[0].code)
        self.assertIn('20261115000000Z', view.issues[0].detail)

    def testFutureManifest(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], this_update='20261116000000Z')

        view = self._view(manifest)

        self.assertEqual(
            ['manifest_not_yet_current'],
            [issue.code for issue in view.issues])

    def testFractionalSecondIsNotAccepted(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], this_update='20261114000000.5Z')

        view = self._view(manifest)

        self.assertEqual(
            ['manifest_thisupdate_invalid'],
            [issue.code for issue in view.issues])

    def testVersionMustBeZero(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], version=1)

        view = self._view(manifest)

        self.assertEqual('manifest_version_invalid', view.issues[0].code)

    def testInvertedInterval(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], this_update='20261120000000Z', next_update='20261115000000Z')

        view = self._view(manifest, checked_at='20261117000000Z')

        self.assertIn(
            'manifest_interval_inverted',
            [issue.code for issue in view.issues])

    def testUnsupportedHashAlgorithm(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ], hash_alg=rfc4055.id_sha1)

        view = self._view(manifest)

        self.assertEqual(
            ['manifest_hash_alg_unsupported'],
            [issue.code for issue in view.issues])
        self.assertEqual({}, view.files)

    def testWrongHashBitStringLength(self):
        short = univ.BitString.fromOctetString(sha256(self.authority)[:16])
        manifest = make_manifest(1, [
            ('a.cer', short),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])

        view = self._view(manifest, candidates={
            'a.cer': self.authority, 'b.cer': self.obj1,
            'crl.cer': self.crl1})

        self.assertIn(
            'manifest_hash_bitstring_length',
            [issue.code for issue in view.issues])
        self.assertIn(
            'a.cer',
            [issue.filename for issue in view.issues
             if issue.code == 'manifest_hash_bitstring_length'])


class FileListTestCase(ManifestHelperMixin, unittest.TestCase):

    def testDuplicateNameWithDifferentHash(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('a.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest), self.directory_one(),
            checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual(
            'manifest_duplicate_name_conflict', view.issues[0].code)
        self.assertIn('different hash', view.issues[0].detail)

    def testDuplicateNameWithSameHash(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('a.cer', digest_bitstring(self.authority)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest),
            {'a.cer': self.authority, 'crl.cer': self.crl1},
            checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual(['manifest_duplicate_file'],
                         [issue.code for issue in view.issues])

    def testParentDirectoryTraversal(self):
        manifest = make_manifest(1, [
            ('../outside.cer', digest_bitstring(b'outside')),
            ('crl.cer', digest_bitstring(self.crl1)),
        ])

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest), {}, checked_at=CHECKED_AT)

        self.assertEqual('manifest_file_name_path', view.issues[0].code)

    def testAbsolutePathIsRejected(self):
        manifest = make_manifest(1, [
            ('/etc/passwd', digest_bitstring(b'x')),
        ])

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest), {}, checked_at=CHECKED_AT)

        self.assertEqual('manifest_file_name_path', view.issues[0].code)

    def testControlCharacterInName(self):
        manifest = make_manifest(1, [
            ('a\x00.cer', digest_bitstring(b'x')),
        ])

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest), {}, checked_at=CHECKED_AT)

        self.assertEqual('manifest_file_name_invalid', view.issues[0].code)


class DirectoryTestCase(ManifestHelperMixin, unittest.TestCase):

    def testMissingFilesAreDistinctFromExtraFiles(self):
        candidates = dict(self.directory_one())
        del candidates['b.cer']
        candidates['extra.cer'] = b'extra'

        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), candidates, checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual(['b.cer'], view.missing)
        self.assertEqual(['extra.cer'], view.extra)
        self.assertEqual(
            sorted(['directory_missing_file', 'directory_extra_file']),
            sorted(issue.code for issue in view.issues))

    def testHashMismatchKeepsNameOutOfView(self):
        candidates = dict(self.directory_one())
        candidates['crl.cer'] = b'corrupted crl'

        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), candidates, checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual(['crl.cer'],
                         [issue.filename for issue in view.issues])
        self.assertEqual('directory_hash_mismatch', view.issues[0].code)
        self.assertEqual({}, view.files)


class PreviousManifestTestCase(ManifestHelperMixin, unittest.TestCase):

    def testOlderManifestIsRejected(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), self.directory_one(),
            previous=self.generation_two(), checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertEqual('manifest_number_rollback', view.issues[0].code)
        self.assertIn('2', view.issues[0].detail)

    def testReusedNumberWithDifferentContentIsRejected(self):
        manifest = make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj1)),
            ('crl.cer', digest_bitstring(self.crl2)),
        ])
        accepted = self.generation_one()

        view = rfc6486_manifest_view.evaluate(
            encode_manifest(manifest),
            {'a.cer': self.authority, 'b.cer': self.obj1,
             'crl.cer': self.crl2},
            previous=accepted, checked_at=CHECKED_AT)

        self.assertEqual('rejected', view.state)
        self.assertIn('manifest_number_conflict',
                      [issue.code for issue in view.issues])

    def testReEvaluatingAcceptedManifestIsIdempotent(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), self.directory_one(),
            previous=self.generation_one(), checked_at=CHECKED_AT)

        self.assertEqual('verified', view.state)
        self.assertEqual([], view.issues)

    def testNewerManifestReturnsNoPreviousIssue(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_two(), self.directory_two(),
            previous=self.generation_one(), checked_at=CHECKED_AT)

        self.assertEqual('verified', view.state)
        self.assertEqual([], view.issues)


class GenerationReportingTestCase(ManifestHelperMixin, unittest.TestCase):

    def testInvalidManifestIsIgnoredButReported(self):
        stale = encode_manifest(make_manifest(
            9, [('a.cer', digest_bitstring(self.authority))],
            next_update='20261114000000Z'))

        generation = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one(), stale], self.directory_one(),
            checked_at=CHECKED_AT)

        self.assertEqual('verified', generation.state)
        self.assertEqual(1, generation.current_number)
        self.assertEqual([9], generation.ignored_invalid_numbers)
        self.assertEqual(
            ['generation_ignored_invalid_manifest'],
            [warning.code for warning in generation.warnings])

    def testDuplicateManifestNumberWithDifferentContent(self):
        changed = encode_manifest(make_manifest(1, [
            ('a.cer', digest_bitstring(self.authority)),
            ('b.cer', digest_bitstring(self.obj2)),
            ('crl.cer', digest_bitstring(self.crl1)),
        ]))

        generation = rfc6486_manifest_view.evaluate_generation(
            [self.generation_one(), changed], self.directory_one(),
            checked_at=CHECKED_AT)

        self.assertEqual('rejected', generation.state)
        self.assertIsNone(generation.current_number)
        self.assertEqual(
            ['generation_duplicate_manifest_number'],
            [issue.code for issue in generation.issues])

    def testNonAsciiDigitsAreNotATime(self):
        # Fullwidth digits look like a timestamp to Unicode-aware regexes.
        # RFC 5280 requires ASCII digits, so the parser must refuse them.
        with self.assertRaises(ValueError):
            rfc6486_manifest_view.parse_time(
                '\uff12\uff10\uff12\uff16\uff11\uff11\uff11\uff14'
                '\uff10\uff10\uff10\uff10\uff10\uff10Z')

    def testOffsetAndMissingZoneAreNotTimes(self):
        for value in ('202611140000+0100', '20261114000000',
                      '20261114000000.5Z', '2026111400000Z'):
            with self.assertRaises(ValueError):
                rfc6486_manifest_view.parse_time(value)


class SignatureTestCase(ManifestHelperMixin, unittest.TestCase):

    def testSignatureFailureIsItsOwnState(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_one(), self.directory_one(),
            checked_at=CHECKED_AT, signature_valid=False)

        self.assertEqual('signature_invalid', view.state)
        self.assertEqual('manifest_signature_invalid', view.issues[0].code)
        self.assertEqual({}, view.files)
        self.assertEqual([], view.missing)
        self.assertEqual([], view.extra)


class DecodingTestCase(ManifestHelperMixin, unittest.TestCase):

    def testTrailingOctetsAreRejected(self):
        view = rfc6486_manifest_view.evaluate(
            self.generation_one() + b'\x00', self.directory_one(),
            checked_at=CHECKED_AT)

        self.assertEqual('undecodable', view.state)
        self.assertIn('trailing octets', view.issues[0].detail)

    def testGarbageIsRejected(self):
        view = rfc6486_manifest_view.evaluate(
            b'not der', self.directory_one(), checked_at=CHECKED_AT)

        self.assertEqual('undecodable', view.state)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestLoader().loadTestsFromModule(sys.modules[__name__]))
    sys.exit(not result.wasSuccessful())
