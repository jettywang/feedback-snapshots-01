"""Structure-aware mutation tests for the MODULEOFFSET -> VBA source chain.

These tests build fully controlled synthetic OLE/VBA projects (see
:mod:`tests.olevba.vba_mut`) in which a module stream contains:

  PerformanceCache prefix + compressed source CompressedContainer + trailing
  (possibly decoy) bytes

and the dir record's MODULEOFFSET, the compressed length and the stream tail are
mutated together. They assert that olevba interprets *only* the source interval
declared by MODULEOFFSET:

* a legitimate non-zero prefix is readable and skipped exactly;
* an offset that lands inside the prefix / past the stream is rejected;
* cross-stream truncation and a broken chunk chain are rejected at distinct,
  precise positions;
* a valid decoy CompressedContainer placed after a corrupt declared start is
  never recovered by forward scanning (no forged source attribution);
* each module's extracted bytes and physical interval are saved and verified.
"""

import struct
import unittest

from tests.olevba.vba_mut.builder import VbaProjectBuilder
from tests.olevba.vba_mut.ovba import (
    compress_stream, bad_signature_chunk, replace_module_offset,
)
from tests.olevba.vba_mut import harness
from oletools.olevba import (
    decompress_stream, ModuleSourceError,
)

SOURCE_A = ('Attribute VB_Name="ModA"\r\n'
            'Sub Alpha()\r\n    MsgBox "alpha"\r\nEnd Sub\r\n')
SOURCE_B = ('Attribute VB_Name="ModB"\r\n'
            'Sub Beta()\r\n    MsgBox "beta"\r\nEnd Sub\r\n')
# a second, independently valid container used as a decoy
DECOY_SOURCE = ('Attribute VB_Name="Decoy"\r\n'
                'Sub Evil()\r\n    MsgBox "forged"\r\nEnd Sub\r\n')


def _builder_two_modules(prefix_a=64, prefix_b=32):
    builder = VbaProjectBuilder()
    builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * prefix_a,
                       module_type=0x21)
    builder.add_module('ModB', SOURCE_B, prefix=b'\xBB' * prefix_b,
                       module_type=0x22)
    return builder


class TestLegitimatePrefix(unittest.TestCase):
    """A non-zero PerformanceCache prefix is legal and must stay readable."""

    def test_nonzero_prefix_skipped_exactly(self):
        builder = _builder_two_modules()
        data = builder.build()
        project = harness.parse_project(data, relaxed=False)
        for name, source in (('ModA', SOURCE_A), ('ModB', SOURCE_B)):
            module = harness.module_by_name(project, name)
            spec = builder.module(name)
            # the parser must report no rejection and full source
            self.assertIsNone(module.source_error)
            self.assertIsNotNone(module.code_str)
            # decompressed source round-trips (trailing NULs only from padding)
            self.assertTrue(module.code_raw.startswith(source.encode('latin-1')))
            # physical interval starts right after the prefix and ends at EOF
            start, end = module.source_interval
            self.assertEqual(start, len(spec.prefix))
            self.assertEqual(end, module.stream_size)
            self.assertEqual(start, spec.physical_interval()[0])
        project._ole.close()

    def test_prefix_bytes_remain_in_stream(self):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 64)
        data = builder.build()
        raw = harness.read_stream(data, 'VBA/ModA')
        # the PerformanceCache prefix is physically present and untouched
        self.assertEqual(raw[:64], b'\xAA' * 64)
        # and the declared source begins with the compression signature
        self.assertEqual(raw[spec.textoffset], 0x01)

    def test_zero_offset_accepted(self):
        builder = VbaProjectBuilder()
        builder.add_module('NoCache', SOURCE_A, prefix=b'')
        project = harness.parse_project(builder.build(), relaxed=False)
        module = harness.module_by_name(project, 'NoCache')
        self.assertIsNone(module.source_error)
        self.assertEqual(module.source_interval[0], 0)
        project._ole.close()


class TestOffsetInsidePrefix(unittest.TestCase):
    """MODULEOFFSET pointing into the compiled cache, not at the source."""

    def _build(self, declared_offset):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 64)
        # mutate the dir record but keep the same physical module stream
        dir_decomp = builder.build_dir_decompressed()
        mutated_dir = replace_module_offset(dir_decomp, 0, declared_offset)
        data = builder.build(dir_mutation=lambda _d: mutated_dir)
        return data, spec

    def test_offset_into_prefix_rejected_relaxed(self):
        data, spec = self._build(10)  # lands inside the 0xAA prefix
        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsInstance(module.source_error, ModuleSourceError)
        # position is the declared offset; byte 0xAA is not the 0x01 signature
        self.assertEqual(module.source_error.position, 10)
        self.assertIsNone(module.code_str)
        self.assertIsNone(module.source_interval)
        project._ole.close()

    def test_offset_into_prefix_raises_strict(self):
        data, _ = self._build(10)
        with self.assertRaises(ModuleSourceError) as ctx:
            harness.parse_project(data, relaxed=False)
        self.assertEqual(ctx.exception.position, 10)

    def test_no_forward_scan_to_real_source(self):
        # even though a perfectly valid container exists at offset 64, a
        # corrupted declaration at 10 must not be repaired by scanning forward
        data, spec = self._build(10)
        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsNone(module.code_str)
        # the real source is still physically present (proving a scanner could
        # have found it) but must not have been attributed to this module
        raw = harness.read_stream(data, 'VBA/ModA')
        self.assertEqual(raw[64], 0x01)
        decompress_stream(bytearray(raw[64:]))  # would succeed if scanned
        project._ole.close()


class TestOffsetOutOfStream(unittest.TestCase):
    """MODULEOFFSET at or beyond the stream end (cross-stream truncation)."""

    def test_offset_equal_stream_size_rejected(self):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 32)
        builder.build()  # populate spec.stream / textoffset
        stream_size = len(spec.stream)
        dir_decomp = builder.build_dir_decompressed()
        mutated = replace_module_offset(dir_decomp, 0, stream_size)
        data = builder.build(dir_mutation=lambda _d: mutated)
        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsInstance(module.source_error, ModuleSourceError)
        self.assertEqual(module.textoffset, stream_size)
        # an empty interval cannot address any byte
        self.assertIsNone(module.code_str)
        project._ole.close()

    def test_offset_beyond_stream_size_rejected(self):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 32)
        builder.build()
        stream_size = len(spec.stream)
        dir_decomp = builder.build_dir_decompressed()
        mutated = replace_module_offset(dir_decomp, 0, stream_size + 200)
        data = builder.build(dir_mutation=lambda _d: mutated)
        with self.assertRaises(ModuleSourceError) as ctx:
            harness.parse_project(data, relaxed=False)
        # rejection reported at the declared offset, distinct from a chunk error
        self.assertEqual(ctx.exception.textoffset, stream_size + 200)
        self.assertGreaterEqual(ctx.exception.position, stream_size)

    def test_truncated_container_rejected_at_tail(self):
        # declare the correct start but truncate the stream mid-container so the
        # chunk chain runs past the end; the failure position must be at/after
        # the declared start rather than being silently accepted
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 16)
        full = spec.assemble()
        # keep signature + first chunk header but cut the body short
        truncated = full[:spec.textoffset + 4]
        builder.stream_overrides['ModA'] = truncated
        data = builder.build()
        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsInstance(module.source_error, ModuleSourceError)
        # truncation is a decompression failure distinct from the OOB case:
        # the offset itself is valid, so position >= declared source start
        self.assertGreaterEqual(module.source_error.position, spec.textoffset)
        self.assertIsNone(module.code_str)
        project._ole.close()


class TestBadChunkChain(unittest.TestCase):
    """The declared interval has a valid signature but a corrupt chunk chain."""

    def test_bad_chunk_signature_rejected(self):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 8)
        # prefix + valid signature byte + a chunk with an invalid 3-bit signature
        spec.assemble()
        corrupted = (spec.prefix + b'\x01' + bad_signature_chunk())
        builder.stream_overrides['ModA'] = corrupted
        data = builder.build()
        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsInstance(module.source_error, ModuleSourceError)
        # signature byte at the offset was fine; the chunk header right after it
        # is where interpretation stops
        self.assertEqual(module.source_error.position, spec.textoffset + 1)
        self.assertIsNone(module.code_str)
        project._ole.close()

    def test_bad_chunk_distinct_from_prefix_and_truncation(self):
        # gather the three minimal counter-examples and prove they fail at
        # different physical positions / for different reasons
        positions = {}

        # 1) offset into prefix
        b1 = VbaProjectBuilder()
        s1 = b1.add_module('M', SOURCE_A, prefix=b'\xAA' * 64)
        dd = b1.build_dir_decompressed()
        d1 = b1.build(dir_mutation=lambda _d: replace_module_offset(dd, 0, 10))
        positions['prefix'] = harness.parse_project(d1).modules[0].source_error

        # 2) cross-stream truncation (offset beyond end)
        b2 = VbaProjectBuilder()
        s2 = b2.add_module('M', SOURCE_A, prefix=b'\xAA' * 16)
        b2.build()
        dd2 = b2.build_dir_decompressed()
        size2 = len(s2.stream)
        d2 = b2.build(dir_mutation=lambda _d:
                      replace_module_offset(dd2, 0, size2 + 50))
        try:
            harness.parse_project(d2, relaxed=False)
            self.fail('expected ModuleSourceError')
        except ModuleSourceError as exc:
            positions['truncation'] = exc

        # 3) bad chunk chain (valid offset + signature)
        b3 = VbaProjectBuilder()
        s3 = b3.add_module('M', SOURCE_A, prefix=b'\xAA' * 8)
        s3.assemble()
        b3.stream_overrides['M'] = s3.prefix + b'\x01' + bad_signature_chunk()
        d3 = b3.build()
        positions['chunk'] = harness.parse_project(d3).modules[0].source_error

        self.assertEqual(positions['prefix'].position, 10)
        self.assertGreaterEqual(positions['truncation'].position, size2)
        self.assertEqual(positions['chunk'].position, s3.textoffset + 1)
        # three distinct minimal counter-examples, three distinct positions
        self.assertEqual(len({positions[k].position for k in positions}), 3)


class TestDecoyNoRescan(unittest.TestCase):
    """A valid decoy container after a corrupt declaration must not be claimed."""

    def test_decoy_after_bad_start_is_not_attributed(self):
        builder = VbaProjectBuilder()
        spec = builder.add_module('ModA', SOURCE_A, prefix=b'\xAA' * 64)
        spec.assemble()
        decoy = compress_stream(DECOY_SOURCE)
        # physical stream: prefix, a deliberately broken start byte (0x02 is not
        # the 0x01 signature), then a fully valid decoy CompressedContainer
        corrupted_stream = spec.prefix + b'\x02' + decoy
        builder.stream_overrides['ModA'] = corrupted_stream
        data = builder.build()

        # prove the decoy really is a decompressable container on its own
        recovered = decompress_stream(bytearray(decoy))
        self.assertIn(b'forged', recovered)

        project = harness.parse_project(data, relaxed=True)
        module = harness.module_by_name(project, 'ModA')
        self.assertIsInstance(module.source_error, ModuleSourceError)
        self.assertIsNone(module.code_str)
        self.assertIsNone(module.source_interval)
        # rejection anchored at the declared offset, not at the decoy
        self.assertEqual(module.source_error.position, spec.textoffset)
        project._ole.close()

    def test_other_module_unaffected_by_corrupt_neighbour(self):
        # corrupt ModA while ModB stays valid; ModB must still extract exactly
        builder = _builder_two_modules()
        spec_a = builder.module('ModA')
        spec_a.assemble()
        builder.stream_overrides['ModA'] = spec_a.prefix + b'\x02' + \
            compress_stream(DECOY_SOURCE)
        data = builder.build()
        project = harness.parse_project(data, relaxed=True)
        mod_a = harness.module_by_name(project, 'ModA')
        mod_b = harness.module_by_name(project, 'ModB')
        self.assertIsInstance(mod_a.source_error, ModuleSourceError)
        self.assertIsNone(mod_a.code_str)
        self.assertIsNone(mod_b.source_error)
        self.assertTrue(mod_b.code_raw.startswith(SOURCE_B.encode('latin-1')))
        project._ole.close()


class TestPhysicalIntervalAccounting(unittest.TestCase):
    """Saved per-module source bytes and physical intervals are self-consistent."""

    def test_interval_bytes_match_declared_container(self):
        builder = _builder_two_modules(prefix_a=128, prefix_b=72)
        data = builder.build()
        project = harness.parse_project(data, relaxed=False)
        for module in project.modules:
            spec = builder.module(module.name)
            start, end = module.source_interval
            raw = harness.read_stream(data, 'VBA/' + spec.streamname)
            declared = raw[start:end]
            # the bytes the parser used are exactly the declared interval
            self.assertEqual(declared[0], 0x01)
            roundtrip = decompress_stream(bytearray(declared))
            self.assertEqual(roundtrip, module.code_raw)
            # nothing before the interval is treated as source
            self.assertEqual(start, len(spec.prefix))
        project._ole.close()

    def test_each_module_saved_independently(self):
        builder = _builder_two_modules()
        data = builder.build()
        project = harness.parse_project(data, relaxed=False)
        names = [m.name for m in project.modules]
        self.assertEqual(sorted(names), ['ModA', 'ModB'])
        codes = {m.name: m.code_raw for m in project.modules}
        self.assertIn(b'Alpha', codes['ModA'])
        self.assertIn(b'Beta', codes['ModB'])
        # independent intervals never overlap across modules
        intervals = {m.name: m.source_interval for m in project.modules}
        self.assertNotEqual(intervals['ModA'], intervals['ModB'])
        project._ole.close()


class TestNoRescanImplementation(unittest.TestCase):
    """Static guard: the extraction path must not retry from a later offset."""

    def test_module_init_has_no_offset_scan_loop(self):
        import inspect
        from oletools import olevba
        source = inspect.getsource(olevba.VBA_Module.__init__)
        # exactly one slicing at the declared offset and one decompress call
        self.assertEqual(source.count('code_data[self.textoffset:]'), 1)
        self.assertEqual(source.count('decompress_stream('), 1)
        # no construct that would hunt forward for another container
        for forbidden in ('find(0x01)', 'find(b\'\\x01\')', 'textoffset +=',
                          'textoffset = textoffset', 'while textoffset'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
