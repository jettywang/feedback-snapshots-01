"""Build fully controlled synthetic VBA OLE files for MODULEOFFSET testing.

A project is described as a set of *module streams*. Each module stream is an
ordered list of byte regions:

    prefix (compiled/performance-cache bytes)
      + compressed-source CompressedContainer starting at TextOffset
      + optional trailing bytes / decoy chunks

The :class:`VbaProjectBuilder` keeps the authoritative physical layout, emits
the matching dir record (with the module's TextOffset) and writes a CFB file
that olefile / olevba can open. It also records, per module, the exact physical
interval claimed for the source so tests can assert which bytes were extracted
and where a corrupt declaration was rejected.
"""

import struct

from tests.olevba.vba_mut.cfb import DirEntry, build_cfb
from tests.olevba.vba_mut.ovba import (
    compress_stream, build_dir, replace_module_offset,
)

VBA_ROOT = 'VBA_PROJECT'


class ModuleSpec(object):
    """One module stream plus its dir-record metadata."""

    def __init__(self, name, source, streamname=None, prefix=b'',
                 suffix=b'', module_type=0x21):
        self.name = name
        self.streamname = streamname if streamname is not None else name
        self.source = source if isinstance(source, bytes) else \
            source.encode('latin-1')
        self.prefix = prefix
        self.suffix = suffix
        self.module_type = module_type
        # authoritative physical interval of the compressed source container,
        # populated when the stream is assembled
        self.textoffset = None
        self.source_compressed = None
        self.stream = None

    def assemble(self):
        """Build the physical ModuleStream and remember source boundaries."""
        self.source_compressed = compress_stream(self.source)
        self.textoffset = len(self.prefix)
        self.stream = (self.prefix + self.source_compressed + self.suffix)
        return self.stream

    def physical_interval(self):
        """Return (start, end_exclusive) of the source container in the stream."""
        if self.textoffset is None:
            self.assemble()
        start = self.textoffset
        end = start + len(self.source_compressed)
        return start, end


class VbaProjectBuilder(object):
    def __init__(self, project_name='TestProj'):
        self.project_name = project_name
        self.modules = []
        # raw override hook for tests that corrupt a stream after assembly
        self.stream_overrides = {}

    def add_module(self, *args, **kwargs):
        spec = ModuleSpec(*args, **kwargs)
        self.modules.append(spec)
        return spec

    def module(self, name):
        for spec in self.modules:
            if spec.name == name:
                return spec
        raise KeyError(name)

    def _module_stream_bytes(self, spec):
        if spec.name in self.stream_overrides:
            return self.stream_overrides[spec.name]
        return spec.assemble()

    def build_dir_decompressed(self, offset_overrides=None):
        offset_overrides = offset_overrides or {}
        records = []
        for idx, spec in enumerate(self.modules):
            spec.assemble()
            records.append({
                'name': spec.name.encode('latin-1'),
                'streamname': spec.streamname.encode('latin-1'),
                'textoffset': offset_overrides.get(idx, spec.textoffset),
                'module_type': spec.module_type,
            })
        return build_dir(records, project_name=self.project_name.encode('latin-1'))

    def build(self, offset_overrides=None, dir_mutation=None):
        """Return the raw CFB bytes of the synthetic OLE file."""
        dir_decomp = self.build_dir_decompressed(offset_overrides)
        if dir_mutation is not None:
            dir_decomp = dir_mutation(dir_decomp)
        dir_compressed = compress_stream(dir_decomp)

        top = []
        vba_storage = DirEntry('VBA', 0x01)
        # _VBA_PROJECT stream: only its presence is required for detection.
        vba_storage.children.append(
            DirEntry('_VBA_PROJECT', 0x02, b'\xCC' * 16))
        vba_storage.children.append(
            DirEntry('dir', 0x02, dir_compressed))
        for spec in self.modules:
            data = self._module_stream_bytes(spec)
            vba_storage.children.append(
                DirEntry(spec.streamname, 0x02, data))
        top.append(vba_storage)

        project_text = (
            'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
            'Document=%s/&H00000000\r\n'
            'Module=%s\r\n'
            'Name="%s"\r\n'
            'HelpContextID="0"\r\n'
            'VersionCompatible32="393222000"\r\n'
            'CMG="0000"\r\n'
            'DPB="00"\r\n'
            'GC="00"\r\n'
            % (_stream_docref(self.modules),
               ','.join(m.name for m in self.modules),
               self.project_name)
        )
        top.append(DirEntry('PROJECT', 0x02, project_text.encode('latin-1')))
        top.append(DirEntry('PROJECTwm', 0x02,
                            ('Name="%s"\r\n' % self.project_name).encode('latin-1')))
        return build_cfb(top)

    def rewrite_offset(self, dir_decomp, module_index, new_offset):
        return replace_module_offset(dir_decomp, module_index, new_offset)


def _stream_docref(modules):
    docs = [m for m in modules if m.module_type == 0x22]
    return docs[0].name if docs else modules[0].name
