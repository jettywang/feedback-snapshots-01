"""In-process harness that runs the olevba VBA extraction chain on a synthetic
OLE byte string and records, per module, the extracted source and the physical
interval / rejection position. Keeping this out of the CLI avoids the unrelated
subprocess test harness and gives exact access to VBA_Module metadata.
"""

import os
import tempfile

import olefile

from oletools.olevba import (
    VBA_Project, ModuleSourceError, decompress_stream,
)


def write_ole(data):
    fd, path = tempfile.mkstemp(suffix='.ole', prefix='vba_mut_')
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    return path


def parse_project(data, relaxed=True):
    """Parse synthetic OLE bytes and return the populated VBA_Project."""
    path = write_ole(data)
    try:
        ole = olefile.OleFileIO(path)
        project = VBA_Project(ole, '', 'PROJECT', 'VBA/dir', relaxed=relaxed)
        project.parse_project_stream()
        # drain the generator so every VBA_Module is constructed
        for _ in project.parse_modules():
            pass
        project._ole = ole  # keep the handle alive for later reads
        return project
    except Exception:
        try:
            ole.close()
        except Exception:
            pass
        raise


def module_by_name(project, name):
    for module in project.modules:
        if module.name == name:
            return module
    raise KeyError(name)


def read_stream(data, stream_path):
    """Read a raw stream from OLE bytes via a temporary file."""
    path = write_ole(data)
    try:
        ole = olefile.OleFileIO(path)
        raw = ole.openstream(stream_path).read()
        ole.close()
        return raw
    except Exception:
        try:
            ole.close()
        except Exception:
            pass
        raise


__all__ = [
    'write_ole', 'parse_project', 'module_by_name', 'read_stream',
    'ModuleSourceError', 'decompress_stream',
]
