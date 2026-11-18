#!/usr/bin/env python3
"""Bounded multi-probe format router (proposal demo).

Unlike ftguess (first-match-wins), every probe runs independently and all
verified container views are analysed. Parse-only: no document content is
ever executed. Resource bounds: MAX_DEPTH, MAX_PARTS, MAX_PART_BYTES.
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import olefile
from oletools.common import clsid

MAX_DEPTH = 2
MAX_PARTS = 512
MAX_PART_BYTES = 64 * 1024 * 1024

OOXML_MAIN_CT = {
    'application/vnd.ms-word.document.macroEnabled.main+xml': ('DOCM', True),
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml': ('DOCX', False),
    'application/vnd.ms-excel.sheet.macroEnabled.main+xml': ('XLSM', True),
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml': ('XLSX', False),
    'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml': ('PPTM', True),
    'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml': ('PPTX', False),
}


def probe_vba(data):
    """Return (found: bool|None, detail: str). None = could not verify."""
    from oletools.olevba import VBA_Parser
    try:
        vp = VBA_Parser('<view>', data=data)
        found = vp.detect_vba_macros()
        vp.close()
        return found, 'olevba parse ok'
    except Exception as exc:
        return None, 'olevba: %s: %s' % (type(exc).__name__, exc)


def ole_view(data, label, depth, report):
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = ['/'.join(e) for e in ole.listdir()]
        root = ole.root.clsid
        cname = clsid.KNOWN_CLSIDS.get(root, 'unknown CLSID')
        ole.close()
    except Exception as exc:
        report['unverifiable'].append(
            '%s: OLE magic present but CFB parse failed (%s: %s) '
            '- NOT proven corrupt, structure unverified' % (label, type(exc).__name__, exc))
        return
    report['verified'].append('%s: OLE/CFB parsed, root CLSID=%s (%s), %d streams'
                              % (label, root, cname, len(streams)))
    has_vba_storage = any(s.startswith('VBA') or s == '_VBA_PROJECT' for s in streams)
    if has_vba_storage:
        report['capabilities'].append('%s: VBA storage present in OLE directory' % label)
    found, detail = probe_vba(data)
    if found:
        report['capabilities'].append('%s: VBA macros detected (%s)' % (label, detail))
    elif found is None:
        report['unverifiable'].append('%s: VBA check inconclusive (%s)' % (label, detail))


def zip_view(data, label, depth, report):
    if depth > MAX_DEPTH:
        report['unverifiable'].append('%s: nesting depth > %d, not recursed' % (label, MAX_DEPTH))
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception as exc:
        report['unverifiable'].append('%s: ZIP EOCD present but parse failed (%s)'
                                      % (label, exc))
        return
    if len(names) > MAX_PARTS:
        report['unverifiable'].append('%s: %d parts exceeds MAX_PARTS' % (label, len(names)))
        names = names[:MAX_PARTS]
    report['verified'].append('%s: ZIP parsed, %d parts' % (label, len(names)))
    declared = None
    if '[Content_Types].xml' in names:
        ct = zf.read('[Content_Types].xml')
        for ct_str, (short, macro) in OOXML_MAIN_CT.items():
            if ct_str.encode() in ct:
                declared = (short, macro)
    vba_parts = [n for n in names if n.lower().endswith('vbaproject.bin')]
    ole_parts = []
    for n in names:
        if zf.getinfo(n).file_size > MAX_PART_BYTES:
            report['unverifiable'].append('%s: part %s exceeds MAX_PART_BYTES' % (label, n))
            continue
        head = zf.read(n)[:8]
        if head == olefile.MAGIC and not n.lower().endswith('vbaproject.bin'):
            ole_parts.append(n)
    if declared:
        short, macro = declared
        report['verified'].append('%s: [Content_Types].xml declares main part = %s' % (label, short))
        if vba_parts and not macro:
            report['conflicts'].append(
                '%s: declared %s (macro-free) but %s exists - declaration is not proof'
                % (label, short, vba_parts))
    if vba_parts:
        report['capabilities'].append('%s: vbaProject.bin part present: %s' % (label, vba_parts))
        found, detail = probe_vba(data)
        if found:
            report['capabilities'].append('%s: VBA macros detected (%s)' % (label, detail))
    for n in ole_parts:
        report['capabilities'].append('%s: embedded OLE part %s' % (label, n))
        ole_view(zf.read(n), '%s!%s' % (label, n), depth + 1, report)
    zf.close()


def probe(path):
    data = open(path, 'rb').read()
    report = {'candidates': [], 'verified': [], 'capabilities': [],
              'conflicts': [], 'unverifiable': []}
    ext = os.path.splitext(path)[1].lower().lstrip('.')
    report['candidates'].append('extension suggests: .%s (informational only, never verified)'
                                % ext)
    if data.startswith(b'{\\rt'):
        report['candidates'].append('RTF magic at offset 0')
    if data.startswith(olefile.MAGIC):
        report['candidates'].append('OLE/CFB magic at offset 0')
    if zipfile.is_zipfile(io.BytesIO(data)):
        report['candidates'].append('ZIP EOCD found (archive end record)')
    if data.startswith(olefile.MAGIC):
        ole_view(data, 'OLE-view', 0, report)
    if zipfile.is_zipfile(io.BytesIO(data)):
        zip_view(data, 'ZIP-view', 0, report)
    if not report['verified'] and not report['unverifiable']:
        report['unverifiable'].append('no container structure verified; type unknown')
    return report


def main():
    for path in sys.argv[1:]:
        r = probe(path)
        print('=' * 70)
        print(path)
        for key in ('candidates', 'verified', 'capabilities', 'conflicts', 'unverifiable'):
            print('  [%s]' % key)
            for item in r[key] or ['  (none)']:
                print('    - %s' % item)


if __name__ == '__main__':
    main()
