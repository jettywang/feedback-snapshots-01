#!/usr/bin/env python3
"""Build conflict/polyglot samples for format-guessing review.

All payloads are inert: VBA comes from oletools' own test file
(tests/test-data/olevba/sample_with_vba.ppt). Nothing is executed;
samples are only parsed by oletools itself.
"""
import io
import os
import shutil
import uuid
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PPT_OLE = os.path.join(ROOT, 'tests', 'test-data', 'olevba', 'sample_with_vba.ppt')
OUT = os.path.join(HERE, 'samples')

CT_DOCM = 'application/vnd.ms-word.document.macroEnabled.main+xml'
CT_DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'


def content_types(main_ct, with_vba_override):
    vba = ('<Override PartName="/word/vbaProject.bin" '
           'ContentType="application/vnd.ms-office.vbaProject"/>') if with_vba_override else ''
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="%s"/>%s'
            '</Types>' % (main_ct, vba)).encode()


RELS = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        b'Target="word/document.xml"/>'
        b'</Relationships>')

DOCUMENT = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:body><w:p><w:r><w:t>inert</w:t></w:r></w:p></w:body></w:document>')


def make_docm_bytes(main_ct, with_vba_override):
    """Minimal .docm package; vbaProject.bin is a real CFB carrying VBA."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types(main_ct, with_vba_override))
        z.writestr('_rels/.rels', RELS)
        z.writestr('word/document.xml', DOCUMENT)
        with open(PPT_OLE, 'rb') as f:
            z.writestr('word/vbaProject.bin', f.read())
    return buf.getvalue()


def s1_ole_renamed():
    shutil.copyfile(PPT_OLE, os.path.join(OUT, 'S1_ole_renamed.docx'))


def s2_ole_zip_polyglot():
    docm = make_docm_bytes(CT_DOCM, with_vba_override=True)
    with open(PPT_OLE, 'rb') as f:
        ole = f.read()
    with open(os.path.join(OUT, 'S2_ole_zip_polyglot.doc'), 'wb') as f:
        f.write(ole)
        f.write(docm)  # trailing ZIP: EOCD at EOF, so zipfile accepts it


def s3_docm_declared_as_docx():
    data = make_docm_bytes(CT_DOCX, with_vba_override=False)
    with open(os.path.join(OUT, 'S3_docm_declared_as_docx.docx'), 'wb') as f:
        f.write(data)


def s4_ole_magic_only():
    with open(os.path.join(OUT, 'S4_ole_magic_only.doc'), 'wb') as f:
        f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
        f.write(b'\x41' * 2048)  # 'AAAA...' - no FAT, no directory


def s5_xlsx_with_ole_embed():
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Default Extension="bin" ContentType="application/vnd.ms-office.oleObject"/>'
          '<Override PartName="/xl/workbook.xml" '
          'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '</Types>').encode()
    rels = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            b'Target="xl/workbook.xml"/></Relationships>')
    workbook = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                b'<sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
    wb_rels = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               b'<Relationship Id="rId9" '
               b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
               b'Target="embeddings/oleObject1.bin"/></Relationships>')
    with open(PPT_OLE, 'rb') as f:
        ole = f.read()
    with zipfile.ZipFile(os.path.join(OUT, 'S5_xlsx_with_ole_embed.xlsx'), 'w',
                         zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', ct)
        z.writestr('_rels/.rels', rels)
        z.writestr('xl/workbook.xml', workbook)
        z.writestr('xl/_rels/workbook.xml.rels', wb_rels)
        z.writestr('xl/embeddings/oleObject1.bin', ole)


def s6_clsid_spoofed():
    word97 = uuid.UUID('00020906-0000-0000-c000-000000000046').bytes_le
    ppt97 = uuid.UUID('64818d10-4f9b-11cf-86ea-00aa00b929e8').bytes_le
    with open(PPT_OLE, 'rb') as f:
        data = bytearray(f.read())
    idx, n = -1, 0
    while True:
        idx = data.find(ppt97, idx + 1)
        if idx < 0:
            break
        data[idx:idx + 16] = word97
        n += 1
    assert n > 0, 'root CLSID not found in sample'
    with open(os.path.join(OUT, 'S6_clsid_spoofed.doc'), 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    s1_ole_renamed()
    s2_ole_zip_polyglot()
    s3_docm_declared_as_docx()
    s4_ole_magic_only()
    s5_xlsx_with_ole_embed()
    s6_clsid_spoofed()
    for name in sorted(os.listdir(OUT)):
        print('%8d  %s' % (os.path.getsize(os.path.join(OUT, name)), name))
