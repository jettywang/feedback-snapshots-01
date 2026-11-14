# -*- coding: utf-8 -*-
"""
Demo: directory name collisions in olefile (MS-CFB name resolution).

Builds a minimal in-memory OLE file containing two streams whose distinct
raw UTF-16 names collide after decoding ('Data' + lone surrogate U+D800 vs
'Data' + literal U+FFFD), and shows how listdir/exists/get_type/openstream
behave. Run it against the fixed code and, optionally, against a copy of
the pre-fix olefile.py to compare:

    python tests/name_collision_demo.py [path/to/old_olefile.py]

To obtain the pre-fix version from git:

    git show HEAD~1:olefile/olefile.py > /tmp/olefile_old.py
"""
import importlib.util
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_olefile import _make_collision_file, _make_clean_file


def load_module(path, tag):
    spec = importlib.util.spec_from_file_location('olefile_' + tag, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def probe(module, label):
    print('=== %s ===' % label)
    for swap in (False, True):
        shape = 'B (left/right swapped)' if swap else 'A'
        data = _make_collision_file(swap_tree=swap)
        print('-- collision file, tree shape %s' % shape)
        try:
            ole = module.OleFileIO(io.BytesIO(data))
        except Exception as exc:
            print('   open() raised %s: %s' % (type(exc).__name__, exc))
            continue
        print('   listdir()      ->',
              [[n.encode('unicode_escape').decode() for n in path]
               for path in ole.listdir()])
        print('   parsing_issues ->',
              [msg for _, msg in ole.parsing_issues])
        for query in ['Data\ufffd', 'data\ufffd']:
            try:
                stream = ole.openstream(query)
                print('   openstream(%r) -> content 0x%02X'
                      % (query, stream.read(1)[0]))
            except Exception as exc:
                print('   openstream(%r) -> %s: %s'
                      % (query, type(exc).__name__, exc))
        print('   exists("data\\ufffd")  ->', ole.exists('data\ufffd'))
        print('   get_type("data\\ufffd") ->', ole.get_type('data\ufffd'))
        if hasattr(ole, 'find_sids'):
            print('   find_sids("data\\ufffd") ->', ole.find_sids('data\ufffd'))
        ole.close()
        try:
            ole = module.OleFileIO(io.BytesIO(data),
                                   raise_defects=module.DEFECT_INCORRECT)
            print('   strict mode: opened without error (unexpected)')
            ole.close()
        except Exception as exc:
            print('   strict mode -> %s: %s' % (type(exc).__name__, exc))
    ole = module.OleFileIO(io.BytesIO(_make_clean_file()))
    print('-- clean file: case aliases WordDocument/worddocument ->',
          ole.exists('worddocument') and ole.exists('WORDDOCUMENT'))
    ole.close()


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if len(sys.argv) > 1:
        probe(load_module(sys.argv[1], 'old'), 'BEFORE (%s)' % sys.argv[1])
    probe(load_module(os.path.join(here, 'olefile', 'olefile.py'), 'new'),
          'CURRENT (%s)' % os.path.join('olefile', 'olefile.py'))


if __name__ == '__main__':
    main()
