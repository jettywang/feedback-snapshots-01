#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.forensics.test_raw.suite',
     'tests.forensics.test_evidence.suite',
     'tests.forensics.test_compare.suite']
)


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
