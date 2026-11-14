#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Reference CRMF proof-of-possession validation example.

Modules:

``der``
    Independent DER construction for the octets RFC 4211 section 4.1 says
    are signed, plus a fixed test signature construction.
``verifier``
    Reference validation that binds verified octets to the request.
``fixtures``
    One legitimate request per RFC 4211 case plus one-field attack copies.
``demo``
    Runnable demonstration; ``python -m examples.crmf_pop.demo``.
"""
