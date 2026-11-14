#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Sensitivity checks for the CRMF POP regression suite.

A regression test that passes is only useful if it would fail when the
property it claims to protect is broken.  Each test here takes the working
reference verifier, removes exactly one binding rule, and asserts that the
main suite then fails.  The rule is checked independently: the mutated run
relaxes the *other* rules where needed so that the removal under test is the
only reason a request could be accepted.

If a mutation stops being caught, either the main suite lost coverage or the
rule disappeared from the verifier; both are regressions worth failing on.
"""

import ast
import io
import os
import sys
import unittest

import tests.test_crmf_pop as pop_suite

VERIFIER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'examples', 'crmf_pop', 'verifier.py')


def load_verifier_source():
    with open(VERIFIER_PATH, 'r', encoding='utf-8') as handle:
        return handle.read()


def _replace_once(source, old, new, label):
    if source.count(old) != 1:
        raise AssertionError(
            'mutation %s no longer applies; update it' % label)
    return source.replace(old, new)


MUTATIONS = {
    'drop_sender_subject_equality': (
        """            if template_subject_der is not None:
                if sender_subject_der is None or \\
                        template_subject_der != sender_subject_der:
                    raise PopError(
                        'CertTemplate subject does not match the signed '
                        'sender identity')
                subject_der = template_subject_der
            else:
                subject_der = sender_subject_der""",
        """            if template_subject_der is not None:
                subject_der = template_subject_der
            else:
                subject_der = sender_subject_der"""),

    'drop_input_key_equality': (
        """        if template_pk_der is not None and template_pk_der != input_pk_der:
            raise PopError(
                'POPOSigningKeyInput publicKey does not match CertTemplate')""",
        """        if False:
            raise PopError('unreachable')"""),

    'trust_any_ra_context': (
        """    if not isinstance(ra_context, TrustedRA) or not ra_context.trusted:
        raise PopError('raVerified requires an explicit trusted RA context')

    if ra_context.approved_cert_request_der is None:
        raise PopError('trusted RA context does not cover a CertRequest')

    if der_encoder(cert_req) != ra_context.approved_cert_request_der:
        raise PopError('raVerified does not cover this CertRequest')""",
        """    if ra_context is None:
        raise PopError('raVerified requires some RA context')"""),

    'ignore_public_key_mac_result': (
        """            if not verify_public_key_mac(pbm, public_key_der, mac_value):
                raise PopError('publicKeyMAC verification failed')""",
        """            verify_public_key_mac(pbm, public_key_der, mac_value)"""),

    'allow_input_on_complete_template': (
        """        if has_subject and has_public_key:
            raise PopError(
                'poposkInput must be omitted when certTemplate has both '
                'subject and publicKey')""",
        """        if False:
            raise PopError('unreachable')"""),

    'allow_missing_input': (
        """        if not (has_subject and has_public_key):
            raise PopError(
                'poposkInput must be present when certTemplate lacks subject '
                'or publicKey')""",
        """        if False:
            raise PopError('unreachable')"""),
}


def _run_main_suite(verifier_module):
    """Run the main suite with a replacement verifier module."""
    original = pop_suite.verifier
    pop_suite.verifier = verifier_module
    try:
        suite = unittest.TestLoader().loadTestsFromModule(pop_suite)
        result = unittest.TextTestRunner(stream=io.StringIO(),
                                         verbosity=0).run(suite)
        return result
    finally:
        pop_suite.verifier = original


def _build_mutated_module(source):
    namespace = {}
    exec(compile(source, '<mutated verifier>', 'exec'), namespace)
    module = type(sys)('mutated_verifier')
    module.__dict__.update(namespace)
    return module


class MutationSensitivityTest(unittest.TestCase):
    """Every binding rule has at least one test that fails without it."""

    @classmethod
    def setUpClass(cls):
        cls.source = load_verifier_source()
        # Parse once so a syntactically broken mutant is reported clearly.
        ast.parse(cls.source)

    def test_baseline_suite_passes(self):
        import examples.crmf_pop.verifier as verifier
        self.assertTrue(_run_main_suite(verifier).wasSuccessful())

    def test_every_mutation_is_caught(self):
        for label, (old, new) in MUTATIONS.items():
            with self.subTest(mutation=label):
                mutated_source = _replace_once(
                    self.source, old, new, label)
                mutated = _build_mutated_module(mutated_source)
                result = _run_main_suite(mutated)
                self.assertFalse(
                    result.wasSuccessful(),
                    'main suite still passes with mutation %s; the '
                    'regression does not cover that rule' % label)
                self.assertTrue(
                    result.failures or result.errors,
                    'mutation %s produced no failing test' % label)


if __name__ == '__main__':
    unittest.main()
