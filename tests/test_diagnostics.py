import io
import logging
import traceback

from tests import unittest

import jmespath
from jmespath import diagnostics
from jmespath import exceptions
from jmespath import functions
from jmespath import parser
from jmespath.spans import CharacterSpan


class SyntheticExtension(functions.Functions):
    """Extension whose second invocation always raises a private failure."""

    def __init__(self):
        self.calls = 0

    @functions.signature({'types': ['string']})
    def _func_boom(self, value):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError('PRIVATE-FIXTURE-VALUE column=secret')
        return 'ok:' + value


class AlwaysFailingExtension(functions.Functions):
    @functions.signature({'types': ['string']})
    def _func_explode(self, value):
        raise RuntimeError('PRIVATE-FIXTURE-VALUE column=secret')


def make_options(extension, **kwargs):
    kwargs.setdefault('public', True)
    return jmespath.Options(
        custom_functions=extension,
        diagnostics=diagnostics.Diagnostics(**kwargs))


class TestCharacterSpans(unittest.TestCase):
    def test_multibyte_lexer_span_is_character_based(self):
        with self.assertRaises(exceptions.LexerError) as e:
            parser.Parser().parse('"名称".???')
        exception = e.exception
        self.assertEqual(exception.phase, exceptions.PHASE_LEXER)
        self.assertEqual(exception.span, CharacterSpan(5, 6))
        self.assertEqual(exception.span.start, 5)
        self.assertEqual(exception.span.end, 6)

    def test_multibyte_byte_vs_character_offsets_differ(self):
        expression = '"名称" ]'
        self.assertNotEqual(len(expression.encode('utf-8')), len(expression))
        with self.assertRaises(exceptions.ParseError) as e:
            parser.Parser().parse(expression)
        # Character offsets land on the ']' (not the UTF-8 byte offset).
        self.assertEqual(e.exception.span.start, 5)
        self.assertEqual(expression[5], ']')

    def test_multibyte_parse_span(self):
        with self.assertRaises(exceptions.ParseError) as e:
            parser.Parser().parse('"名称" ]')
        self.assertEqual(e.exception.phase, exceptions.PHASE_PARSER)
        self.assertEqual(e.exception.span, CharacterSpan(5, 6))

    def test_incomplete_expression_is_zero_width_at_end(self):
        expression = '"名称" | length('
        with self.assertRaises(exceptions.IncompleteExpressionError) as e:
            parser.Parser().parse(expression)
        exception = e.exception
        self.assertEqual(exception.span,
                         CharacterSpan(len(expression), len(expression)))

    def test_quoted_identifier_span_includes_quotes(self):
        tokens = list(jmespath.lexer.Lexer().tokenize('"名称"'))
        token = tokens[0]
        self.assertEqual(token.span, CharacterSpan(0, 4))
        # Legacy keys are unchanged.
        self.assertEqual(token['start'], 0)
        self.assertEqual(token['end'], 3)

    def test_token_span_slices_out_the_whole_lexeme(self):
        for expression in ['`a`', '`[0, 1]`', '"foobar"', "'abc'", '"名称"']:
            token = list(jmespath.lexer.Lexer().tokenize(expression))[0]
            self.assertEqual(expression[token.span.start:token.span.end],
                             expression)

    def test_quoted_identifier_after_previous_token(self):
        tokens = list(jmespath.lexer.Lexer().tokenize('"名称".x'))
        self.assertEqual(tokens[0].span, CharacterSpan(0, 4))
        self.assertEqual(tokens[1].span, CharacterSpan(4, 5))
        self.assertEqual(tokens[2].span, CharacterSpan(5, 6))

    def test_token_dicts_remain_equal_to_plain_dicts(self):
        tokens = list(jmespath.lexer.Lexer().tokenize('foo'))
        self.assertEqual(
            tokens,
            [{'type': 'unquoted_identifier', 'value': 'foo',
              'start': 0, 'end': 3},
             {'type': 'eof', 'value': '', 'start': 3, 'end': 3}])


class TestPhaseClassification(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.reports = []
        self.options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(
                internal_sink=self.events.append,
                public_sink=self.reports.append))

    def test_lexer_phase(self):
        with self.assertRaises(exceptions.LexerError):
            jmespath.search('foo[0^]', {}, options=self.options)
        self.assertEqual(self.events[-1].phase, 'lexer')
        self.assertEqual(self.events[-1].code, 'lexer.unknown_token')

    def test_parser_phase(self):
        with self.assertRaises(exceptions.ParseError):
            jmespath.search('foo]baz', {}, options=self.options)
        self.assertEqual(self.events[-1].phase, 'parser')
        self.assertEqual(self.events[-1].code, 'parser.unexpected_token')

    def test_evaluation_phase(self):
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('length(@)', 2, options=self.options)
        self.assertEqual(self.events[-1].phase, 'evaluation')
        self.assertEqual(self.events[-1].code, 'evaluation.invalid_type')

    def test_exception_classes_expose_phase(self):
        self.assertEqual(exceptions.LexerError.phase, 'lexer')
        self.assertEqual(exceptions.ParseError.phase, 'parser')
        self.assertEqual(exceptions.JMESPathTypeError.phase, 'evaluation')
        self.assertEqual(exceptions.UnknownFunctionError.phase, 'evaluation')

    def test_arity_error_is_evaluation_despite_parse_base(self):
        # ArityError still subclasses ParseError for backwards compatibility,
        # but diagnostics must report the evaluation phase.
        self.assertTrue(issubclass(exceptions.ArityError,
                                   exceptions.ParseError))
        with self.assertRaises(exceptions.ArityError):
            jmespath.search('length(@, @)', [1, 2], options=self.options)
        self.assertEqual(self.events[-1].phase, 'evaluation')
        self.assertEqual(self.events[-1].code, 'evaluation.invalid_arity')


class TestPublicReport(unittest.TestCase):
    def test_public_report_contains_only_approved_fields(self):
        reports = []
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(
                public=True, public_sink=reports.append))
        with self.assertRaises(diagnostics.PublicJMESPathError) as e:
            jmespath.search(
                '"租户名称" | length(@)', {'租户名称': 3},
                options=options)
        report = reports[-1]
        self.assertEqual(
            set(report.to_dict()),
            {'correlation_id', 'phase', 'code', 'message', 'span',
             'location'})
        rendered = repr(report.to_dict())
        self.assertNotIn('租户名称', rendered)
        self.assertNotIn('3', report.message)
        self.assertEqual(e.exception.correlation_id, report.correlation_id)

    def test_public_exception_redacts_string_and_chain(self):
        options = jmespath.Options(
            custom_functions=AlwaysFailingExtension(),
            diagnostics=diagnostics.Diagnostics(public=True))
        with self.assertRaises(diagnostics.PublicJMESPathError) as e:
            jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                            options=options)
        exception = e.exception
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', str(exception))
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', repr(exception))
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', repr(exception.args))
        self.assertIsNone(exception.__cause__)
        self.assertIsNone(exception.__context__)
        formatted = ''.join(traceback.format_exception(
            type(exception), exception, exception.__traceback__))
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', formatted)
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', repr(vars(exception)))
        # Trusted in-process handlers can still inspect the original.
        self.assertIsInstance(exception.internal_error, RuntimeError)
        self.assertIn('PRIVATE-FIXTURE-VALUE', str(exception.internal_error))

    def test_extension_exception_is_not_chained(self):
        # Raising from inside an ``except`` block would otherwise attach the
        # original exception as ``__context__`` after construction.
        options = jmespath.Options(
            custom_functions=AlwaysFailingExtension(),
            diagnostics=diagnostics.Diagnostics(public=True))
        for _ in range(2):
            try:
                try:
                    jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                                    options=options)
                except Exception:
                    raise
            except diagnostics.PublicJMESPathError as e:
                self.assertIsNone(e.__context__)
                self.assertNotIn(
                    'PRIVATE-FIXTURE-VALUE', traceback.format_exc())

    def test_public_exception_args_match_public_message(self):
        options = jmespath.Options(
            custom_functions=AlwaysFailingExtension(),
            diagnostics=diagnostics.Diagnostics(public=True))
        with self.assertRaises(diagnostics.PublicJMESPathError) as e:
            jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                            options=options)
        self.assertEqual(
            e.exception.args,
            ('The expression could not be evaluated.',))

    def test_logger_never_receives_private_values(self):
        stream = io.StringIO()
        logger = logging.getLogger('jmespath.test.diagnostics')
        logger.handlers = []
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        try:
            options = jmespath.Options(
                custom_functions=AlwaysFailingExtension(),
                diagnostics=diagnostics.Diagnostics(
                    public=True, logger=logger))
            with self.assertRaises(diagnostics.PublicJMESPathError):
                jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                                options=options)
        finally:
            logger.removeHandler(handler)
        logged = stream.getvalue()
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', logged)
        self.assertNotIn('名称', logged)

    def test_public_error_copies_do_not_expose_original(self):
        import copy
        import pickle
        options = jmespath.Options(
            custom_functions=AlwaysFailingExtension(),
            diagnostics=diagnostics.Diagnostics(public=True))
        with self.assertRaises(diagnostics.PublicJMESPathError) as e:
            jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                            options=options)
        for clone in (copy.copy(e.exception), copy.deepcopy(e.exception),
                      pickle.loads(pickle.dumps(e.exception))):
            self.assertIsNone(clone.internal_error)
            self.assertNotIn('PRIVATE-FIXTURE-VALUE', repr(vars(clone)))

    def test_unknown_location_for_opaque_extension_error(self):
        events = []
        options = jmespath.Options(
            custom_functions=AlwaysFailingExtension(),
            diagnostics=diagnostics.Diagnostics(internal_sink=events.append))
        with self.assertRaises(RuntimeError):
            jmespath.search('"名称" | explode(@)', {'名称': 'x'},
                            options=options)
        event = events[-1]
        self.assertIsNone(event.span)
        self.assertEqual(event.location, diagnostics.LOCATION_UNKNOWN)
        self.assertEqual(event.phase, 'evaluation')

    def test_evaluator_error_points_at_call_site(self):
        events = []
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(internal_sink=events.append))
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('length(@)', 2, options=options)
        event = events[-1]
        self.assertEqual(event.span, CharacterSpan(0, 6))
        self.assertEqual(event.location, diagnostics.LOCATION_CALL_SITE)
        self.assertEqual(event.function_name, 'length')


class TestInterleavedScenario(unittest.TestCase):
    def test_cached_expression_interleaved_then_parse_failure(self):
        internal = []
        public = []
        compiled = jmespath.compile('"名称"."子字段" | boom(@)')
        options = make_options(
            SyntheticExtension(), internal_sink=internal.append,
            public_sink=public.append)

        self.assertEqual(
            compiled.search({'名称': {'子字段': 'first'}}, options=options),
            'ok:first')

        with self.assertRaises(diagnostics.PublicJMESPathError) as first:
            compiled.search({'名称': {'子字段': 'second'}}, options=options)

        with self.assertRaises(diagnostics.PublicJMESPathError) as second:
            jmespath.search('"名称" ]', {}, options=options)

        # The third query must not inherit anything from the failing one.
        self.assertEqual(
            compiled.search({'名称': {'子字段': 'third'}}, options=options),
            'ok:third')

        evaluation_report = public[0]
        parse_report = public[1]
        self.assertEqual(evaluation_report.phase, 'evaluation')
        self.assertIsNone(evaluation_report.span)
        self.assertEqual(evaluation_report.location, 'unknown')
        self.assertEqual(parse_report.phase, 'parser')
        self.assertEqual(parse_report.span, CharacterSpan(5, 6))
        self.assertEqual(parse_report.location, 'exact')
        self.assertNotEqual(evaluation_report.correlation_id,
                            parse_report.correlation_id)
        self.assertEqual(first.exception.correlation_id,
                         evaluation_report.correlation_id)
        self.assertEqual(second.exception.correlation_id,
                         parse_report.correlation_id)

        # The internal events join back to the public receipts by id.
        by_id = {event.correlation_id: event for event in internal}
        self.assertIn(evaluation_report.correlation_id, by_id)
        self.assertIn(parse_report.correlation_id, by_id)
        self.assertIsInstance(
            by_id[evaluation_report.correlation_id].exception, RuntimeError)
        self.assertEqual(
            by_id[parse_report.correlation_id].expression, '"名称" ]')


class TestOptInBehaviour(unittest.TestCase):
    def test_default_behaviour_is_unchanged(self):
        with self.assertRaises(exceptions.JMESPathTypeError) as e:
            jmespath.search('length(@)', 2)
        self.assertIn('invalid type for value: 2', str(e.exception))
        self.assertNotIsInstance(e.exception, diagnostics.PublicJMESPathError)

    def test_disabled_reporter_does_not_raise_public_errors(self):
        options = jmespath.Options(diagnostics=diagnostics.Diagnostics())
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('length(@)', 2, options=options)

    def test_public_reports_can_keep_original_exception(self):
        receipts = []
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(
                public=True, public_exception=False,
                public_sink=receipts.append))
        with self.assertRaises(exceptions.ParseError):
            jmespath.search('foo]x', {}, options=options)
        self.assertEqual(receipts[-1].phase, 'parser')
        self.assertEqual(receipts[-1].span, CharacterSpan(3, 4))

    def test_internal_sink_only_keeps_original_exception(self):
        events = []
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(internal_sink=events.append))
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('length(@)', 2, options=options)
        self.assertEqual(events[-1].phase, 'evaluation')
        self.assertEqual(events[-1].span, CharacterSpan(0, 6))

    def test_public_error_view_can_be_logged_without_sink(self):
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(public=True))
        with self.assertRaises(diagnostics.PublicJMESPathError) as e:
            jmespath.search('foo]', {}, options=options)
        report = e.exception.to_dict()
        self.assertEqual(report['phase'], 'parser')
        self.assertEqual(report['span'], {'start': 3, 'end': 4})
        self.assertIn(report['correlation_id'], str(e.exception))

    def test_empty_expression_is_lexer_phase(self):
        reports = []
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(
                public=True, public_sink=reports.append))
        with self.assertRaises(diagnostics.PublicJMESPathError):
            jmespath.search('', {}, options=options)
        self.assertEqual(reports[-1].phase, 'lexer')
        self.assertEqual(reports[-1].code, 'lexer.empty_expression')
        self.assertEqual(reports[-1].span, CharacterSpan(0, 0))

    def test_broken_sink_does_not_mask_query_failure(self):
        def explode(event):
            raise ValueError('sink is broken')
        options = jmespath.Options(
            diagnostics=diagnostics.Diagnostics(
                internal_sink=explode, public_sink=explode))
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('length(@)', 2, options=options)


if __name__ == '__main__':
    unittest.main()
