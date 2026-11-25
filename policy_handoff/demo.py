"""Acceptance demo: revoking an extension function around in-flight queries.

The extensions are logging-only: every time a function body is actually
entered it appends a marker to ``extension_calls``.  ``audit_echo`` can block
on a threading gate so the main thread can change the permission while a
search is in flight.

Three searches demonstrate the handoff rules:

* search-1 enters ``audit_echo`` directly, is paused inside that body while
  the permission is revoked, then resumes and completes (a function already
  entered keeps running under the entry snapshot);
* search-2 enters ``audit_map`` (a higher order function) and, after the
  permission is revoked, reaches the deferred expression reference
  ``&audit_echo(@)``; the deferred reference re-checks the live policy and the
  search is cancelled before that nested function body runs;
* search-3 is a brand new request reusing the precompiled extension
  expression from the shared parser cache; it is blocked under the new
  revision, while a cached extension-free expression still works.

Every conclusion is read from the AuditLog records and the public results.
"""
import threading

import jmespath
from jmespath import functions
from jmespath import parser as parser_module
from jmespath.policy import ExtensionRevokedError


class Gate(object):
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()


class LoggingExtensions(functions.Functions):
    def __init__(self, extension_calls, echo_gate=None):
        super(LoggingExtensions, self).__init__()
        self._calls = extension_calls
        self._echo_gate = echo_gate

    @functions.signature({'types': ['string']})
    def _func_audit_echo(self, text):
        self._calls.append('audit_echo:body:%s' % text)
        if self._echo_gate is not None:
            self._echo_gate.entered.set()
            self._echo_gate.release.wait()
        return 'echo:%s' % text

    @functions.signature({'types': ['expref']}, {'types': ['array']})
    def _func_audit_map(self, expref, array):
        self._calls.append('audit_map:body')
        return [expref.visit(expref.expression, item) for item in array]


def in_cache(compiled):
    return compiled in parser_module.Parser._CACHE.values()


def main():
    parser_module.Parser.purge()
    extension_calls = []
    direct_gate = Gate()
    options = jmespath.Options(custom_functions=LoggingExtensions(
        extension_calls, echo_gate=direct_gate))
    policy = jmespath.Policy(allowed=['audit_echo', 'audit_map'])
    audit = jmespath.AuditLog()
    data = {'name': 'alpha', 'items': ['a', 'b']}

    # Precompile expressions; the shared cache must survive the revocation.
    compiled_echo = jmespath.compile('audit_echo(name)')
    compiled_builtin = jmespath.compile('length(name)')

    # -- search-1: function entered, then permission revoked mid-flight ----
    search1 = {}

    def run_direct():
        try:
            search1['result'] = jmespath.search(
                'audit_echo(name)', data, options, policy=policy,
                audit=audit, query_id='search-1')
        except ExtensionRevokedError as error:
            search1['error'] = error

    worker = threading.Thread(target=run_direct, name='direct')
    worker.start()
    direct_gate.entered.wait()
    revision = policy.revoke('audit_echo')
    direct_gate.release.set()
    worker.join()

    # -- search-2: deferred expression reference under the new policy ------
    deferred_options = jmespath.Options(
        custom_functions=LoggingExtensions(extension_calls))
    search2 = {}
    try:
        jmespath.search(
            'audit_map(&audit_echo(@), items)', data, deferred_options,
            policy=policy, audit=audit, query_id='search-2')
    except ExtensionRevokedError as error:
        search2['error'] = error

    # -- search-3: new request reusing the precompiled expressions ---------
    search3 = {}
    try:
        search3['echo'] = compiled_echo.search(
            data, options=options, policy=policy, audit=audit,
            query_id='search-3')
    except ExtensionRevokedError as error:
        search3['error'] = error
    search3['builtin'] = compiled_builtin.search(
        data, policy=policy, audit=audit, query_id='search-3b')

    report(audit, extension_calls, revision, search1, search2, search3,
           compiled_echo)
    return verify(audit, extension_calls, revision, search1, search2,
                  search3, compiled_echo)


def report(audit, extension_calls, revision, search1, search2, search3,
           compiled_echo):
    print('== Audit trail (real run records) ==')
    for record in audit.records:
        detail = ''
        if record['event'] == 'function_check':
            detail = ' function=%s checkpoint=%s allowed=%s' % (
                record['function'], record['checkpoint'],
                record['allowed'])
        print('  %-10s seq=%-2d rev=%s%s' % (
            record['query_id'], record['seq'],
            record.get('policy_revision'), detail))
    print('\n== Extension body entry log (where execution actually went) ==')
    for call in extension_calls:
        print('  ', call)
    print('\n== Public outcomes ==')
    print('   revoke revision      :', revision)
    print('   search-1 result      :', search1.get('result'),
          'error:', search1.get('error'))
    print('   search-2 error       :', search2.get('error'))
    print('   search-3 echo error  :', search3.get('error'))
    print('   search-3 builtin     :', search3['builtin'])
    print('   compiled echo cached :', in_cache(compiled_echo))


def verify(audit, extension_calls, revision, search1, search2, search3,
           compiled_echo):
    checks = []

    def expect(label, actual, expected):
        ok = actual == expected
        checks.append(ok)
        print('  [%s] %-46s got=%r want=%r' % (
            'PASS' if ok else 'FAIL', label, actual, expected))

    print('\n== Acceptance checks ==')

    s1 = audit.for_query('search-1')
    s1_check = [e for e in s1 if e['event'] == 'function_check'][0]
    expect('search-1 entered the extension body',
           extension_calls.count('audit_echo:body:alpha'), 1)
    expect('search-1 checked at function_entry',
           s1_check['checkpoint'], 'function_entry')
    expect('search-1 allowed under entry revision 0',
           (s1_check['allowed'], s1_check['policy_revision']), (True, 0))
    expect('search-1 completed and produced a result',
           (s1[-1]['event'], search1.get('result')),
           ('search_completed', 'echo:alpha'))

    s2 = audit.for_query('search-2')
    s2_checks = [e for e in s2 if e['event'] == 'function_check']
    expect('search-2 entered audit_map but not nested echo',
           extension_calls,
           ['audit_echo:body:alpha', 'audit_map:body'])
    expect('search-2 checkpoints',
           [(c['function'], c['checkpoint'], c['allowed'])
            for c in s2_checks],
           [('audit_map', 'function_entry', True),
            ('audit_echo', 'deferred_expression', False)])
    expect('search-2 cancelled under new revision',
           (s2[-1]['event'], s2_checks[-1]['policy_revision']),
           ('search_cancelled', revision))
    expect('search-2 raised at the deferred checkpoint',
           (search2['error'] is not None,
            getattr(search2.get('error'), 'checkpoint', None)),
           (True, 'deferred_expression'))

    s3 = audit.for_query('search-3')
    s3_check = [e for e in s3 if e['event'] == 'function_check'][0]
    expect('search-3 new request blocked at entry',
           (s3_check['allowed'], s3_check['policy_revision']),
           (False, revision))
    expect('search-3 cancelled without entering the body again',
           s3[-1]['event'], 'search_cancelled')
    expect('search-3 raised ExtensionRevokedError',
           search3.get('error') is not None, True)
    expect('cached extension expression retained',
           in_cache(compiled_echo), True)
    expect('cached extension-free path still evaluates',
           search3['builtin'], 5)
    return all(checks)


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
