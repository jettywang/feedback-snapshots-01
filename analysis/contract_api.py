"""
Caller-facing adapter that makes the THREE matching semantics explicit and
keeps the library's coverage limits visible in the returned types.

It deliberately does NOT pretend that stix2-matcher performs full hit
enumeration.  Each function is named for the question it can actually answer,
and each documents its dedup granularity.
"""
from stix2matcher.matcher import Pattern, MatchListener

DEFAULT_VERSION = "2.0"


def _listener(pattern, observations, stix_version):
    p = Pattern(pattern, stix_version)
    ml = MatchListener(observations, stix_version=stix_version)
    p.walk(ml)
    return ml


def matches(pattern, observations, stix_version=DEFAULT_VERSION):
    """(E) EXISTENCE.  True iff at least one satisfying binding exists.

    Sound and complete for the boolean 'does the pattern match?' question.
    This is the only semantic the one-sided OR optimization never affects.
    """
    ml = _listener(pattern, observations, stix_version)
    return next(ml.matched(), None) is not None


def witness(pattern, observations, stix_version=DEFAULT_VERSION):
    """(W) ONE SUFFICIENT WITNESS.  SDOs from a single satisfying binding.

    Returns [] when there is no match.  A witness PROVES existence but is not
    the unique hit and is not exhaustive: under OR it is one-sided, and its
    identity depends on input/branch ordering.  Do not treat its absence from
    the list as 'this SDO did not match'.  Treat the list only as evidence.
    """
    ml = _listener(pattern, observations, stix_version)
    first_binding = next(ml.matched(), [])
    return ml.get_sdos_from_binding(first_binding)


def matched_sdo_index_set(pattern, observations, stix_version=DEFAULT_VERSION):
    """(N-LIMITED) SDO-level union over ALL bindings the engine emits.

    Dedup granularity = observed-data SDO index.  Returns the set of SDO
    indices that participate in AT LEAST ONE emitted binding.

    Coverage limits (must be enforced by the caller's contract):
      * OR only emits one-sided bindings, so this is 'satisfies >= 1 branch',
        never a per-branch hit map, and never includes two-sided assignments.
      * number_observed instances are collapsed: matched() maps inst_idx>0 to
        None, so repeated instances of one SDO count ONCE.  The result is a
        set of SDOs, not a multiset of observation instances.
      * It is the union across a *partial* binding space, so even this set is
        not guaranteed to equal the logical 'every satisfying observation'
        under arbitrary nesting.  Use for prioritization, not for compliance
        assertions that require completeness.
    """
    ml = _listener(pattern, observations, stix_version)
    return {idx for binding in ml.matched() for idx in binding if idx is not None}
