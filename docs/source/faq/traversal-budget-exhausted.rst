GETNEXT/GETBULK traversal budget exhausted
-----------------------------------------

Q. A manager walking a sparse view gets ``resourceUnavailable`` (or an
   ``authorizationError``/``genErr``) instead of the next OID, although the
   OIDs it is allowed to read do exist further on. What happened?

A. The command responders bound the work spent per request while
   resolving GETNEXT/GETBULK successors.

   A requester whose MIB view hides large parts of the tree forces the agent
   to examine every hidden candidate between two visible ones. Some MIB
   implementations can also fail to advance, or answer for an OID the
   requester cannot read. To keep one request from consuming unbounded CPU,
   each incoming PDU gets a *traversal candidate budget* that is shared by
   all varbinds in the request and by all GETBULK repetitions.

   Only candidates that are actually examined are counted. The two-phase
   ``readTestNext``/``readGetNext`` lookup of the same candidate counts as
   one unit, while a candidate re-examined during a later repetition counts
   again. The budget is reset for every incoming request.

   The resulting error is explicit and distinguishable from a completed
   walk:

   ``resourceUnavailable``
       The candidate budget ran out before a lexicographic successor could
       be established. This is **not** ``endOfMibView``: the view was not
       traversed to its end. ``error-index`` points at the varbind whose
       repetition hit the limit.

   ``genErr``
       The MIB instrumentation returned a value that does not
       lexicographically follow the requested OID, returned an SMIv2
       exception value other than ``endOfMibView``, or returned a wrong
       number of varbinds.

   ``authorizationError``
       The MIB instrumentation returned a value for a candidate that the
       requester's access control model does not permit. Neither the OID
       nor the value is included in the response.

   Adjust the limit at the responder that serves the context:

   .. code-block:: python

       from pysnmp.entity.rfc3413 import cmdrsp

       # More headroom for very sparse views
       cmdrsp.NextCommandResponder(
           snmpEngine, snmpContext, traversal_candidate_limit=20000
       )

       # Disable the limit (unbounded work; use with care)
       cmdrsp.BulkCommandResponder(
           snmpEngine, snmpContext, traversal_candidate_limit=None
       )

   The class attributes ``NextCommandResponder.traversal_candidate_limit``
   and ``BulkCommandResponder.traversal_candidate_limit`` change the default
   for subsequently created responders of that class.

   Programs that use :py:class:`~pysnmp.smi.instrum.MibInstrumController`
   directly can pass the same policy explicitly:

   .. code-block:: python

       from pysnmp.smi.budget import TraversalBudget

       budget = TraversalBudget(1000)
       controller.read_next_variables(("1.3.6.1.2.1.1.1.0", None),
                                      traversal_budget=budget)

   The number of candidates examined and the exact OIDs probed are available
   on the budget object (``examined`` and ``candidates``). Responders keep
   the budget of the most recent request on
   ``responder.last_traversal_budget``.

   Because these failures leave the agent in a clean state, a subsequent
   request within the configured limit is handled normally.
