Symbol Table Isolation and Type Template Caching
=================================================

A single Volatility process can analyse more than one memory image at a time,
including images produced by different kernel versions. Their Intermediate
Symbol Format (ISF) files routinely define structures with identical names but
incompatible layouts. This page documents which parts of the type system are
shared safely and which state belongs to a single symbol table, so that
interpreting one kernel can never silently change how another kernel is
interpreted.

What may be reused across symbol tables
---------------------------------------

The following are stateless or immutable once published and are safe to share:

* The raw ISF JSON object held by a table is read-only after construction.
* Object and template Python classes (``StructType``, ``Pointer`` and the
  framework extension classes such as ``_EPROCESS``) are reusable; they carry no
  per-table layout data themselves.
* Native *format definitions* (size, endianness and signedness) are reused as
  the dictionary from which each table builds its own native table.
* :class:`~volatility3.framework.objects.templates.ReferenceTemplate` objects and
  the table mapping machinery. A reference such as ``nt_symbols!_task`` is
  rewritten through the owning table's ``table_mapping`` at load time, so
  legitimate cross-table references continue to resolve while two contexts may
  map the same reference to different concrete tables.

What must belong to one symbol table
------------------------------------

The following state is per-table and must never be aliased across tables:

* The table's :class:`~volatility3.framework.symbols.native.NativeTable`. Each
  table receives an independent copy via
  :func:`~volatility3.framework.interfaces.symbols.NativeTableInterface.copy`,
  named ``<table>_natives``. The copy owns its name (which prefixes native type
  names such as ``table!pointer``) and its class overrides. Legacy ISF readers
  previously returned the process-wide ``native.x86NativeTable`` /
  ``native.x64NativeTable`` singletons and renamed them in place, leaking one
  table's name into every other table; those singletons are now never mutated.
* The class override dictionary (``set_type_class`` / ``del_type_class``).
  Overrides apply only to the table that registered them.
* The resolved-template cache inside
  :class:`~volatility3.framework.symbols.SymbolSpace`. Cache keys are always
  qualified (``table!type``), so same-named types of different kernels cache
  independently.

Template cache boundaries
-------------------------

``SymbolSpace`` permanently caches the fully resolved templates returned by
``get_type``, including the object class bound when the template was built.
When a class override changes how a table constructs templates,
:func:`~volatility3.framework.interfaces.symbols.SymbolSpaceInterface.invalidate_table_caches`
drops every cached entry belonging to that table (and its native table) as one
closure, then calls the table's own ``clear_symbol_cache``. Entries keyed to
other tables are left untouched.

Dropping only individual cache entries would be unsafe: a parent template may
already hold a resolved child in its member list, so it could outlive a child
that no longer matches the cache. Whole-table invalidation rebuilds the full
reference closure on the next resolution.

Already constructed objects are frozen
---------------------------------------

Object templates returned before an override, and objects already instantiated
from them, keep the class and layout they were built with. The
:class:`~volatility3.framework.interfaces.objects.Template` ``clone``/``vol``
contract means later ``update_vol`` changes and cache rebuilds never reach an
existing object. Only templates resolved (and objects constructed) after the
override use the new class. This prevents an in-flight analysis object from
changing interpretation underneath the caller.

A pre-existing defect in ``AggregateType``'s template proxy meant
``replace_child`` looked up a non-existent nested ``members`` key, so struct and
union member references were never substituted with their resolved templates.
Fixing this allows nested member references to resolve correctly after a cache
invalidation.

Verifying the boundaries
------------------------

The regression suite ``test/test_symbol_table_isolation.py`` interleaves two
minimal ISFs that define a same-named ``_task`` structure with different
layouts, then asserts that:

* the same address is read as a different structure through each table;
* reverse symbol lookup is scoped to the requested table;
* native tables are independent and the shared singletons keep their name;
* a class override on one table neither changes the other table nor mutates
  objects already created;
* nested struct/union references resolve after an override; and
* a ``table_mapping`` cross-table reference is honoured, while an independent
  context can map the same reference elsewhere.
