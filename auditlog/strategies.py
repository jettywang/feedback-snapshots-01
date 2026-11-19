class M2mLogStrategy:
    """
    Controls how objects involved in a many-to-many change are represented in
    the log entry's ``changes``.

    ``STR`` stores each related object's string representation (``str(obj)``),
    which is the historical behaviour but may disclose sensitive data such as a
    customer's email address.

    ``PK`` stores only the primary key of each related object. This reveals no
    business data while staying stable across renames, so events for the same
    object can still be correlated and two objects sharing a name can be told
    apart.
    """

    STR = "str"
    PK = "pk"

    choices = (
        (STR, "string representation"),
        (PK, "primary key"),
    )
