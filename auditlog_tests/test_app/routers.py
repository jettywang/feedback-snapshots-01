class BusinessRouter:
    """Route the audited test model to a separate ``business`` database.

    ``auditlog`` itself never passes ``using=``: ``LogEntry`` therefore keeps
    using the default database. This router makes that split explicit.
    """

    def db_for_read(self, model, **hints):
        if model._meta.app_label == "test_app":
            return "business"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == "test_app":
            return "business"
        return None
