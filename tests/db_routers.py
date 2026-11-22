MAGIC_LINK_MODEL = "sesame_magiclink.MagicLink"

# Runtime, file-based SQLite alias created by the concurrency tests. It isn't
# declared in DATABASES, so the test runner never replaces it with an in-memory
# database. Toggled on only by the file-based concurrency tests; every other
# test keeps the MagicLink model on the default, in-memory test database.
FILE_DB_ALIAS = "magiclink_file"
FILE_DB_ACTIVE = False


class MagicLinkRouter:
    def _uses_file_db(self, model):
        return FILE_DB_ACTIVE and model._meta.label == MAGIC_LINK_MODEL

    def db_for_read(self, model, **hints):
        if self._uses_file_db(model):
            return FILE_DB_ALIAS
        return None

    def db_for_write(self, model, **hints):
        if self._uses_file_db(model):
            return FILE_DB_ALIAS
        return None

    def allow_relation(self, obj1, obj2, **hints):
        labels = {obj1._meta.label, obj2._meta.label}
        if MAGIC_LINK_MODEL in labels:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # The MagicLink migration is applied on every alias that needs it.
        if app_label == "sesame_magiclink":
            return True
        return None
