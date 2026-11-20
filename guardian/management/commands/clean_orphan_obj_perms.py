from django.core.management.base import BaseCommand

from guardian.utils import clean_orphan_obj_perms, find_orphan_obj_perms, remove_orphan_obj_perms


class Command(BaseCommand):
    """A wrapper around `guardian.utils.clean_orphan_obj_perms`.

    Seeks and removes all object permissions entries pointing at non-existing targets.
    Returns the number of objects removed.

    Example:
        ```shell
        $ python manage.py clean_orphan_obj_perms
        Removed 11 object permission entries with no targets

        $ python manage.py clean_orphan_obj_perms --batch-size 100 --max-batches 5
        Removed 500 object permission entries with no targets

        $ python manage.py clean_orphan_obj_perms --batch-size 50 --skip-batches 2 --max-duration-secs 60
        Removed 200 object permission entries with no targets

        $ python manage.py clean_orphan_obj_perms --dry-run
        contenttypes.contenttype [guardian.UserObjectPermission]: 11 entries

        $ python manage.py clean_orphan_obj_perms --checked
        Removed 10 object permission entries with no targets
        Skipped 1 entries (no longer orphan)
        ```
    """

    help = "Removes object permissions with not existing targets"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            help="Number of objects to process per batch. If not specified, all objects are processed at once.",
        )
        parser.add_argument(
            "--max-batches", type=int, help="Maximum number of batches to process. Use with --batch-size."
        )
        parser.add_argument(
            "--max-duration-secs", type=int, help="Maximum duration in seconds for the cleanup operation."
        )
        parser.add_argument(
            "--skip-batches",
            type=int,
            default=0,
            help="Number of batches to skip before starting cleanup. Use with --batch-size.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only preview orphan candidates, grouped by content type and permission model. " "Nothing is deleted.",
        )
        parser.add_argument(
            "--checked",
            action="store_true",
            help="Re-verify each candidate immediately before deleting it and report entries "
            "that were skipped because they are no longer orphan.",
        )

    def handle(self, **options):
        if options["dry_run"]:
            self._handle_dry_run(options["verbosity"])
            return

        if options["checked"]:
            self._handle_checked(options["verbosity"])
            return

        kwargs = {}

        if options["batch_size"] is not None:
            kwargs["batch_size"] = options["batch_size"]

        if options["max_batches"] is not None:
            kwargs["max_batches"] = options["max_batches"]

        if options["max_duration_secs"] is not None:
            kwargs["max_duration_secs"] = options["max_duration_secs"]

        if options["skip_batches"] > 0:
            kwargs["skip_batches"] = options["skip_batches"]

        removed = clean_orphan_obj_perms(**kwargs)

        if options["verbosity"] > 0:
            self.stdout.write("Removed %d object permission entries with no targets" % removed)

    def _handle_dry_run(self, verbosity):
        preview = find_orphan_obj_perms()

        if verbosity == 0:
            return

        if not preview.candidates:
            self.stdout.write("No orphan object permission entries found")
            return

        self.stdout.write("Orphan object permission candidates (no changes made):")
        for (content_type, perm_model), candidates in preview.groups.items():
            self.stdout.write("%s [%s]: %d entries" % (content_type, perm_model, len(candidates)))
            if verbosity > 1:
                for candidate in candidates:
                    self.stdout.write(
                        "  pk=%s object_pk=%s: %s" % (candidate.pk, candidate.object_pk, candidate.reason)
                    )

    def _handle_checked(self, verbosity):
        preview = find_orphan_obj_perms()
        removed, skipped = remove_orphan_obj_perms(preview.candidates)

        if verbosity > 0:
            self.stdout.write("Removed %d object permission entries with no targets" % removed)
            if skipped:
                self.stdout.write("Skipped %d entries (no longer orphan):" % len(skipped))
                for candidate, reason in skipped:
                    self.stdout.write("  %s pk=%s: %s" % (candidate.perm_model, candidate.pk, reason))
