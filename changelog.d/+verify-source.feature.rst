``pipx reinstall`` and ``pipx reinstall-all`` gained an opt-in ``--verify-source`` check: before rebuilding an
environment from a local source directory, pipx compares the directory against the fingerprint (content and
owning account) recorded at install time. When the directory changed, changed hands, or predates recording, the
reinstall holds, the environment and its commands stay as they are, and pipx writes a JSON review report under
the logs directory; an approved reinstall writes the same report, pairing the decision with the source and the
pip arguments it replayed, so the run can be reconciled with what was approved.
