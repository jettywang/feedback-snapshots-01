``pipx manifest sync --policy POLICY [--verify]`` checks each declared lock against a local approval policy before
installing or exposing anything. ``--verify`` reads the manifest and locks only, names the intent each lock matches,
and reports any dependency left for human review as ``needs_review``. A ``sync`` with ``--policy`` that fails the check
stops before the first lock, environment, or app link is touched.
