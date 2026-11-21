``pipx install --only-apps APP`` now installs a package and all its dependencies while publishing only the named entry
points. The selection is recorded, so ``upgrade``, ``reinstall``, ``expose``, and ``pipx manifest sync`` keep it, and a
failed upgrade leaves the existing commands in place.
