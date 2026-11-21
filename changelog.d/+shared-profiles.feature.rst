Add versioned shared-libraries profiles for pip-backed environments. ``pipx profile declare NAME --requires 'pip<26.2'``
records a compatibility declaration without touching any running environment, ``pipx profile upgrade NAME`` upgrades only
that profile, and ``pipx install --profile NAME`` links a new environment to it. ``pipx profile list`` reports each
profile's declaration and users, ``pipx profile reclaim`` and ``pipx profile gc`` remove a profile once no environment
references it, and every environment records its profile so older environments keep their own pip.
