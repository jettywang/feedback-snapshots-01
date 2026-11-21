Add ``PIPX_INSTALL_ENV_ALLOWLIST`` to limit the environment variables installer subprocesses (``pip`` and ``uv``)
inherit to a comma-separated allowlist, and ``PIPX_APP_ENV_ALLOWLIST`` (with per-app
``PIPX_APP_ENV_ALLOWLIST_<APP>`` overrides) to do the same for launched apps, so install credentials do not leak
into them.
