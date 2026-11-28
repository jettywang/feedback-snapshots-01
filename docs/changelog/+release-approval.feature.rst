Add the ``approved_env_list`` core configuration and the ``--release`` flag: release runs select only the approved
environments (matched by exact expanded name, including required packaging environments), report newly added
unapproved targets, and leave them available for personal development runs; ``tox list`` marks each environment with
its approval status.
