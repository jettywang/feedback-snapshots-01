Add ``stage_pass_env`` configuration to scope environment variables to a run stage (``deps`` or ``commands``), so CI
can hand short-lived credentials to the install stage of a shared tox process without exposing them to the test
commands; stage-scoped values are always masked in the command logs.
