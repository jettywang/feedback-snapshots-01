Add an optional execution plan: ``tox plan -o plan.json`` records the final targets, run order, prerequisites and the
commands, working directory, dependencies and variables of the environments that run project code without running any
project command. A run given the approved file with ``--plan`` checks its premises before executing anything and reports
which one changed when they differ, and ``--plan-out`` records the commands that actually executed, each matched to the
approved fact it belongs to.
