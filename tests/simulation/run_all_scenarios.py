"""Print the three required walks (plus two boundaries) as request timelines.

    .venv/bin/python -m tests.simulation.run_all_scenarios
"""

from __future__ import annotations

import requests

from .pool import ClientPool, DeploymentLease
from .vault_sim import FakeVault, Fault, render_timeline


def walk(title: str, *, mode: str = "happy", cookie: bool = False, lying: bool = False) -> None:
    vault = FakeVault(issue_task_cookie=cookie, revoke_is_noop=lying)
    with vault:
        pool = ClientPool(vault)
        lease = DeploymentLease(pool, vault, idempotency_key=f"demo-{mode}")
        if mode == "refused":
            vault.inject(Fault("task.execute", "reject", "service refused the revision"))
        if mode == "uncertain":
            vault.inject(Fault("task.execute", "lost_after_commit", "response lost after commit"))
        lease.claim()
        try:
            lease.execute()
        except (requests.exceptions.ConnectionError, Exception):
            pass
        decision = lease.finish(unresolved_outcome=mode == "uncertain")
        print(render_timeline(vault.rows(), title))
        print()
        print(f"decision: `{decision.action}` — {decision.reason}")
        print(f"commits: {sorted(vault.commits)}; pool: {pool.stats}")
        print("\n" + "=" * 78 + "\n")


def main() -> None:
    walk("Walk 1: identity switch succeeds", mode="happy")
    walk("Walk 2: service refuses the deployment", mode="refused")
    walk("Walk 3: response uncertain after server commit", mode="uncertain")
    walk("Boundary A: revoke reports success but the token survives", lying=True)
    walk("Boundary B: credential dies but the session carries a task cookie", cookie=True)


if __name__ == "__main__":
    main()
