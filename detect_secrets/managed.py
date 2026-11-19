"""
Managed run mode.

This supports deployments where the scanning service is maintained by a platform
team, but customers are allowed to submit their own baselines (policies). Since a
baseline can reference arbitrary third-party plugins and filters (which are executed
as code when loaded), the platform can enable managed mode to restrict which of
those third-party extensions a customer-supplied policy is allowed to load.

Built-in plugins and filters are always available, regardless of managed mode.
Third-party extensions (custom plugin files, or filters that don't ship with
detect-secrets) must be explicitly allowlisted by the platform; anything else is
skipped and a denial reason is recorded, without executing the referenced code.
"""
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set

from .core.log import log


_enabled = False
_allowed_plugin_paths: Set[str] = set()
_allowed_filter_paths: Set[str] = set()
_denial_reasons: List[str] = []


def enable_managed_mode(
    allowed_plugins: Optional[Iterable[str]] = None,
    allowed_filters: Optional[Iterable[str]] = None,
) -> None:
    """
    Enables managed mode, restricting which third-party extensions a policy can load.

    :param allowed_plugins: `path` values (as declared in a baseline's `plugins_used`
        entries, e.g. `file://path/to/plugin.py`) that are approved for loading.
    :param allowed_filters: filter paths (as declared in a baseline's `filters_used`
        entries) that are approved for loading.
    """
    global _enabled
    _enabled = True

    _allowed_plugin_paths.clear()
    _allowed_plugin_paths.update(allowed_plugins or [])

    _allowed_filter_paths.clear()
    _allowed_filter_paths.update(allowed_filters or [])

    _denial_reasons.clear()


def disable_managed_mode() -> None:
    global _enabled
    _enabled = False

    _allowed_plugin_paths.clear()
    _allowed_filter_paths.clear()
    _denial_reasons.clear()


def is_managed_mode() -> bool:
    return _enabled


def get_denial_reasons() -> List[str]:
    """Reasons for third-party extensions that were rejected while in managed mode."""
    return list(_denial_reasons)


def check_plugin(name: str, path: str) -> Optional[str]:
    """
    :return: None if the plugin is allowed to load; otherwise, the denial reason.
    """
    if not _enabled or path in _allowed_plugin_paths:
        return None

    return (
        f'Managed mode: third-party plugin "{name}" ({path}) is not in the '
        'platform allowlist. Skipping.'
    )


def check_filter(path: str) -> Optional[str]:
    """
    :return: None if the filter is allowed to load; otherwise, the denial reason.
    """
    if not _enabled or _is_builtin_filter(path) or path in _allowed_filter_paths:
        return None

    return (
        f'Managed mode: third-party filter "{path}" is not in the '
        'platform allowlist. Skipping.'
    )


def record_denial(reason: str) -> None:
    _denial_reasons.append(reason)
    log.warning(reason)


def get_policy() -> Dict[str, Any]:
    """Serializes the managed mode policy, e.g. for propagation to child processes."""
    return {
        'enabled': _enabled,
        'allowed_plugins': sorted(_allowed_plugin_paths),
        'allowed_filters': sorted(_allowed_filter_paths),
    }


def restore_policy(policy: Dict[str, Any]) -> None:
    """Restores a policy serialized through `get_policy` (e.g. in a child process)."""
    if policy.get('enabled'):
        enable_managed_mode(
            allowed_plugins=policy.get('allowed_plugins'),
            allowed_filters=policy.get('allowed_filters'),
        )
    else:
        disable_managed_mode()


def _is_builtin_filter(path: str) -> bool:
    # Built-in filters are referenced by their python module path, within this package.
    # Anything else (e.g. `file://` references, or other modules) is third-party.
    return '://' not in path and path.startswith('detect_secrets.')
