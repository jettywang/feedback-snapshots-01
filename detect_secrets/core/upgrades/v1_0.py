import os
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import List
from typing import Tuple

from ...exceptions import InvalidFile
from .. import plugins
from ..plugins.util import get_plugins_from_file


# Plugins that were renamed before the v1.0.0 release. The detection semantics (including the
# `secret_type` written into each result) did not change, so audited findings can be carried over
# untouched once the plugin reference is rewritten.
RENAMED_PLUGINS: Dict[str, str] = {
    'BasicOAuthDetector': 'SquareOAuthDetector',
}


def upgrade(baseline: Dict[str, Any]) -> None:
    for function in [
        _migrate_filters,
        _rename_high_entropy_string_arguments,
        _migrate_custom_plugins,
        _rename_plugins,
    ]:
        function(baseline)


def _rename_plugins(baseline: Dict[str, Any]) -> None:
    """
    Some plugins were renamed in the lead-up to v1.0.0. A straightforward rename is only safe
    when the current library can initialize the replacement with the exact configuration carried
    over from the old baseline. Otherwise, the entry is kept for manual review, and a structured
    report of every renamed entry is attached to the baseline so that ambiguous configurations can
    be handed back to the original reviewer.
    """
    report = {
        'renamed': [],
        'needs_review': [],
        'unloadable': [],
    }
    baseline.pop('plugin_upgrades', None)

    for plugin in cast(List[Dict[str, Any]], baseline.get('plugins_used', [])):
        old_name = plugin.get('name')
        new_name = RENAMED_PLUGINS.get(old_name)
        if not new_name:
            continue

        entry = {
            'old_name': old_name,
            'new_name': new_name,
            'config': {
                key: value
                for key, value in plugin.items()
                if key != 'name'
            },
        }

        status, detail = _classify_renamed_plugin(new_name, entry['config'])
        if status == 'renamed':
            plugin['name'] = new_name
            report['renamed'].append(entry)
        elif status == 'needs_review':
            entry['reason'] = detail
            report['needs_review'].append(entry)
        else:
            entry['reason'] = detail
            report['unloadable'].append(entry)

    if any(report.values()):
        baseline['plugin_upgrades'] = report


def _classify_renamed_plugin(
    new_name: str,
    config: Dict[str, Any],
) -> Tuple[str, str]:
    try:
        plugin = plugins.initialize.from_plugin_classname(new_name)
    except TypeError:
        return (
            'unloadable',
            f'No such `{new_name}` plugin exists in this detect-secrets version.',
        )

    try:
        plugin.__class__(**config)
    except TypeError as error:
        return (
            'needs_review',
            f'Configuration is not accepted by `{new_name}`: {error}',
        )

    return 'renamed', ''


def _migrate_filters(baseline: Dict[str, Any]) -> None:
    """
    In v1.0.0, we introduced the idea of `filters`. This consolidated a variety of different
    false positive filters into a configurable layout. To reduce upgrade friction, this will
    contain the default filters used before this version upgrade.
    """
    baseline['filters_used'] = [
        {
            'path': 'detect_secrets.filters.allowlist.is_line_allowlisted',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_sequential_string',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_potential_uuid',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_likely_id_string',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_templated_secret',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign',
        },
        {
            'path': 'detect_secrets.filters.heuristic.is_indirect_reference',
        },
        {
            'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',

            # Hard-code this, just in case VerifiedResult enum values changes.
            # This corresponds to VerifiedResult.UNVERIFIED
            'min_level': 2,
        },
    ]

    if baseline.get('exclude'):
        if baseline['exclude'].get('files'):
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': [
                    baseline['exclude']['files'],
                ],
            })

        if baseline['exclude'].get('lines'):
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': [
                    baseline['exclude']['lines'],
                ],
            })

        baseline.pop('exclude')

    if baseline.get('word_list'):
        if baseline['word_list']['file']:
            baseline['filters_used'].append({
                'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
                'min_length': 3,
                'file_name': baseline['word_list']['file'],
                'file_hash': baseline['word_list']['hash'],
            })

        baseline.pop('word_list')


def _rename_high_entropy_string_arguments(baseline: Dict[str, Any]) -> None:
    """
    During the great refactor for v1.0.0, we also decided to rename these arguments for
    consistency and simplicity.
    """
    for plugin in baseline['plugins_used']:
        if plugin['name'] == 'Base64HighEntropyString':
            plugin['limit'] = plugin.pop('base64_limit')

        elif plugin['name'] == 'HexHighEntropyString':
            plugin['limit'] = plugin.pop('hex_limit')

    # TODO: KeywordDetector?


def _migrate_custom_plugins(baseline: Dict[str, Any]) -> None:
    if 'custom_plugin_paths' not in baseline:
        return

    for path in baseline['custom_plugin_paths']:
        try:
            # NOTE: We don't want to use `detect_secrets.core.plugins.initialize.from_file`
            # since we don't want to *initialize* these plugins. That will pollute our global
            # settings object. Instead, we're merely "parsing" this file, and applying changes
            # as necessary.
            custom_plugins = cast(Iterable, get_plugins_from_file(path))
        except InvalidFile:
            # Best effort upgrade. Don't break if invalid file.
            continue

        for plugin in custom_plugins:
            baseline['plugins_used'].append({
                'name': plugin.__name__,
                'path': f'file://{os.path.abspath(path)}',
            })

    del baseline['custom_plugin_paths']
