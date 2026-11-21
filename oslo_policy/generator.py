#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from collections.abc import Generator, Sequence
import importlib.metadata
import logging
import sys
import textwrap
from typing import Any
import warnings
import yaml

from oslo_config import cfg
from oslo_serialization import jsonutils
import stevedore

from oslo_policy import policy

LOG = logging.getLogger(__name__)

GENERATOR_OPTS = [
    cfg.StrOpt(
        'output-file', help='Path of the file to write to. Defaults to stdout.'
    ),
    cfg.BoolOpt(
        'exclude-deprecated',
        default=False,
        help='If True, exclude deprecated entries from the generated output.',
    ),
]

RULE_OPTS = [
    cfg.MultiStrOpt(
        'namespace',
        help='Option namespace(s) under "oslo.policy.policies" in '
        'which to query for options.',
    ),
]

ENFORCER_OPTS = [
    cfg.StrOpt(
        'namespace',
        help='Option namespace under "oslo.policy.enforcer" in '
        'which to look for a policy.Enforcer.',
    ),
]

UPGRADE_OPTS = [
    cfg.StrOpt(
        'policy',
        required=True,
        help='Path to the policy file which need to be updated.',
    )
]

CONVERT_OPTS = [
    cfg.MultiStrOpt(
        'namespace',
        required=True,
        help='Option namespace(s) under "oslo.policy.policies" in '
        'which to query for options.',
    ),
    cfg.StrOpt(
        'policy-file',
        required=True,
        help='Path to the policy file which need to be converted to '
        'yaml format.',
    ),
]

SOURCE_CHECK_OPTS = [
    cfg.StrOpt(
        'approved-overrides',
        help='Path to a YAML file listing the rule overrides approved by the '
        'site. Every entry is checked against the actual rule '
        'registrations and listed explicitly in the report.',
    ),
]


def get_policies_dict(
    namespaces: Sequence[str],
) -> dict[str, list[policy.RuleDefault]]:
    """Find the options available via the given namespaces.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies'
    :returns: a dict of {namespace1: [rule_default_1, rule_default_2],
                         namespace2: [rule_default_3]...}
    """
    mgr: stevedore.named.NamedExtensionManager[list[policy.RuleDefault]]
    mgr = stevedore.named.NamedExtensionManager(
        'oslo.policy.policies',
        names=namespaces,
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True,
    )
    opts = {ep.name: ep.obj for ep in mgr}

    # we know the values of this dict are non-None due to invoke_on_load=True
    return opts  # type: ignore


def _get_enforcer(namespace: str) -> policy.Enforcer:
    """Find a policy.Enforcer via an entry point with the given namespace.

    :param namespace: a namespace under oslo.policy.enforcer where the desired
                      enforcer object can be found.
    :returns: a policy.Enforcer object
    """
    mgr: stevedore.named.NamedExtensionManager[policy.Enforcer]
    mgr = stevedore.named.NamedExtensionManager(
        'oslo.policy.enforcer',
        names=[namespace],
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True,
    )
    if namespace not in mgr:
        raise KeyError(f'Namespace "{namespace}" not found.')
    enforcer = mgr[namespace].obj

    # we know this will always be non-None due to invoke_on_load=True
    assert enforcer is not None  # narrow type

    return enforcer


def _format_help_text(description: str | None) -> str:
    """Format a comment for a policy based on the description provided.

    :param description: A string with helpful text.
    :returns: A line wrapped comment, or blank comment if description is None
    """
    if not description:
        return '#'

    formatted_lines: list[str] = []
    paragraph: list[str] = []

    def _wrap_paragraph(lines: Sequence[str]) -> list[str]:
        return textwrap.wrap(
            ' '.join(lines), 70, initial_indent='# ', subsequent_indent='# '
        )

    for line in description.strip().splitlines():
        if not line.strip():
            # empty line -> line break, so dump anything we have
            formatted_lines.extend(_wrap_paragraph(paragraph))
            formatted_lines.append('#')
            paragraph = []
        elif len(line) == len(line.lstrip()):
            # no leading whitespace = paragraph, which should be wrapped
            paragraph.append(line.rstrip())
        else:
            # leading whitespace - literal block, which should not be wrapping
            if paragraph:
                # ...however, literal blocks need a new line before them to
                # delineate things
                # TODO(stephenfin): Raise an exception here and stop doing
                # anything else in oslo.policy 2.0
                warnings.warn(
                    'Invalid policy description: literal blocks must be '
                    'preceded by a new line. This will raise an exception in '
                    f'a future version of oslo.policy:\n{description}',
                    FutureWarning,
                )
                formatted_lines.extend(_wrap_paragraph(paragraph))
                formatted_lines.append('#')
                paragraph = []

            formatted_lines.append(f'# {line.rstrip()}')

    if paragraph:
        # dump anything we might still have in the buffer
        formatted_lines.extend(_wrap_paragraph(paragraph))

    return '\n'.join(formatted_lines)


def _format_rule_default_yaml(
    default: policy.RuleDefault,
    include_help: bool = True,
    comment_rule: bool = True,
    add_deprecated_rules: bool = True,
) -> str:
    """Create a yaml node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param comment_rule: By default rules will be commented out in generated
                         yaml format text. If you want to keep few or all rules
                         uncommented then pass this arg as False.
    :param add_deprecated_rules: Whether to add the deprecated rules in format
                                 text.
    :returns: A string containing a yaml representation of the RuleDefault
    """  # noqa: E501
    text = f'"{default.name}": "{default.check_str}"\n'

    if include_help:
        op = ''
        if hasattr(default, 'operations'):
            for operation in default.operations:
                if operation['method'] and operation['path']:
                    op += '# {method}  {path}\n'.format(
                        method=operation['method'],
                        path=operation['path'],
                    )
        intended_scope = ''
        if default.scope_types is not None:
            intended_scope = (
                '# Intended scope(s): ' + ', '.join(default.scope_types) + '\n'
            )
        comment = '#' if comment_rule else ''
        text = f'{op}{intended_scope}{comment}{text}\n'
        if default.description:
            text = _format_help_text(default.description) + '\n' + text

    if add_deprecated_rules and default.deprecated_for_removal:
        text = (
            f'# DEPRECATED\n# "{default.name}" has been deprecated since '
            f'{default.deprecated_since}.\n'
            f'{_format_help_text(default.deprecated_reason)}\n{text}'
        )
    elif add_deprecated_rules and default.deprecated_rule:
        deprecated_reason = (
            default.deprecated_rule.deprecated_reason
            or default.deprecated_reason
        )
        deprecated_since = (
            default.deprecated_rule.deprecated_since
            or default.deprecated_since
        )

        # This issues a deprecation warning but aliases the old policy name
        # with the new policy name for compatibility.
        deprecated_text = (
            f'"{default.deprecated_rule.name}":"{default.deprecated_rule.check_str}" has been deprecated '  # noqa: E501
            f'since {deprecated_since} in favor of "{default.name}":"{default.check_str}".'  # noqa: E501
        )
        text = (
            f'{text}# DEPRECATED\n{_format_help_text(deprecated_text)}\n'
            f'{_format_help_text(deprecated_reason)}\n'
        )

        if default.name != default.deprecated_rule.name:
            text += (
                '# WARNING: A rule name change has been identified.\n'
                '#          This may be an artifact of new rules being\n'
                '#          included which require legacy fallback\n'
                '#          rules to ensure proper policy behavior.\n'
                '#          Alternatively, this may just be an alias.\n'
                '#          Please evaluate on a case by case basis\n'
                '#          keeping in mind the format for aliased\n'
                '#          rules is:\n'
                '#          "old_rule_name": "new_rule_name".\n'
            )
            text += (
                f'# "{default.deprecated_rule.name}": "rule:{default.name}"\n'
            )
        text += '\n'

    return text


def _sort_and_format_by_section(
    policies: dict[str, list[policy.RuleDefault]],
    include_help: bool = True,
    exclude_deprecated: bool = False,
) -> Generator[str, None, None]:
    """Generate a list of policy section texts

    The text for a section will be created and returned one at a time. The
    sections are sorted first to provide for consistent output.

    Text is created in yaml format. This is done manually because PyYaml
    does not facilitate outputing comments.

    :param policies: A dict of {section1: [rule_default_1, rule_default_2],
                                section2: [rule_default_3]}
    :param include_help: True, generates a sample-policy file with help text
                         along with rules in which everything is commented out.
                         False, generates a sample-policy file with only rules.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
    """
    for section in sorted(policies.keys()):
        rule_defaults = policies[section]
        for rule_default in rule_defaults:
            yield _format_rule_default_yaml(
                rule_default,
                include_help=include_help,
                add_deprecated_rules=not exclude_deprecated,
            )


def _generate_sample(
    namespaces: list[str],
    output_path: str | None = None,
    include_help: bool = True,
    exclude_deprecated: bool = False,
) -> None:
    """Generate a sample policy file.

    List all of the policies available via the namespace specified in the
    given configuration and write them to the specified output file.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies'. Stevedore will look here for
                       policy options.
    :param output_path: The path of a file to output to. stdout used if None.
    :param include_help: True, generates a sample-policy file with help text
                         along with rules in which everything is commented out.
                         False, generates a sample-policy file with only rules.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
    """
    policies = get_policies_dict(namespaces)

    output_file = open(output_path, 'w') if output_path else sys.stdout

    sections_text = []
    for section in _sort_and_format_by_section(
        policies,
        include_help=include_help,
        exclude_deprecated=exclude_deprecated,
    ):
        sections_text.append(section)

    output_file.writelines(sections_text)

    if output_file != sys.stdout:
        output_file.close()


def _generate_policy(
    namespace: str,
    output_path: str | None = None,
    exclude_deprecated: bool = False,
) -> None:
    """Generate a policy file showing what will be used.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param output_path: The path of a file to output to. stdout used if None.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
    """
    enforcer = _get_enforcer(namespace)
    # Ensure that files have been parsed
    enforcer.load_rules()

    file_rules = [
        policy.RuleDefault(name, default.check_str)
        for name, default in enforcer.file_rules.items()
    ]
    registered_rules = [
        policy.RuleDefault(name, default.check_str)
        for name, default in enforcer.registered_rules.items()
        if name not in enforcer.file_rules
    ]
    policies = {'rules': file_rules + registered_rules}

    output_file = open(output_path, 'w') if output_path else sys.stdout

    for section in _sort_and_format_by_section(
        policies, include_help=False, exclude_deprecated=exclude_deprecated
    ):
        output_file.write(section)

    if output_file != sys.stdout:
        output_file.close()


def _list_redundant(namespace: str) -> None:
    """Generate a list of configured policies which match defaults.

    This checks all policies loaded from policy files and checks to see if they
    match registered policies. If so then it is redundant to have them defined
    in a policy file and operators should consider removing them.
    """
    enforcer = _get_enforcer(namespace)
    # NOTE(bnemec): We don't want to see policy deprecation warnings in the
    # output of this tool. They tend to overwhelm the output that the user
    # actually cares about, and checking for deprecations isn't the purpose of
    # this tool.
    enforcer.suppress_deprecation_warnings = True
    # Ensure that files have been parsed
    enforcer.load_rules()

    for name, file_rule in enforcer.file_rules.items():
        reg_rule = enforcer.registered_rules.get(name)
        if reg_rule:
            if file_rule == reg_rule:
                print(reg_rule)


def _validate_policy(namespace: str) -> int:
    """Perform basic sanity checks on a policy file

    Checks for the following errors in the configured policy file:

    * A missing policy file
    * Rules which have invalid syntax
    * Rules which reference non-existent other rules
    * Rules which form a cyclical reference with another rule
    * Rules which do not exist in the specified namespace

    :param namespace: The name under which the oslo.policy enforcer is
                      registered.
    :returns: 0 if all policies validated correctly, 1 if not.
    """
    return_code = 0
    enforcer = _get_enforcer(namespace)
    # NOTE(bnemec): We don't want to see policy deprecation warnings in the
    # output of this tool. They tend to overwhelm the output that the user
    # actually cares about. If we check for deprecated rules in this tool,
    # we need to do it another way.
    enforcer.suppress_deprecation_warnings = True
    # Disable logging from the parser code. We'll be printing any errors we
    # find below.
    logging.disable(logging.ERROR)
    # Ensure that files have been parsed
    enforcer.load_rules()

    if enforcer._informed_no_policy_file:
        print(f'Configured policy file "{enforcer.policy_file}" not found')
        # If the policy file is completely missing then the rest of our checks
        # don't make sense.
        return 1

    # Re-enable logging so we get messages for things like cyclical references
    logging.disable(logging.NOTSET)
    result = enforcer.check_rules()
    if not result:
        print('Invalid rules found')
        return_code = 1

    # TODO(bnemec): Allow this to handle policy_dir
    with open(cfg.CONF.oslo_policy.policy_file) as f:
        unparsed_policies = yaml.safe_load(f.read())
    for name, file_rule in enforcer.file_rules.items():
        reg_rule = enforcer.registered_rules.get(name)
        if reg_rule is None:
            print('Unknown rule found in policy file:', name)
            return_code = 1
        # If a rule has invalid syntax it will be forced to '!'. If the literal
        # rule from the policy file isn't '!' then this means there was an
        # error parsing it.
        if str(enforcer.rules[name]) == '!' and unparsed_policies[name] != '!':
            print('Failed to parse rule:', unparsed_policies[name])
            return_code = 1
    return return_code


def _convert_policy_json_to_yaml(
    namespace: str, policy_file: str, output_path: str | None = None
) -> None:
    with open(policy_file) as rule_data:
        file_policies = jsonutils.loads(rule_data.read())

    yaml_format_rules = []
    default_policies = get_policies_dict(namespace)
    for section in sorted(default_policies):
        default_rules = default_policies[section]
        for default_rule in default_rules:
            if default_rule.name not in file_policies:
                continue
            file_rule_check_str = file_policies.pop(default_rule.name)
            # Some rules might be still RuleDefault object so let's prepare
            # empty 'operations' list and rule name as description for
            # those.
            operations: list[policy.Operation] = [{'method': '', 'path': ''}]
            if hasattr(default_rule, 'operations'):
                operations = default_rule.operations
            # Converting JSON file rules to DocumentedRuleDefault rules so
            # that we can convert the JSON file to YAML including
            # descriptions which is what 'oslopolicy-sample-generator'
            # tool does.
            file_rule = policy.DocumentedRuleDefault(
                default_rule.name,
                file_rule_check_str,
                default_rule.description or default_rule.name,
                operations,
                default_rule.deprecated_rule,
                default_rule.deprecated_for_removal,
                default_rule.deprecated_reason,
                default_rule.deprecated_since,
                scope_types=default_rule.scope_types,
            )
            if file_rule == default_rule:
                rule_text = _format_rule_default_yaml(
                    file_rule, add_deprecated_rules=False
                )
            else:
                # NOTE(gmann): If json file rule is not same as default
                # means rule is overridden then do not comment out it in
                # yaml file.
                rule_text = _format_rule_default_yaml(
                    file_rule, comment_rule=False, add_deprecated_rules=False
                )
            yaml_format_rules.append(rule_text)

    extra_rules_text = (
        '# WARNING: Below rules are either deprecated rules\n'
        '# or extra rules in policy file, it is strongly\n'
        '# recommended to switch to new rules.\n'
    )
    # NOTE(gmann): If policy json file still using the deprecated rules which
    # will not be present in default rules list. Or it can be case of any
    # extra rule (old rule which is now removed) present in json file.
    # so let's keep these as it is (not commented out) to avoid breaking
    # existing deployment.
    if file_policies:
        yaml_format_rules.append(extra_rules_text)
    for file_rule, check_str in file_policies.items():
        rule_text = f'"{file_rule}": "{check_str}"\n'
        yaml_format_rules.append(rule_text)

    if output_path:
        with open(output_path, 'w') as fh:
            fh.writelines(yaml_format_rules)
    else:
        sys.stdout.writelines(yaml_format_rules)


def _load_approved_overrides(
    path: str,
) -> dict[str, dict[str, Any]]:
    """Load the site-approved rule overrides from a YAML file.

    The file must contain a top-level ``overrides`` mapping of rule name to
    either a plain check string or a mapping with ``check_str`` and,
    optionally, ``scope_types`` keys.

    :param path: Path to the YAML file.
    :returns: a dict of {rule_name: {'check_str': str, 'scope_types': list}}
    """
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    overrides = data.get('overrides')
    if not isinstance(overrides, dict):
        raise ValueError(
            f'Approved overrides file "{path}" must contain a top-level '
            '"overrides" mapping.'
        )

    parsed: dict[str, dict[str, Any]] = {}
    for name, override in overrides.items():
        if isinstance(override, str):
            parsed[name] = {'check_str': override, 'scope_types': None}
        elif isinstance(override, dict) and 'check_str' in override:
            parsed[name] = {
                'check_str': override['check_str'],
                'scope_types': override.get('scope_types'),
            }
        else:
            raise ValueError(
                f'Approved override for rule "{name}" in "{path}" must be '
                'a check string or a mapping with a "check_str" key.'
            )
    return parsed


def _registrations_equal(
    first: policy.RuleDefault, second: policy.RuleDefault
) -> bool:
    """Compare two registrations of the same rule, including scope."""
    return (
        first == second
        and first.scope_types == second.scope_types
        and first.description == second.description
    )


def _registration_diff(
    registrations: list[tuple[str, policy.RuleDefault]],
) -> list[str]:
    """Return the fields on which the given registrations differ."""
    differing = []
    for field in ('check_str', 'scope_types', 'description'):
        values = [getattr(rule, field) for _, rule in registrations]
        if any(value != values[0] for value in values[1:]):
            differing.append(field)
    return differing


def _format_registration(rule: policy.RuleDefault) -> str:
    scope = (
        ', '.join(rule.scope_types)
        if rule.scope_types is not None
        else '<unspecified>'
    )
    return f'check="{rule.check_str}" scope=[{scope}]'


def _check_rule_sources(
    namespaces: list[str],
    approved_overrides_file: str | None = None,
    output_path: str | None = None,
) -> int:
    """Check rule registrations from multiple sources before generating config.

    This is a read-only audit tool: it never writes a policy file and never
    modifies an enforcer, so generating the report cannot apply unapproved
    configuration. It cross-checks the rules registered by each namespace
    and reports:

    * the registration sources, in the precedence order used to resolve
      duplicates (the first source registering a rule wins),
    * the site-approved overrides, each traced back to the actual
      registrations for that rule,
    * rules registered identically by more than one source,
    * rules registered with conflicting definitions, showing the
      differences, which registration will be adopted, and whether a
      site-approved override covers the conflict.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies', in precedence order.
    :param approved_overrides_file: path to a YAML file with site-approved
                                    overrides, or None.
    :param output_path: The path of a file to output to. stdout used if None.
    :returns: 0 if no unapproved conflicts or stale overrides were found,
              1 otherwise.
    """
    policies = get_policies_dict(namespaces)

    approved: dict[str, dict[str, Any]] = {}
    if approved_overrides_file:
        approved = _load_approved_overrides(approved_overrides_file)

    # Index every registration by rule name, keeping source order so that
    # the adopted registration (first source in precedence order) is known.
    by_name: dict[str, list[tuple[str, policy.RuleDefault]]] = {}
    for namespace in namespaces:
        for rule in policies.get(namespace, []):
            by_name.setdefault(rule.name, []).append((namespace, rule))

    lines = []
    lines.append('Policy registration source check\n')
    lines.append('================================\n\n')
    lines.append('Registration sources (in precedence order):\n')
    for index, namespace in enumerate(namespaces, start=1):
        count = len(policies.get(namespace, []))
        lines.append(f'  {index}. {namespace} ({count} rules)\n')
    lines.append('\n')

    failures = 0

    lines.append('Site-approved overrides:\n')
    if approved_overrides_file:
        lines.append(f'(from {approved_overrides_file})\n')
    if not approved:
        lines.append('  none configured\n')
    for name in sorted(approved):
        override = approved[name]
        scope = override['scope_types']
        scope_text = ', '.join(scope) if scope else '<unspecified>'
        lines.append(
            f'  "{name}": check="{override["check_str"]}" '
            f'scope=[{scope_text}]\n'
        )
        registrations = by_name.get(name)
        if not registrations:
            lines.append(
                '    STALE: no registered rule with this name; the '
                'override does not apply to anything\n'
            )
            failures += 1
            continue
        sources = ', '.join(source for source, _ in registrations)
        lines.append(f'    registered by: {sources}\n')
        adopted = registrations[0][1]
        if (
            adopted.check_str == override['check_str']
            and adopted.scope_types == scope
        ):
            lines.append(
                '    NOTE: identical to the adopted registration; the '
                'override is redundant\n'
            )
        else:
            lines.append(
                f'    adopted default: {_format_registration(adopted)}\n'
            )
            lines.append(
                '    the override changes the effective rule and must be '
                'carried into the config submitted for approval\n'
            )
    lines.append('\n')

    duplicates = []
    conflicts = []
    for name in sorted(by_name):
        registrations = by_name[name]
        if len(registrations) < 2:
            continue
        first = registrations[0][1]
        if all(
            _registrations_equal(first, rule) for _, rule in registrations[1:]
        ):
            duplicates.append((name, registrations))
        else:
            conflicts.append((name, registrations))

    lines.append('Duplicate registrations (identical, no action needed):\n')
    if not duplicates:
        lines.append('  none\n')
    for name, registrations in duplicates:
        sources = ', '.join(source for source, _ in registrations)
        lines.append(f'  "{name}" registered identically by: {sources}\n')
        lines.append(f'    adopted registration: {registrations[0][0]}\n')
    lines.append('\n')

    lines.append('Conflicting registrations:\n')
    if not conflicts:
        lines.append('  none\n')
    for name, registrations in conflicts:
        lines.append(f'  "{name}":\n')
        for source, rule in registrations:
            lines.append(
                f'    {source}: {_format_registration(rule)}\n'
            )
        differing = _registration_diff(registrations)
        lines.append(f'    differences: {", ".join(differing)}\n')
        adopted_source, adopted = registrations[0]
        lines.append(
            f'    adopted registration: {adopted_source} '
            '(first source in precedence order)\n'
        )
        shadowed = ', '.join(source for source, _ in registrations[1:])
        lines.append(f'    shadowed registration(s): {shadowed}\n')
        override = approved.get(name)
        if override is not None:
            lines.append(
                f'    APPROVED: site-approved override '
                f'check="{override["check_str"]}" covers this rule\n'
            )
        else:
            lines.append(
                '    UNAPPROVED: no site-approved override covers this '
                'conflict; nothing is applied by this report\n'
            )
            failures += 1
    lines.append('\n')

    if failures:
        lines.append(
            f'Result: {failures} issue(s) require operator approval\n'
        )
        return_code = 1
    else:
        lines.append('Result: all registrations are consistent\n')
        return_code = 0

    output_file = open(output_path, 'w') if output_path else sys.stdout
    output_file.writelines(lines)
    if output_file != sys.stdout:
        output_file.close()

    return return_code


def on_load_failure_callback(
    em: stevedore.ExtensionManager[Any],
    ep: importlib.metadata.EntryPoint,
    err: BaseException,
) -> None:
    raise


def _check_for_namespace_opt(conf: cfg.ConfigOpts) -> None:
    # NOTE(bnemec): This opt is required, but due to lp#1849518 we need to
    # make it optional while our consumers migrate to the new method of
    # parsing cli args. Making the arg itself optional and explicitly checking
    # for it in the tools will allow us to migrate projects without breaking
    # anything. Once everyone has migrated, we can make the arg required again
    # and remove this check.
    if conf.namespace is None:
        raise cfg.RequiredOptError('namespace', cfg.OptGroup('DEFAULT'))


def generate_sample(
    args: Sequence[str] | None = None, conf: cfg.ConfigOpts | None = None
) -> None:
    logging.basicConfig(level=logging.WARNING)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS)
    # https://review.opendev.org/c/openstack/oslo.config/+/992762
    conf(list(args) if args else None)
    _check_for_namespace_opt(conf)
    _generate_sample(
        conf.namespace,
        output_path=conf.output_file,
        exclude_deprecated=conf.exclude_deprecated,
    )


def generate_policy(args: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.WARNING)
    conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf.register_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _generate_policy(conf.namespace, conf.output_file, conf.exclude_deprecated)


def _upgrade_policies(
    policies: dict[str, str],
    default_policies: dict[str, list[policy.RuleDefault]],
) -> None:
    old_policies_keys = list(policies.keys())
    for section in sorted(default_policies.keys()):
        rule_defaults = default_policies[section]
        for rule_default in rule_defaults:
            if (
                rule_default.deprecated_rule
                and rule_default.deprecated_rule.name in old_policies_keys
            ):
                policies[rule_default.name] = policies.pop(
                    rule_default.deprecated_rule.name
                )
                LOG.info(
                    'The name of policy %(old_name)s has been upgraded to'
                    '%(new_name)',
                    {
                        'old_name': rule_default.deprecated_rule.name,
                        'new_name': rule_default.name,
                    },
                )


def upgrade_policy(
    args: list[str] | None = None, conf: cfg.ConfigOpts | None = None
) -> None:
    logging.basicConfig(level=logging.WARNING)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS + UPGRADE_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS + UPGRADE_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    with open(conf.policy) as input_data:
        policies = policy.parse_file_contents(input_data.read())
    default_policies = get_policies_dict(conf.namespace)

    _upgrade_policies(policies, default_policies)

    if conf.output_file:
        with open(conf.output_file, 'w') as fh:
            yaml.safe_dump(policies, fh, default_flow_style=False)
    else:
        sys.stdout.write(yaml.safe_dump(policies, default_flow_style=False))


def list_redundant(args: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.WARNING)
    conf = cfg.CONF
    conf.register_cli_opts(ENFORCER_OPTS)
    conf.register_opts(ENFORCER_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _list_redundant(conf.namespace)


def check_rule_sources(
    args: list[str] | None = None, conf: cfg.ConfigOpts | None = None
) -> None:
    logging.basicConfig(level=logging.WARNING)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS + SOURCE_CHECK_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS + SOURCE_CHECK_OPTS)
    conf(list(args) if args else None)
    _check_for_namespace_opt(conf)
    sys.exit(
        _check_rule_sources(
            conf.namespace,
            approved_overrides_file=conf.approved_overrides,
            output_path=conf.output_file,
        )
    )


def validate_policy(args: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.WARNING)
    conf = cfg.CONF
    conf.register_cli_opts(ENFORCER_OPTS)
    conf.register_opts(ENFORCER_OPTS)
    conf(args)
    sys.exit(_validate_policy(conf.namespace))


def convert_policy_json_to_yaml(
    args: list[str] | None = None, conf: cfg.ConfigOpts | None = None
) -> None:
    logging.basicConfig(level=logging.WARNING)
    LOG.warning('The oslopolicy-convert-json-to-yaml tool is deprecated')
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + CONVERT_OPTS)
    conf.register_opts(GENERATOR_OPTS + CONVERT_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _convert_policy_json_to_yaml(
        conf.namespace, conf.policy_file, conf.output_file
    )
