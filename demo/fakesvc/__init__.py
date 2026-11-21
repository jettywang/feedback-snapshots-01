"""Entry-point package exposing the fake service enforcer to oslo.policy CLIs."""
import os

from oslo_config import cfg

from oslo_policy import opts
from oslo_policy import policy

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build(release):
    # The generator CLIs read policy_file from the global cfg.CONF at the
    # end of validation, so register the oslo_policy options there too.
    if not hasattr(cfg.CONF, 'oslo_policy'):
        opts._register(cfg.CONF)
    default_file = os.path.join(
        _HERE, 'policies',
        'phaseA_aliases.yaml' if release == 'old' else 'phaseC_cleanup.yaml',
    )
    policy_file = default_file
    if hasattr(cfg.CONF, 'oslo_policy') and cfg.CONF.oslo_policy.policy_file:
        policy_file = cfg.CONF.oslo_policy.policy_file
    enforcer = policy.Enforcer(cfg.CONF, policy_file=policy_file)
    from fake_service import OLD_RELEASE, NEW_RELEASE
    enforcer.register_defaults(OLD_RELEASE if release == 'old' else NEW_RELEASE)
    return enforcer


def old_enforcer():
    return _build('old')


def new_enforcer():
    return _build('new')


def list_old_policies():
    from fake_service import OLD_RELEASE
    return OLD_RELEASE


def list_new_policies():
    from fake_service import NEW_RELEASE
    return NEW_RELEASE
