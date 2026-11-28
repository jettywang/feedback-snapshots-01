"""Example runtime-only endpoint schemes for the audit demo.

Two schemes are provided so the review can see both sides of the extension
rule:

* C{runtimeprobe} ships no static discloser at all.  Its listening address is
  only knowable when the plugin actually runs, so the audit must keep the
  range uncertain and flag it for manual review.
* C{metricsd} voluntarily ships a side-effect-free C{disclose()} helper.
  The helper only inspects description text (no reactor, no socket, no key
  file) and returns the range the plugin would bind, which the audit records
  as inspectable information.
"""

from __future__ import annotations

from endpoint_audit.extensions import Disclosure, ip_host, wildcard_host
from endpoint_audit.model import Family

prefix = "metricsd"


def disclose(args, kwargs):
    port_raw = kwargs.get("port") or (args[0] if args else None)
    if port_raw is None:
        return None
    try:
        port = int(port_raw)
    except ValueError:
        return None
    interface = kwargs.get("interface")
    if interface:
        host = ip_host(interface)
    else:
        host = wildcard_host(Family.INET4)
    return Disclosure(family=host.family, host=host, port=port)
