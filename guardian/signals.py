"""Signals emitted by django-guardian.

Unlike the permission-model signals documented in the user guide, these are
Guardian-produced notifications about authorization decisions and transitions.
"""

import django.dispatch

#: Sent after an authenticated request is switched to a visitor principal.
#: Receivers get ``record`` (a ``guardian.principals.PrincipalSwitch``) and
#: ``request``.
principal_switched = django.dispatch.Signal()
