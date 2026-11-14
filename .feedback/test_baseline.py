"""Run unchanged upstream SMTP tests with a process-local loopback test port."""
import socket
import sys
import pytest


class LoopbackPort:
    def pytest_configure(self, config):
        config.addinivalue_line('markers', 'controller_data: upstream SMTP controller fixture options')

    def pytest_collection_modifyitems(self, items):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        print('SMTP test loopback port:', port)
        for item in items:
            existing = item.get_closest_marker('controller_data')
            options = dict(existing.kwargs) if existing else {}
            if 'host_port' not in options:
                options.setdefault('hostname', '127.0.0.1')
                options.setdefault('port', port)
            item.add_marker(pytest.mark.controller_data(**options), append=False)


args = sys.argv[1:] or [
    '-q', '-o', 'addopts=', 'aiosmtpd/tests/test_smtp.py', '-k', 'helo or rset'
]
raise SystemExit(pytest.main(args, plugins=[LoopbackPort()]))
