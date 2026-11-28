import functools

import pytest
from sigstore import oidc
from urllib3 import request


@pytest.fixture
@functools.cache
def id_token() -> oidc.IdentityToken:
    resp = request(
        "GET",
        "https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt",
        timeout=30.0,
    )
    return oidc.IdentityToken(resp.data.decode().rstrip())


@pytest.fixture(scope="module")
def trust_home(tmp_path_factory):
    """Provide a writable HOME so the offline Sigstore TUF cache can be created."""
    home = tmp_path_factory.mktemp("sigstore-home")
    home = home / "home"
    home.mkdir()
    mp = pytest.MonkeyPatch()
    mp.setenv("HOME", str(home))
    yield home
    mp.undo()
