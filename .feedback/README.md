# Local preparation

Upstream: https://github.com/aio-libs/aiohttp
Pinned upstream: `fe099491d275ef2c21bf683e024e34d51ac05d43`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12, pure Python mode. Initialize the pinned llhttp submodule (needed for license/package metadata even without C extensions).

`uv venv --python 3.12 .venv`
`AIOHTTP_NO_EXTENSIONS=1 uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
env AIOHTTP_NO_EXTENSIONS=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -p pytest_mock -q -o addopts= -o filterwarnings=default tests/test_formdata.py -k not client
```

Recorded exit code: 0. Local elapsed seconds: 0.285.
