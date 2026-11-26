# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['hookpkg']

package_data = \
{'': ['*']}

setup_kwargs = {
    'name': 'hookpkg',
    'version': '0.1.0',
    'description': 'Event-recording Poetry build script project',
    'long_description': '# hookpkg\n\nMinimal build-script evidence project.\n',
    'author': 'Approval Lab',
    'author_email': 'lab@example.invalid',
    'maintainer': 'None',
    'maintainer_email': 'None',
    'url': 'None',
    'packages': packages,
    'package_data': package_data,
    'python_requires': '>=3.11',
}
from build import *
build(setup_kwargs)

setup(**setup_kwargs)
