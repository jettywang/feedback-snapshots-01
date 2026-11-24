#  Copyright 2018-Present The CloudEvents Authors
#
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

"""This package contains the core functionality of the CloudEvents spec."""

# Optional offline evidence-receipt / cross-binding correlation API.
# Imported for its public re-export surface; see cloudevents.core.receipt.
from cloudevents.core.receipt import *  # noqa: F401,F403
from cloudevents.core.receipt import __all__ as _receipt_all

__all__ = list(_receipt_all)
