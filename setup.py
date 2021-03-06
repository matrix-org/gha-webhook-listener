#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup

setup(
    name="gha-webhook-listener",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[
        "flask",
        "requests",
    ],
    python_requires='>=3.5',
    scripts=[
        "gha-webhook-listener.py",
    ],
)
