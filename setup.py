#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

with open("README.md", "r") as f:
    long_description = f.read()

# extract version info indirectly
version_info = {}
base_dir = os.path.dirname(__file__)
with open(os.path.join(base_dir, "spsdk", "__version__.py")) as f:
    exec(f.read(), version_info)

setup(
    name='spsdk',
    version=version_info["__version__"],
    description='Open Source Boot SDK for NXP MCU/MPU',
    long_description=long_description,
    long_description_content_type="text/markdown",
    platforms="Windows, Linux, Mac OSX",
    python_requires=">=3.6",
    setup_requires=[
        'setuptools>=40.0'
    ],
    install_requires=requirements,
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha'
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'License :: OSI Approved :: BSD License',
        'Topic :: Scientific/Engineering',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: System :: Hardware',
        'Topic :: Utilities'
    ],
    packages=find_packages(exclude=["tests.*", "tests", "examples"]),
    entry_points={
        'console_scripts': [
            'pfr=spsdk.apps.pfr:main',
            'blhost=spsdk.apps.blhost:main',
            'sdphost=spsdk.apps.sdphost:main',
            'spsdk=spsdk.apps.spsdk_apps:main',
            'nxpkeygen=spsdk.apps.nxpkeygen:main',
            'nxpdebugmbox=spsdk.apps.nxpdebugmbox:main'
        ],
    },
)
