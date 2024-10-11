#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import itertools

from setuptools import find_packages, setup  # type: ignore

with open("requirements.txt") as req_file:
    requirements = req_file.read().splitlines()


with open("README.md", "r") as f:
    long_description = f.read()

extras_require = {
    "tp": ["pyscard==2.0.2"],
    "examples": ["flask", "requests", "ipython", "notebook"],
    "dk6": ["pyftdi", "pylibftdi", "ftd2xx"],
    "oscca": ["asn1tools>=0.160,<1", "gmssl>=3.2,<4"],
    "can": ["python-can<4.4"],
    "pqc": ["spsdk-pqc<1.0,>=0.3.1"],
}
# specify all option that contains all extras
extras_require["all"] = list(itertools.chain.from_iterable(extras_require.values()))

setup(
    name="spsdk",
    use_scm_version=True,
    description="Open Source Secure Provisioning SDK for NXP MCU/MPU",
    url="https://github.com/NXPmicro/spsdk",
    project_urls={
        "Code": "https://github.com/NXPmicro/spsdk",
        "Issue tracker": "https://github.com/NXPmicro/spsdk/issues",
        "Documentation": "https://spsdk.readthedocs.io",
    },
    author="NXP",
    author_email="michal.starecek@nxp.com",
    license="BSD-3-Clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    platforms="Windows, Linux, Mac OSX",
    python_requires=">=3.9",
    setup_requires=["setuptools_scm<8.2", "setuptools>=72.1,<74", "wheel"],
    install_requires=requirements,
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "License :: OSI Approved :: BSD License",
        "Topic :: Scientific/Engineering",
        "Topic :: Software Development :: Embedded Systems",
        "Topic :: System :: Hardware",
        "Topic :: Utilities",
    ],
    packages=find_packages(
        exclude=["tests.*", "tests", "examples.*", "examples", "tools", "tools.*"]
    ),
    entry_points={
        "console_scripts": [
            "pfr=spsdk.apps.pfr:safe_main",
            "blhost=spsdk.apps.blhost:safe_main",
            "sdphost=spsdk.apps.sdphost:safe_main",
            "sdpshost=spsdk.apps.sdpshost:safe_main",
            "spsdk=spsdk.apps.spsdk_apps:safe_main",
            "nxpdebugmbox=spsdk.apps.nxpdebugmbox:safe_main",
            "nxpcrypto=spsdk.apps.nxpcrypto:safe_main",
            "nxpdevscan=spsdk.apps.nxpdevscan:safe_main",
            "nxpdevhsm=spsdk.apps.nxpdevhsm:safe_main",
            "nxpele=spsdk.apps.nxpele:safe_main",
            "nxpdice=spsdk.apps.nxpdice:safe_main",
            "nxpimage=spsdk.apps.nxpimage:safe_main",
            "nxpmemcfg=spsdk.apps.nxpmemcfg:safe_main",
            "nxpuuu=spsdk.apps.nxpuuu:safe_main",
            "nxpwpc=spsdk.apps.nxpwpc:safe_main",
            "shadowregs=spsdk.apps.shadowregs:safe_main",
            "ifr=spsdk.apps.ifr:safe_main",
            "tpconfig=spsdk.apps.tpconfig:safe_main",
            "tphost=spsdk.apps.tphost:safe_main",
            "dk6prog=spsdk.apps.dk6prog:safe_main",
            "el2go-host=spsdk.apps.el2go:safe_main",
            "lpcprog=spsdk.apps.lpcprog:safe_main",
        ],
    },
    extras_require=extras_require,
)
