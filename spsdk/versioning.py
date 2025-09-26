#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Customized version scheme for setuptools_scm."""

from setuptools_scm import ScmVersion
from setuptools_scm._log import log
from setuptools_scm.version import no_guess_dev_version


def run(version: ScmVersion) -> str:
    """Return a string representation of version object provided by setuptools_scm."""
    log.info("Starting custom version processing")

    # we are on a release branch
    if version.branch and version.branch.startswith("release/"):
        result = version.branch.lower()
        result = result.replace("release/", "").replace("-", ".")
        result = result.replace("ear", "a").replace("prc", "rc")
        if result.startswith(("v", "V")):
            result = result[1:]
        # this is a distance from previous tag (not distance from master branch)
        # we keep it here for consistency
        if version.distance:
            result += f".dev{version.distance}"
        return result

    # default behavior
    return no_guess_dev_version(version)
