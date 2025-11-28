#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK version management utilities for setuptools_scm integration.

This module provides customized version schemes and formatting functions
for SPSDK package versioning using setuptools_scm framework.
"""

from setuptools_scm import ScmVersion
from setuptools_scm._log import log
from setuptools_scm.version import no_guess_dev_version


def run(version: ScmVersion) -> str:
    """Return a string representation of version object provided by setuptools_scm.

    The method processes version information with custom logic for release branches.
    For release branches, it extracts and formats the version string by removing
    prefixes, replacing separators, and handling development versions. For non-release
    branches, it falls back to default behavior.

    :param version: Version object containing branch, distance and other version metadata.
    :return: Formatted version string based on branch type and version metadata.
    """
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
