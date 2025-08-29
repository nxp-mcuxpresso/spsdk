#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Secure Provisioning SDK is unified, reliable and easy to use SW library.

It's working across NXP MCU portfolio providing strong foundation from quick customer
prototyping up to production deployment.
The library allows the user to
    - connect and communicate with a device
    - configure the device; prepare
    - download and upload data
    - providing security operations.
It is delivered in a form of python library with functionality presented as CLI or GUI utilities.
"""
import os
import sys
from typing import Optional, Union

from packaging.version import Version, parse
from platformdirs import PlatformDirs


class SPSDKPlatformDirs(PlatformDirs):
    """Adjust platformdirs behavior."""

    # default platformdirs behavior on win
    # cache -> AppData/$author/$app/Cache/$version
    # logs  -> AppData/$author/$app/$version/Logs
    # to unify that we change "cache" dir so it aligns to "logs" dir
    @property
    def user_cache_dir(self) -> str:
        """Cache directory tied to the user."""
        if sys.platform != "win32":
            return super().user_cache_dir
        path = os.path.join(self.user_data_dir, "Cache")
        self._optionally_create_directory(path)
        return path


def get_spsdk_version() -> Version:
    """Get SPSDK's version. Either from (already generated) __version__ or dynamically via setuptools_scm."""
    try:
        from .__version__ import __version__ as spsdk_version
    except ImportError:
        from setuptools_scm import get_version

        spsdk_version = get_version()
    return parse(spsdk_version)


def value_to_bool(value: Optional[Union[bool, int, str]]) -> bool:
    """Function decode bool value from various formats."""
    if isinstance(value, str):
        return value in ("True", "true", "T", "1")
    return bool(value)


version = get_spsdk_version()

__author__ = "NXP"
__contact__ = "spsdk@nxp.com"
__license__ = "BSD-3-Clause"
__version__ = str(version)
__release__ = "beta"


# The SPSDK behavior settings
# SPSDK_DATA_FOLDER might be redefined by SPSDK_DATA_FOLDER_{version}
# or SPSDK_DATA_FOLDER env variable
SPSDK_VERSION_BASE = version.base_version
SPSDK_VERSION_FOLDER_SUFFIX = SPSDK_VERSION_BASE.replace(".", "_")
SPSDK_DATA_FOLDER_ENV_VERSION = "SPSDK_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_DATA_FOLDER = (
    os.environ.get(SPSDK_DATA_FOLDER_ENV_VERSION)
    or os.environ.get("SPSDK_DATA_FOLDER")
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
)
SPSDK_PLATFORM_DIRS = SPSDKPlatformDirs(
    appauthor="nxp",
    appname="spsdk",
    version=SPSDK_VERSION_BASE,
    ensure_exists=True,
)

# SPSDK_RESTRICTED_DATA_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_RESTRICTED_DATA_FOLDER_ENV_VERSION = (
    "SPSDK_RESTRICTED_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
)
SPSDK_RESTRICTED_DATA_FOLDER = os.environ.get(
    SPSDK_RESTRICTED_DATA_FOLDER_ENV_VERSION
) or os.environ.get("SPSDK_RESTRICTED_DATA_FOLDER")

# SPSDK_ADDONS_DATA_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_ADDONS_DATA_FOLDER_ENV_VERSION = "SPSDK_ADDONS_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_ADDONS_DATA_FOLDER = os.environ.get(SPSDK_ADDONS_DATA_FOLDER_ENV_VERSION) or os.environ.get(
    "SPSDK_ADDONS_DATA_FOLDER"
)

# SPSDK_CACHE_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_CACHE_FOLDER_ENV_VERSION = "SPSDK_CACHE_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_CACHE_FOLDER = os.environ.get(SPSDK_CACHE_FOLDER_ENV_VERSION) or os.environ.get(
    "SPSDK_CACHE_FOLDER"
)

# SPSDK_CACHE_DISABLED might be redefined by SPSDK_CACHE_DISABLED_{version} env variable, default is False
SPSDK_CACHE_DISABLED = value_to_bool(os.environ.get("SPSDK_CACHE_DISABLED"))
SPSDK_CACHE_DISABLED |= value_to_bool(
    os.environ.get(f"SPSDK_CACHE_DISABLED_{SPSDK_VERSION_FOLDER_SUFFIX}")
)

SPSDK_INTERACTIVE_DISABLED = value_to_bool(os.environ.get("SPSDK_INTERACTIVE_DISABLED"))

SPSDK_DEBUG = value_to_bool(os.environ.get("SPSDK_DEBUG"))
# SPSDK_DEBUG_DB enables debug loggers for utils/database module
SPSDK_DEBUG_DB = SPSDK_DEBUG or value_to_bool(os.environ.get("SPSDK_DEBUG_DB"))

SPSDK_YML_INDENT = 2


ROOT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SPSDK_EXAMPLES_FOLDER = os.path.abspath(os.path.join(ROOT_DIR, "examples"))

SPSDK_DEBUG_LOGGING_DISABLED = value_to_bool(os.environ.get("SPSDK_DEBUG_LOGGING_DISABLED"))
SPSDK_DEBUG_LOG_FILE = os.environ.get(
    "SPSDK_DEBUG_LOG_FILE", os.path.join(SPSDK_PLATFORM_DIRS.user_log_dir, "debug.log")
)
SPSDK_SCHEMA_STRICT = value_to_bool(os.environ.get("SPSDK_SCHEMA_STRICT"))

SPSDK_SECRETS_PATH = os.environ.get(
    "SPSDK_SECRETS_PATH", os.path.expanduser("~/.spsdk/secrets.yaml")
)
