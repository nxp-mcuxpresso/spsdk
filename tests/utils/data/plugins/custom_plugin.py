#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK test plugin implementation for plugin system validation.

This module provides a custom plugin implementation used for testing
the SPSDK plugin loading and management system functionality.
"""


class CustomPlugin:
    """Custom plugin for SPSDK testing framework.

    This class serves as a test plugin that can be dynamically imported and loaded
    by the SPSDK plugin system during unit tests. It provides a minimal implementation
    to verify plugin discovery and loading mechanisms.
    """

    def __init__(self) -> None:
        """Initialize the Custom Plugin.

        This constructor sets up a new instance of the Custom Plugin for testing purposes.
        """
        pass
