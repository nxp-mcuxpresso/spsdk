#!/usr/bin/env python
#
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Secure Binary Key Derivation Provider plugin.

This module provides a custom key derivation provider implementation for SPSDK's
encryption framework, enabling secure key derivation for binary protection workflows.
"""

__author__ = """NXP"""
__email__ = "spsdk@nxp.com"
__version__ = "0.1.0"

from .provider import MySBKeyDerivatorProvider

__all__ = ["MySBKeyDerivatorProvider"]
