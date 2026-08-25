#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Super Awesome Signature Provider (SASP) plugin package.

This module provides a signature provider plugin implementation for SPSDK,
offering secure signing capabilities through the Super Awesome Signature Provider.
"""

__author__ = """NXP"""
__email__ = "spsdk@nxp.com"
__version__ = "0.1.0"

from .provider import SuperAwesomeSP

__all__ = ["SuperAwesomeSP"]
