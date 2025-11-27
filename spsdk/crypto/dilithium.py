#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Dilithium post-quantum cryptography integration module.

This module provides integration support for Dilithium digital signature
algorithm, a post-quantum cryptographic scheme. It handles the detection
and availability of Dilithium cryptographic capabilities within the SPSDK
framework.
"""

import importlib.util

IS_DILITHIUM_SUPPORTED = importlib.util.find_spec("spsdk_pqc") is not None
