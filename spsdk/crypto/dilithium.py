#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK post-quantum cryptography support detection.

This module centralizes optional dependency detection for post-quantum
cryptographic algorithms used by SPSDK. Dilithium is still provided by
the external ``spsdk-pqc`` package, while ML-DSA support comes from the
required ``cryptography`` dependency.
"""

import importlib.util

IS_DILITHIUM_SUPPORTED = importlib.util.find_spec("spsdk_pqc") is not None
