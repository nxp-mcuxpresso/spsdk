#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Integration submodule for PQC."""

try:
    import spsdk_pqc  # pylint: disable=unused-import

    IS_DILITHIUM_SUPPORTED = True

except ImportError:
    IS_DILITHIUM_SUPPORTED = False
