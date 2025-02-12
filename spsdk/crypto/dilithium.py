#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Integration submodule for PQC."""
import importlib.util

IS_DILITHIUM_SUPPORTED = importlib.util.find_spec("spsdk_pqc") is not None
