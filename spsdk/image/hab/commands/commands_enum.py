#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""This module contains CSF command's enum definition."""

from spsdk.utils.spsdk_enum import SpsdkEnum


class SecCommand(SpsdkEnum):
    """CSF command Enum."""

    HEADER = (20, "SEC_CSF_HEADER", "Header")
    INSTALL_SRK = (21, "INSTALL_SRK", "Install SRK")
    INSTALL_CSFK = (22, "INSTALL_CSFK", "Install CSFK")
    INSTALL_NOCAK = (23, "INSTALL_NOCAK", "Install NOCAK")
    AUTHENTICATE_CSF = (24, "AUTHENTICATE_CSF", "Authenticate CSF")
    INSTALL_KEY = (25, "INSTALL_KEY", "Install Key")
    AUTHENTICATE_DATA = (26, "AUTHENTICATE_DATA", "Authenticate data")
    INSTALL_SECRET_KEY = (27, "INSTALL_SECRET_KEY", "Install Secret Key")
    DECRYPT_DATA = (28, "DECRYPT_DATA", "Decrypt data")
    SET_ENGINE = (31, "SET_ENGINE", "Set Engine")
    UNLOCK = (33, "UNLOCK", "Unlock")
