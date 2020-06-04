#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing SBFile."""

from spsdk.mboot import ExtMemId
from spsdk.utils.crypto import crypto_backend, Certificate
from .commands import CmdNop, CmdErase, CmdLoad, CmdFill, CmdJump, CmdCall, CmdReset, CmdMemEnable, CmdProg, \
    CmdKeyStoreBackup, CmdKeyStoreRestore
from .commands import VersionCheckType, CmdVersionCheck
from .images import BootImageV20, BootImageV21, SBV2xAdvancedParams
from .misc import BcdVersion3
from .sb1.headers import SecureBootFlagsV1
from .sb1.images import SecureBootV1
from .sb1.sections import BootSectionV1
from .sections import BootSectionV2, CertSectionV2, CertBlockV2

__all__ = [
    # images
    'BootImageV20',
    'BootImageV21',
    # sections
    'BootSectionV2',
    'CertSectionV2',
    'CertBlockV2',
    # commands
    'CmdNop',
    'CmdErase',
    'CmdLoad',
    'CmdFill',
    'CmdJump',
    'CmdCall',
    'CmdReset',
    'CmdMemEnable',
    'CmdProg',
    'CmdVersionCheck',
    'CmdKeyStoreBackup',
    'CmdKeyStoreRestore',
    # other types and enums
    'SBV2xAdvancedParams',
    'BcdVersion3',
    'Certificate',
    'VersionCheckType',
    'ExtMemId',
    # functions
    'crypto_backend',
]
