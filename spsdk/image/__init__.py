#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing functionality of srktool, dcdgen, mkimage and other similar tools."""

from .bee import BeeRegionHeader, BeeKIB, BeeProtectRegionBlock, BeeFacRegion
from .commands import EnumWriteOps, EnumCheckOps, EnumCertFormat, EnumInsKey, EnumAuthDat, EnumEngine, \
                      EnumItm, CmdWriteData, CmdCheckData, CmdNop, CmdSet, CmdInitialize, CmdUnlock, \
                      CmdUnlockCAAM, CmdUnlockOCOTP, CmdUnlockSNVS, CmdInstallKey, CmdAuthData
from .segments import SegIVT2, SegIVT3a, SegIVT3b, SegBDT, SegAPP, SegDCD, SegCSF, PaddingFCB, FlexSPIConfBlockFCB
from .secret import SrkTable, SrkItem, CertificateImg, Signature, MAC, SecretKeyBlob, EnumAlgorithm
from .images import parse, BootImgRT, BootImg2, BootImg3a, BootImg3b, BootImg4, EnumAppType
from .keystore import KeySourceType, KeyStore
from .mbimg import MasterBootImage, MasterBootImageN4Analog, MasterBootImageType, MasterBootImageManifest, \
                   MultipleImageEntry, MultipleImageTable
from .trustzone import TrustZone, TrustZoneType

__all__ = [
    # Main Classes
    'BootImgRT',
    'BootImg2',
    'BootImg3a',
    'BootImg3b',
    'BootImg4',
    'MasterBootImage',
    'MasterBootImageType',
    # multiple images for MasterBootImage (relocation table)
    'MultipleImageEntry',
    'MultipleImageTable',
    # Segments
    'SegIVT2',
    'SegIVT3a',
    'SegIVT3b',
    'SegBDT',
    'SegAPP',
    'SegDCD',
    'SegCSF',
    'TrustZone',
    'TrustZoneType',
    'PaddingFCB',
    'FlexSPIConfBlockFCB',
    # BEE
    'BeeRegionHeader',
    'BeeKIB',
    'BeeProtectRegionBlock',
    'BeeFacRegion',
    # Secret
    'SrkTable',
    'SrkItem',
    'CertificateImg',
    'Signature',
    'MAC',
    'SecretKeyBlob',
    # Enums
    'EnumAppType',
    # Commands
    'CmdNop',
    'CmdSet',
    'CmdWriteData',
    'CmdCheckData',
    'CmdInitialize',
    'CmdInstallKey',
    'CmdAuthData',
    'CmdUnlock',
    'CmdUnlockCAAM',
    'CmdUnlockOCOTP',
    'CmdUnlockSNVS',
    # Elements
    'EnumWriteOps',
    'EnumCheckOps',
    'EnumAlgorithm',
    'EnumCertFormat',
    'EnumInsKey',
    'EnumAuthDat',
    'EnumEngine',
    'EnumItm',
    # Methods
    'parse',
    # KeyStore
    'KeyStore',
    'KeySourceType',
]
