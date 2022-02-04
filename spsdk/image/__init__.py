#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing functionality of srktool, dcdgen, mkimage and other similar tools."""

import os

from spsdk import SPSDK_DATA_FOLDER

IMG_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "image")
TZ_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "sch_tz.yml")
MBIMG_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "sch_mbimg.yml")
SB3_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "sch_sb3.yml")

from .bee import BeeFacRegion, BeeKIB, BeeProtectRegionBlock, BeeRegionHeader
from .commands import (
    CmdAuthData,
    CmdCheckData,
    CmdInitialize,
    CmdInstallKey,
    CmdNop,
    CmdSet,
    CmdUnlock,
    CmdUnlockCAAM,
    CmdUnlockOCOTP,
    CmdUnlockSNVS,
    CmdWriteData,
    EnumAuthDat,
    EnumCertFormat,
    EnumCheckOps,
    EnumEngine,
    EnumInsKey,
    EnumItm,
    EnumWriteOps,
)
from .exceptions import SPSDKUnsupportedImageType
from .images import BootImg2, BootImg3a, BootImg3b, BootImg4, BootImgRT, EnumAppType, parse
from .keystore import KeySourceType, KeyStore
from .mbi_mixin import MasterBootImageManifest, MultipleImageEntry, MultipleImageTable
from .mbimg import MasterBootImage, get_mbi_class
from .secret import MAC, CertificateImg, EnumAlgorithm, SecretKeyBlob, Signature, SrkItem, SrkTable
from .segments import (
    FlexSPIConfBlockFCB,
    PaddingFCB,
    SegAPP,
    SegBDT,
    SegCSF,
    SegDCD,
    SegIVT2,
    SegIVT3a,
    SegIVT3b,
)
from .trustzone import TrustZone, TrustZoneType

__all__ = [
    # Main Classes
    "BootImgRT",
    "BootImg2",
    "BootImg3a",
    "BootImg3b",
    "BootImg4",
    "MasterBootImage",
    # multiple images for MasterBootImage (relocation table)
    "MultipleImageEntry",
    "MultipleImageTable",
    # Segments
    "SegIVT2",
    "SegIVT3a",
    "SegIVT3b",
    "SegBDT",
    "SegAPP",
    "SegDCD",
    "SegCSF",
    "TrustZone",
    "TrustZoneType",
    "PaddingFCB",
    "FlexSPIConfBlockFCB",
    # BEE
    "BeeRegionHeader",
    "BeeKIB",
    "BeeProtectRegionBlock",
    "BeeFacRegion",
    # Secret
    "SrkTable",
    "SrkItem",
    "CertificateImg",
    "Signature",
    "MAC",
    "SecretKeyBlob",
    # Enums
    "EnumAppType",
    # Commands
    "CmdNop",
    "CmdSet",
    "CmdWriteData",
    "CmdCheckData",
    "CmdInitialize",
    "CmdInstallKey",
    "CmdAuthData",
    "CmdUnlock",
    "CmdUnlockCAAM",
    "CmdUnlockOCOTP",
    "CmdUnlockSNVS",
    # Elements
    "EnumWriteOps",
    "EnumCheckOps",
    "EnumAlgorithm",
    "EnumCertFormat",
    "EnumInsKey",
    "EnumAuthDat",
    "EnumEngine",
    "EnumItm",
    # Methods
    "parse",
    # KeyStore
    "KeyStore",
    "KeySourceType",
]
