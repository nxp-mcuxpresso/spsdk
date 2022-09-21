#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for cryptographic utilities."""

import os

from spsdk.utils import UTILS_DATA_FOLDER

CRYPTO_SCH_FILE: str = os.path.join(UTILS_DATA_FOLDER, "sch_crypto.yml")
OTFAD_DATA_FOLDER: str = os.path.join(UTILS_DATA_FOLDER, "otfad")
OTFAD_SCH_FILE: str = os.path.join(OTFAD_DATA_FOLDER, "sch_otfad.yml")
OTFAD_DATABASE_FILE: str = os.path.join(OTFAD_DATA_FOLDER, "database.yml")

from .abstract import BackendClass
from .cert_blocks import CertBlock, CertBlockV2, CertBlockV31
from .certificate import Certificate
from .common import Counter, crypto_backend, matches_key_and_cert, serialize_ecc_signature
from .otfad import KeyBlob, Otfad

__all__ = [
    "matches_key_and_cert",
    "crypto_backend",
    "Counter",
    "BackendClass",
    "CertBlockV2",
    "Certificate",
]
