#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DICE RTF (Runtime Firmware) calculation utilities.

This module provides functionality for calculating RTF values used in DICE
(Device Identifier Composition Engine) attestation flows. RTF calculation
is essential for secure boot and device identity verification processes.
"""

from typing import Optional

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.image.mbi.mbi import CertBlockV21, MasterBootImage
from spsdk.utils.family import FamilyRevision


def calculate_rtf(family: FamilyRevision, mbi_data: bytes) -> Optional[bytes]:
    """Calculate RTF (Root of Trust Fingerprint) for given Master Boot Image.

    The method extracts cryptographic components from the MBI certificate block
    and computes the RTF hash using SHA256 algorithm. Only supports image types 4 and 8.

    :param family: Target MCU family and revision information.
    :param mbi_data: Raw Master Boot Image data bytes.
    :raises NotImplementedError: When MBI contains ISK certificate (not yet supported).
    :raises AssertionError: When certificate block is not version 2.1.
    :return: 32-byte RTF hash or None if image type is not supported.
    """
    image_type = MasterBootImage.get_image_type(family=family, data=mbi_data)
    if image_type not in [4, 8]:
        return None
    rtf = bytes(32)
    rtf_hash_alg = EnumHashAlgorithm.SHA256

    mbi = MasterBootImage.parse(family=family, data=mbi_data)
    assert isinstance(mbi.cert_block, CertBlockV21)
    data_hash_alg = EnumHashAlgorithm.from_label(f"sha{mbi.cert_block.signature_size *4}")

    puk = mbi.cert_block.root_key_record.root_public_key
    data_hash = get_hash(puk, data_hash_alg)
    rtf = get_hash(rtf + data_hash, rtf_hash_alg)

    rkth = mbi.cert_block.root_key_record._rkht.export()
    data_hash = get_hash(rkth, data_hash_alg)
    rtf = get_hash(rtf + data_hash, rtf_hash_alg)

    if mbi.cert_block.isk_certificate:
        raise NotImplementedError("RTF-ISK calculation is not yet supported")

    image = mbi_data[: len(mbi_data) - mbi.cert_block.signature_size]
    data_hash = get_hash(image, data_hash_alg)
    rtf = get_hash(rtf + data_hash, rtf_hash_alg)

    return rtf
