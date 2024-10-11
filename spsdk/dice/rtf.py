#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for offline RTF calculation."""

from typing import Optional

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.image.mbi.mbi import CertBlockV21, MasterBootImage


def calculate_rtf(family: str, mbi_data: bytes) -> Optional[bytes]:
    """Calculate RTF for given MBI."""
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
