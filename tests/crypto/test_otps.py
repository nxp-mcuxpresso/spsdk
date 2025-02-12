#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.crypto.keys import PublicKey, PublicKeyEcc


def test_otps_ecc_puk_parsing(data_dir: str) -> None:
    puk1 = PublicKey.load(f"{data_dir}/otps_org.pub")
    puk2 = PublicKey.load(f"{data_dir}/otps_extracted.bin")
    assert isinstance(puk1, PublicKeyEcc)
    assert isinstance(puk2, PublicKeyEcc)
    assert puk1 == puk2
