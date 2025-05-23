#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import pytest

from spsdk.crypto.certificate import Certificate


@pytest.fixture(name="srk_pem")
def srk_pem_func(data_dir):
    srk_pem = []
    for i in range(4):
        srk_pem_file = "SRK{}_sha256_4096_65537_v3_ca_crt.pem".format(i + 1)
        with open(os.path.join(data_dir, srk_pem_file), "rb") as f:
            srk_pem.append(f.read())
    return srk_pem


@pytest.fixture(name="test_certificates")
def test_certificates_fixture(srk_pem) -> list[Certificate]:
    return [Certificate.parse(cert) for cert in srk_pem]
