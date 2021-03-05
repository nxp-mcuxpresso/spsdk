#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from datetime import datetime

from spsdk.utils.crypto import Certificate


def test_basics(data_dir: str) -> None:
    """Test basic features of the Certificate class"""
    with open(os.path.join(data_dir, 'selfsign_2048_v3.der.crt'), 'rb') as f:
        cert_data = f.read()

    cert = Certificate(cert_data)
    #
    assert cert.version == 'v3'
    #
    assert not cert.ca
    #
    assert cert.self_signed == 'maybe'
    #
    assert cert.self_issued
    #
    assert cert.serial_number == 0x3CC30000BABADEDA
    #
    assert cert.hash_algo == 'sha256'
    #
    mod = cert.public_key_modulus
    assert isinstance(mod, int) and mod > 10e10
    assert cert.public_key_exponent == 65537
    #
    expected_hash = b'I\xad$\xeb=+\xddR\xa8\xef\x1b\xdf\xcaa-S\x10a\xfc\x13v\xff\xd4\xacVE~\xd0\x83\x80\xa6\''
    assert cert.public_key_hash == expected_hash
    #
    usage = cert.public_key_usage
    assert usage is not None and len(usage) == 5
    for item in usage:
        assert isinstance(item, str)
    #
    assert cert.signature_algo == 'rsassa_pkcs1v15'
    #
    sign = cert.signature
    assert isinstance(sign, bytes) and len(sign) == 256
    #
    assert cert.max_path_length == 0
    #
    issuer = cert.issuer
    assert isinstance(issuer, dict) and len(issuer) == 5
    for key, value in issuer.items():
        assert isinstance(key, str)
        assert isinstance(value, str)
    #
    no_before = cert.not_valid_before
    assert isinstance(no_before, datetime) and no_before.year == 2019 and no_before.month == 5 and no_before.day == 6
    no_after = cert.not_valid_after
    assert isinstance(no_after, datetime) and no_after.year == 2039 and no_after.month == 5 and no_after.day == 1
    #
    assert cert.raw_size == 1060
    #
    assert cert.info()
    #
    data = cert.export()
    assert isinstance(data, bytes) and len(data) == cert.raw_size
