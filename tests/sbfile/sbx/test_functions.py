#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""

from spsdk.sbfile.sbx.images import (
    SecureBinaryX,
    SecureBinaryXHeader,
    SecureBinaryXType,
    TpHsmBlob,
    TpHsmBlobHeader,
)


def test_sbx():
    tphshm_header = TpHsmBlobHeader()
    tphsm_blob = TpHsmBlob(
        tphshm_header, hmac_key="51487d5c13d56346bc178d5050bc145a7924f76d77dce97456b8ef039c4f4590"
    )

    header = SecureBinaryXHeader(
        firmware_version=2,
        description="Testing SBX file",
        timestamp=25698748,
        image_type=SecureBinaryXType.OEM_PROVISIONING,
    )

    sbx = SecureBinaryX(
        tphsm_blob=tphsm_blob,
        firmware_version=2,
        description="Testing SBX file",
        timestamp=25698748,
        image_type=SecureBinaryXType.OEM_PROVISIONING,
    )

    assert (
        tphsm_blob.export() == b"\x01\x004\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x93(r\xe9"
        b"\xfe\xb2\xcb\xec\x82\xad\xbb\x1a\x17sD\xfb"
        b"\xacyS\x83\xa0\xf2\x86\xccu\xdc`\x99I\xf3\xf7\x88"
    )

    header.validate()
    assert (
        header.export() == b"sbvx\x00\x00\x01\x00\x00\x00\x00\x00\x01"
        b"\x00\x00\x00$\x01\x00\x00\xbc!\x88\x01\x00\x00\x00\x00\x02"
        b"\x00\x00\x00\xac\x00\x00\x00\x02\x00\x00\x00Testing SBX file"
    )
    assert "Total length of Block#0:     172" in str(header)

    assert "SBx commands blob" in str(sbx)
    sbx.validate()
