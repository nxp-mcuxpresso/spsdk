#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import os
from spsdk.image.ahab.signed_msg import MessageKeyImport


def test_signed_image_key_import(data_dir):
    with open(os.path.join(data_dir, "key_import.bin"), "rb") as f:
        ki_tlv = f.read()
    with open(os.path.join(data_dir, "oem_import_mk_sk_key.bin"), "rb") as f:
        oem_import_mk_sk_key = f.read()
    with open(os.path.join(data_dir, "local_prvk.bin"), "rb") as f:
        local_prvk = f.read()

    ki = MessageKeyImport()
    ki.parse_payload(ki_tlv)
    assert ki.export_payload() == ki_tlv
    ki.verify()


def test_signed_image_key_import_wrap_and_sign(data_dir):
    with open(os.path.join(data_dir, "key_import.bin"), "rb") as f:
        ki_tlv = f.read()
    with open(os.path.join(data_dir, "oem_import_mk_sk_key.bin"), "rb") as f:
        oem_import_mk_sk_key = f.read()
    with open(os.path.join(data_dir, "local_prvk.bin"), "rb") as f:
        local_prvk = f.read()

    ki = MessageKeyImport()
    ki.parse_payload(ki_tlv)
    ki.wrap_and_sign(private_key=local_prvk, oem_import_mk_sk_key=oem_import_mk_sk_key)
    assert ki.export_payload() == ki_tlv
    ki.verify()
