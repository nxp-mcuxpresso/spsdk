#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.commands import CmdWriteData, EnumWriteOps
from spsdk.image.images import BootImgBase, BootImgRT, parse
from spsdk.image.secret import SrkItem, SrkTable
from spsdk.image.segments import SegCSF, SegDCD


@pytest.mark.skip
def test_create_image():
    pass


def test_info_image(data_dir):
    with open(os.path.join(data_dir, "imx8qma0mek-sd.bin"), "rb") as f:
        data = f.read()
    img = parse(data)
    assert isinstance(img, BootImgBase)


def test_rt_image_parse(data_dir):
    with open(f"{data_dir}/led_blinky_xip_srec_iar_dcd_unsigned.bin", "rb") as f:
        image_data = f.read()
    boot_image = BootImgRT.parse(image_data)
    boot_image_data = boot_image.export()
    assert image_data == boot_image_data


def test_rt_image_dcd(data_dir):
    with open(f"{data_dir}/led_blinky_xip_srec_iar_dcd_unsigned.bin", "rb") as f:
        image_data = f.read()
    with open(f"{data_dir}/dcd.bin", "rb") as f:
        dcd_data = f.read()

    parsed_dcd = BootImgRT.parse(image_data).dcd.export()
    assert parsed_dcd == dcd_data


def test_rt_image_invalid():
    with pytest.raises(SPSDKError, match="Invalid IVT offset"):
        BootImgRT(address=0x1, offset=16)
    with pytest.raises(SPSDKError, match="Invalid version"):
        BootImgRT(address=0x1, version=0x44)
    with pytest.raises(SPSDKError, match="Plugin is not supported"):
        BootImgRT(address=0x1, plugin=True)
    bimg = BootImgRT(address=0x1)
    with pytest.raises(SPSDKError, match="Invalid length of DEK key"):
        bimg.dek_key = bytes(15)
    with pytest.raises(SPSDKError, match="Invalid IVT offset"):
        bimg.ivt_offset = 15
    bimg = BootImgRT(address=0x1)
    bimg._dek_key = bytes(15)
    bimg.hab_encrypted
    csf = SegCSF(enabled=True)
    csf.append_command(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=[(0x30340004, 0x4F400005)]))
    with pytest.raises(SPSDKError, match="Nonce not present"):
        bimg.csf = csf
    bimg._nonce = bytes(15)
    with pytest.raises(SPSDKError, match="Mac not present"):
        bimg.csf = csf


def test_rt_image_invalid_add_dcd():
    bimg = BootImgRT(address=0x1)
    dcd = SegDCD()
    bimg._dcd = dcd
    with pytest.raises(SPSDKError, match="DCD is already present"):
        bimg.add_dcd_bin(data=bytes(10))
    bimg = BootImgRT(address=0x1)
    dcd1 = SegDCD(enabled=True)
    data = dcd1.export()
    with pytest.raises(SPSDKError, match="DCD must be enabled to include DCD into export"):
        bimg.add_dcd_bin(data=data)


def test_rt_image_invalid_add_csf():
    bimg = BootImgRT(address=0x1)
    srk = SrkTable()
    with pytest.raises(SPSDKError, match="Invalid length of srk table"):
        bimg.add_csf_standard_auth(
            version=1,
            srk_table=srk,
            src_key_index=0,
            csf_cert=bytes(4),
            csf_priv_key=bytes(4),
            img_cert=bytes(4),
            img_priv_key=bytes(4),
        )
    item = SrkItem()
    srk.append(item)
    with pytest.raises(SPSDKError, match="Invalid index of selected SRK key"):
        bimg.add_csf_standard_auth(
            version=1,
            srk_table=srk,
            src_key_index=10,
            csf_cert=bytes(4),
            csf_priv_key=bytes(4),
            img_cert=bytes(4),
            img_priv_key=bytes(4),
        )


def test_rt_image_invalid_hab_encrypt_app_data():
    bimg = BootImgRT(address=0x1)
    with pytest.raises(SPSDKError, match="Nonce is not present"):
        bimg._hab_encrypt_app_data(app_data=bytes(16))
    bimg = BootImgRT(address=0x1)
    bimg._nonce = bytes(16)
    with pytest.raises(SPSDKError, match="Invalid length of application data"):
        bimg._hab_encrypt_app_data(app_data=bytes(15))
    bimg = BootImgRT(address=0x1)
    bimg._dek_key = None
    bimg._nonce = bytes(16)
    with pytest.raises(SPSDKError, match="DEK key is not present"):
        bimg._hab_encrypt_app_data(app_data=bytes(16))


def test_rt_image_invalid_decrypted_app_data():
    bimg = BootImgRT(address=0x1)
    with pytest.raises(SPSDKError, match="Application not present"):
        bimg.decrypted_app_data()


def test_rt_image_invalid_add_csf_encrypted():
    bimg = BootImgRT(address=0x1)
    srk = SrkTable()
    with pytest.raises(SPSDKError, match="Invalid length of srk table"):
        bimg.add_csf_encrypted(
            version=1,
            srk_table=srk,
            src_key_index=2,
            csf_cert=bytes(16),
            csf_priv_key=bytes(16),
            img_cert=bytes(16),
            img_priv_key=bytes(16),
        )
    srk.append(SrkItem())
    with pytest.raises(SPSDKError, match="Invalid index of srk table"):
        bimg.add_csf_encrypted(
            version=1,
            srk_table=srk,
            src_key_index=10,
            csf_cert=bytes(4),
            csf_priv_key=bytes(4),
            img_cert=bytes(4),
            img_priv_key=bytes(4),
        )
