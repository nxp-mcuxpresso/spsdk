#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows methods how to create Secure Boot (SB) images.

- The SB file version 2.0 and 2.1 is used
- Boot image with and without a signature
"""

import os
from binascii import unhexlify

from spsdk import SPSDKError
from spsdk.sbfile.commands import CmdErase, CmdLoad, CmdReset
from spsdk.sbfile.images import BootImageV20, BootImageV21, BootSectionV2, SBV2xAdvancedParams
from spsdk.utils.crypto import CertBlockV2, Certificate, KeyBlob, Otfad

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(THIS_DIR, "data")


########################################################################################################################
# Certificate Section
########################################################################################################################
def gen_cert_block() -> CertBlockV2:
    """Generate a Certification Block."""
    with open(f"{DATA_DIR}/selfsign_v3.der.crt", "rb") as cert_file:
        cert_data = cert_file.read()

    cert_obj = Certificate(cert_data)
    root_key = cert_obj.public_key_hash

    cert_block = CertBlockV2()
    cert_block.set_root_key_hash(0, root_key)
    cert_block.add_certificate(cert_data)
    return cert_block


########################################################################################################################
# Boot Section
########################################################################################################################
def gen_boot_section() -> BootSectionV2:
    """Generate a Boot Section withput encryption."""
    with open(f"{DATA_DIR}/boot_image.bin", "rb") as boot_image_file:
        boot_data = boot_image_file.read()

    boot_section = BootSectionV2(
        0,
        CmdErase(address=0, length=100000),
        CmdLoad(address=0, data=boot_data),
        CmdReset(),
        hmac_count=10,
    )

    return boot_section


def gen_boot_section_otfad() -> BootSectionV2:
    """Generate a Boot Section with content encrypted by OTFAD.

    :raises SPSDKError: When length of key blobs is not 256
    """
    with open(f"{DATA_DIR}/boot_image.bin", "rb") as boot_image_file:
        boot_data = boot_image_file.read()

    otfad = Otfad()
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    otfad.add_key_blob(
        KeyBlob(
            0x08001000,
            0x0800F3FF,
            key,
            counter,
            zero_fill=bytes(4),
            crc=bytes(4),
        )
    )  # zero_fill and crc should be used only for testing !
    enc_image = otfad.encrypt_image(boot_data, 0x08001000, True)
    key_blobs = otfad.encrypt_key_blobs(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
    if len(key_blobs) != 256:
        raise SPSDKError("Length of key blobs is not 256")

    boot_section = BootSectionV2(
        0,
        CmdErase(address=0x08001000, length=0x0800F000 - 0x08001000),
        CmdLoad(address=0x08001000, data=enc_image),
        CmdLoad(address=0x08000000, data=key_blobs),
        CmdReset(),
        hmac_count=10,
    )

    return boot_section


########################################################################################################################
# Boot Image
########################################################################################################################

# Input values
KEK_VALUE = unhexlify("AC701E99BD3492E419B756EADC0985B3D3D0BC0FDB6B057AA88252204C2DA732")
DEK_VALUE = b"\xA0" * 32  # it is recommended to use random value
MAC_VALUE = b"\x0B" * 32  # it is recommended to use random value
with open(f"{DATA_DIR}/selfsign_privatekey_rsa2048.pem", "rb") as key_file:
    PRIVATE_KEY_PEM_DATA = key_file.read()


def gen_boot_image_20_base() -> bytes:
    """Generate SB2.0 image without signature."""
    # create boot section
    boot_section = gen_boot_section()
    # create boot image
    boot_image = BootImageV20(signed=False, kek=KEK_VALUE)
    boot_image.add_boot_section(boot_section)
    # print image info
    # print(boot_image.info())

    return boot_image.export()


def gen_boot_image_20() -> bytes:
    """Generate SB2.0 image with signature."""
    # create boot section
    boot_section = gen_boot_section()
    adv_params = SBV2xAdvancedParams(dek=DEK_VALUE, mac=MAC_VALUE)
    # create boot image
    boot_image = BootImageV20(
        signed=True,
        kek=KEK_VALUE,
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        advanced_params=adv_params,
    )

    # add certificate block
    boot_image.cert_block = gen_cert_block()
    boot_image.private_key_pem_data = PRIVATE_KEY_PEM_DATA
    # add boot sections
    boot_image.add_boot_section(boot_section)
    # print image info
    # print(boot_image.info())

    return boot_image.export()


def gen_boot_image_21() -> bytes:
    """Generate SB2.1 image with signature."""
    # create boot section
    boot_section = gen_boot_section()
    # advanced parameters
    adv_params = SBV2xAdvancedParams(dek=DEK_VALUE, mac=MAC_VALUE)
    # create boot image
    boot_image = BootImageV21(
        KEK_VALUE,
        boot_section,
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        advanced_params=adv_params,
    )

    # add certificate block
    boot_image.cert_block = gen_cert_block()
    boot_image.private_key_pem_data = PRIVATE_KEY_PEM_DATA
    # print image info
    print(boot_image.info())

    return boot_image.export()


def main() -> None:
    """Main."""
    # parse simple SB2.1 file generated by elftosb.exe
    with open(f"{DATA_DIR}/test_output_sb_2_1_from_elftosb.sb2", "rb") as f:
        sb_file = f.read()
    img_obj21 = BootImageV21.parse(sb_file, kek=KEK_VALUE)
    print(img_obj21.info())

    # parse SB2.1 file with OTFAD generated by elftosb.exe
    with open(f"{DATA_DIR}/otfad/test_output_sb_2_1_from_elftosb_OTFAD.sb2", "rb") as f:
        sb_file = f.read()
    img_obj21 = BootImageV21.parse(sb_file, kek=KEK_VALUE)
    print(img_obj21.info())

    # Generate not signed SB2.0 raw image
    raw_data_sb20_base = gen_boot_image_20_base()

    # Parse raw image
    img_obj20 = BootImageV20.parse(raw_data_sb20_base, kek=KEK_VALUE)
    print(img_obj20.info())

    # Generate signed SB2.0 raw image
    raw_data_sb20_signed = gen_boot_image_20()

    # Parse signed SB2.0 raw image
    img_obj20 = BootImageV20.parse(raw_data_sb20_signed, kek=KEK_VALUE)
    print(img_obj20.info())

    # Generate SB21 raw image
    raw_data_sb21_signed = gen_boot_image_21()

    # Parse raw image
    img_obj21 = BootImageV21.parse(raw_data_sb21_signed, kek=KEK_VALUE)
    print(img_obj21.info())


if __name__ == "__main__":
    main()
