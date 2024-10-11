#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from datetime import datetime, timezone
from struct import pack
from time import sleep
from typing import Optional

import pytest
from bitstring import BitArray

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi.mbi import create_mbi_class
from spsdk.image.trustzone import TrustZone
from spsdk.mboot.commands import KeyProvUserKeyType
from spsdk.mboot.exceptions import McuBootConnectionError
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.mcuboot import McuBoot, PropertyTag
from spsdk.mboot.memories import ExtMemId
from spsdk.sbfile.sb2.commands import CmdErase, CmdFill, CmdLoad, CmdMemEnable
from spsdk.sbfile.sb2.images import BootImageV21, BootSectionV2, CertBlockV1, SBV2xAdvancedParams
from spsdk.utils.crypto.otfad import KeyBlob, Otfad
from spsdk.utils.misc import Endianness, align_block, load_binary
from tests.misc import compare_bin_files

# Flag allowing to switch between testing expected image content and generating an output image
# - use True for "unit-test" mode: output images are not saved but are compared with existing images
# - use False for "production" mode: output images are saved to disk and burned into FLASH
TEST_IMG_CONTENT = True
# Set to True to re-generate key-store; In production mode, the flag should be set to True because key-store is
# specific for each chip (each piece); For testing purpose, this is set to False
UPDATE_KEYSTORE = False
# Set to True to disable changes in shadow registers; this should be used in case fuses are blown
NO_SHADOWS = False
# name of the data sub-directory with input images
INPUT_IMAGES_SUBDIR = "input_images"
# name of the data sub-directory with output images
OUTPUT_IMAGES_SUBDIR = "output"
# name of the data sub-directory with key-store data
KEYSTORE_SUBDIR = "key_store"
# file name of the FCB file for FLASH configuration
FCB_FILE_NAME = "rt500_oct_flash_fcb.bin"
# file name of the key store
KEY_STORE_FILE_NAME = "key_store_spsdk.bin"

# Master key for signed OTP use-case
MASTER_KEY = "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
# Counter initialization vector for encrypted images; For production use None to generate random value
ENCR_CTR_IV = bytes.fromhex("fff5a54ee37de8f9606c048d941588df")


#######################################################################################################################
# Helper functions
#######################################################################################################################


@pytest.fixture(scope="module")
def data_dir(data_dir: str) -> str:
    """:return: absolute path where data files for the test are located"""
    return os.path.join(data_dir, "rt5xx")


def write_image(data_dir: str, image_file_name: str, bin_data: bytes) -> None:
    """In production mode, this function should write image to the disk and burn info external FLASH.
    In test mode, the function just compare existing image with provided image.

    :param data_dir: absolute path of the data directory
    :param image_file_name: of the output image on the disk
    :param bin_data: binary content of the image
    """
    path = os.path.join(data_dir, OUTPUT_IMAGES_SUBDIR, image_file_name)
    if TEST_IMG_CONTENT:
        compare_bin_files(path, bin_data)
    else:
        with open(path, "wb") as f:
            f.write(bin_data)
        # burn info external flash; processor must be connected using USB
        mboot = burn_img_via_usb_into_flexspi_flash(data_dir, bin_data)
        mboot.close()


def write_sb(data_dir: str, sb_file_name: str, bin_data: bytes, key_store: KeyStore) -> None:
    """In production mode, this function should write SB file to the disk and burn info external FLASH.
    In test mode, the function just compare existing content with provided content.

    :param data_dir: absolute path of the data directory
    :param sb_file_name: of the output SB file on the disk
    :param bin_data: binary content of the SB file
    :param key_store: key-store used for SB file
    """
    path = os.path.join(data_dir, OUTPUT_IMAGES_SUBDIR, sb_file_name)
    if TEST_IMG_CONTENT:
        compare_bin_files(path, bin_data)
    else:
        with open(path, "wb") as f:
            f.write(bin_data)
        send_sb_via_usb_into_processor(bin_data, key_store)


#######################################################################################################################
# Example functions communicating with the processor needed to burn the image
# These functions expects USB connection with target processor, so they are not part of the unit-test
#######################################################################################################################


def write_shadow_regis(data_dir: str, writes: list[tuple[int, int]]) -> None:
    """Write shadow registers:
    - prepares and burns into FLASH a binary application for initialization of shadow registers
    - the application is launched using "execute" command
    - after registers are written, the application do software reset to return back to boot-loader

    :param data_dir: absolute path of directory with data files
    :param writes: list of show register initialization tuples, that contain:
    - the first parameter is an address of the shadow register
    - second parameter represents 32-bit value (unsigned integer)
    The list may contain maximum 12 tuples
    """
    if TEST_IMG_CONTENT:
        return
    if NO_SHADOWS:
        return

    assert len(writes) <= 12
    write_shadows_app = load_binary(os.path.join(data_dir, "write_shadows", "write_shadows.bin"))
    stack_ptr = int.from_bytes(write_shadows_app[:4], byteorder=Endianness.LITTLE.value)
    initial_pc = int.from_bytes(write_shadows_app[4:8], byteorder=Endianness.LITTLE.value)
    # write_shadow is an application, that contains table of 12 writes, for each write 32 bit address and 32-bit value
    write_shadows_arr = BitArray(write_shadows_app)
    # now we construct an existing table content to be replaced
    datatable_old = "0x"
    for index in range(12):
        char = hex(index)[2:]
        datatable_old += "d" + char + "debabe"
        datatable_old += "2" + char + "436587"
    assert len(datatable_old) == 12 * 8 * 2 + 2
    # this is new table content
    datatable_new = bytes()
    for addr, value in writes:
        datatable_new += pack("<I", value)
        datatable_new += pack("<I", addr)
    # the table must contain 12 entries, so first entry is repeated, until table is full needed
    for _ in range(12 - len(writes)):
        datatable_new += pack("<I", writes[0][1])  # value
        datatable_new += pack("<I", writes[0][0])  # addr
    assert len(datatable_new) == 12 * 8
    # replace the table in the image
    res = write_shadows_arr.replace(datatable_old, datatable_new, bytealigned=True)
    assert res == 1
    # burn image into FLASH
    mboot = burn_img_via_usb_into_flexspi_flash(data_dir, write_shadows_arr.bytes)
    assert mboot is not None

    assert mboot.execute(initial_pc, 0x8001000, stack_ptr)
    mboot.close()
    sleep(2)  # wait until boot-loader is restarted


def open_mboot() -> McuBoot:
    """Open USB communication with RT5xx boot-loader

    :return: McuBoot instance
    :raises McuBootConnectionError: if device not connected
    """
    assert not TEST_IMG_CONTENT

    devs = []
    for _ in range(
        5
    ):  # try three times to find USB device (wait until shadows registers are ready)
        devs = MbootUARTInterface.scan("RT5xx")
        if len(devs) == 1:
            break

        sleep(1)

    if len(devs) != 1:
        raise McuBootConnectionError(
            "RT5xx not connected via USB, "
            "ensure BOOT CONFIG SW7 is ON,OFF,ON and connect USB cable via J38"
        )

    mboot = McuBoot(devs[0], True)
    mboot.open()
    assert mboot.is_opened

    # test connection
    # blhost -u 0x1FC9,0x20 get-property 1
    res = mboot.get_property(PropertyTag.CURRENT_VERSION)
    assert res is not None

    return mboot


def burn_img_via_usb_into_flexspi_flash(data_dir: str, img_data: bytes) -> Optional[McuBoot]:
    """Burn image into external FLASH connected through FlexSPI

    :param data_dir: absolute path where the data files are located
    :param img_data: binary image data
    :return: McuBoot instance to talk to processor bootloader; None in test mode
    :raises ConnectionError: if USB connection with processor's boot-loader cannot be established
    """
    if TEST_IMG_CONTENT:  # this function communicates with HW board, it cannot be used in test mode
        return None

    mboot = open_mboot()

    # configure FLASH memory
    # blhost -u 0x1FC9,0x20 -- fill-memory 0x10c000 4 0xc0403006
    assert mboot.fill_memory(0x10C000, 4, 0xC0403006)
    # blhost -u 0x1FC9,0x20 -- configure-memory 9 0x10c000
    assert mboot.configure_memory(0x10C000, ExtMemId.FLEX_SPI_NOR.tag)

    # blhost -u 0x1FC9,0x20 -- list-memory
    mem_dict = mboot.get_memory_list()
    assert mem_dict["external_mems"]

    # erase the FLASH
    # blhost -u 0x1FC9,0x20 -- flash-erase-region 0x8000000 0x10000
    assert mboot.flash_erase_region(0x8000000, 0x10000, ExtMemId.FLEX_SPI_NOR.tag)

    # write FCB to configure FLASH
    # blhost -u 0x1FC9,0x20 -- write-memory 0x8000400 "rt500_oct_flash_fcb.bin"
    with open(os.path.join(data_dir, FCB_FILE_NAME), "rb") as f:
        fcb = f.read()
    assert mboot.write_memory(0x8000400, fcb, ExtMemId.FLEX_SPI_NOR.tag)

    # write application to FLASH
    # blhost -u 0x1FC9,0x20 -- write-memory 0x8001000 "app.bin"
    assert mboot.write_memory(0x8001000, img_data, ExtMemId.FLEX_SPI_NOR.tag)

    return mboot


def send_sb_via_usb_into_processor(sb_data: bytes, key_store: KeyStore) -> None:
    """Send SB file into processor

    :param sb_data: SB file to be sent
    :param key_store: key-store used for SB file
    :raises ConnectionError: if USB connection with processor's boot-loader cannot be established
    """
    if TEST_IMG_CONTENT:  # this function communicates with HW board, it cannot be used in test mode
        return

    mboot = open_mboot()

    if key_store.key_source == KeySourceType.KEYSTORE:
        # configure keystore into processor
        # Mind key store is device specific, it is unique for each piece chip
        # blhost -u 0x1FC9,0x20 -- key-provisioning write_key_store "key_store\key_store_spsdk.bin"
        assert mboot.kp_write_key_store(key_store.export())

    # write SB
    assert mboot.receive_sb_file(sb_data)
    mboot.close()


def burn_rkht_fuses() -> None:
    """Burn RKHT fuses, permanent irreversible operation
    (This script was not tested on HW)"""

    mboot = open_mboot()

    # RKTH = 321f3724b5d10bb3e6e2703bd519131eef4de589b288d5f0d339f299ff753f2f
    # burn fuses, permanent irreversible operation
    assert mboot.efuse_program_once(0x78, 0x24371F32)
    assert mboot.efuse_program_once(0x79, 0xB30BD1B5)
    assert mboot.efuse_program_once(0x7A, 0x3B70E2E6)
    assert mboot.efuse_program_once(0x7B, 0x1E1319D5)
    assert mboot.efuse_program_once(0x7C, 0x89E54DEF)
    assert mboot.efuse_program_once(0x7D, 0xF0D588B2)
    assert mboot.efuse_program_once(0x7E, 0x99F239D3)
    assert mboot.efuse_program_once(0x7F, 0x2F3F75FF)

    # verify fuses
    assert mboot.efuse_read_once(0x78) == 0x24371F32
    assert mboot.efuse_read_once(0x79) == 0xB30BD1B5
    assert mboot.efuse_read_once(0x7A) == 0x3B70E2E6
    assert mboot.efuse_read_once(0x7B) == 0x1E1319D5
    assert mboot.efuse_read_once(0x7C) == 0x89E54DEF
    assert mboot.efuse_read_once(0x7D) == 0xF0D588B2
    assert mboot.efuse_read_once(0x7E) == 0x99F239D3
    assert mboot.efuse_read_once(0x7F) == 0x2F3F75FF

    mboot.close()


def generate_keystore(data_dir: str) -> bytes:
    """Generate key-store with
    - OTFAD KEK key for encryption of OTFAD key blobs
    - HMAC user key for signed images
    - SB KEK key for SB2.1 file processing

    :param data_dir: absolute path where test data files are located
    :return: key-store binary data from the processor
    """
    mboot = open_mboot()

    # blhost -u 0X1FC9,0x20 -- key-provisioning enroll
    assert mboot.kp_enroll()

    # This key is needed for OTFAD:
    # blhost -u 0X1FC9,0x20 -- key-provisioning set_user_key 2 keys/OTFADKek_PUF.bin
    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "OTFADKek_PUF.bin"), "rb") as f:
        otfad_key = f.read()
    assert mboot.kp_set_user_key(KeyProvUserKeyType.OTFADKEK.tag, otfad_key)

    # This key is needed for SB2.1 files:
    # blhost -u 0X1FC9,0x20  -- key-provisioning set_user_key 3 keys/SBkek_PUF.bin
    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "SBkek_PUF.bin"), "rb") as f:
        kek_key = f.read()
    assert mboot.kp_set_user_key(KeyProvUserKeyType.SBKEK.tag, kek_key)

    # This key is needed for signed bootable images:
    # blhost -u 0X1FC9,0x20 -- key-provisioning set_user_key 11 key_store/userkey.bin
    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "userkey.bin"), "rb") as f:
        user_key = f.read()
    assert mboot.kp_set_user_key(KeyProvUserKeyType.USERKEK.tag, user_key)

    # blhost -u 0X1FC9,0x20 -- key-provisioning read_key_store key_store/key_store_rt5xx.bin
    key_store_bin = mboot.kp_read_key_store()
    assert key_store_bin
    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, KEY_STORE_FILE_NAME), "wb") as f:
        f.write(key_store_bin)
    mboot.close()

    return key_store_bin


def get_keystore(data_dir: str) -> KeyStore:
    """Return key-store for current processor
    See description of `UPDATE_KEYSTORE` and `gen_keystore` for more details

    :param data_dir: absolute path of directory with data
    :return: instance of key-store class with key-store binary data
    """
    if UPDATE_KEYSTORE:
        key_store_bin = generate_keystore(data_dir)  # generate new key-store for current processor
    else:
        # load keystore with HMAC user key
        key_store_path = os.path.join(data_dir, KEYSTORE_SUBDIR, KEY_STORE_FILE_NAME)
        with open(key_store_path, "rb") as f:
            key_store_bin = f.read()
    return KeyStore(KeySourceType.KEYSTORE, key_store_bin)


def create_cert_block(data_dir: str) -> CertBlockV1:
    """Load 4 certificates and create certificate block

    :param data_dir: absolute path
    :return: certificate block with 4 certificates, certificate 0 is selected
    """
    # load certificates
    cert_path = os.path.join(data_dir, "keys_certs")
    cert_list = list()
    for cert_index in range(4):
        cert_list.append(
            Certificate.load(
                os.path.join(cert_path, f"root_k{str(cert_index)}_signed_cert0_noca.der.cert")
            )
        )
    # create certification block
    cert_block = CertBlockV1(build_number=1)
    cert_block.add_certificate(cert_list[0])
    # add hashes
    for root_key_index, cert in enumerate(cert_list):
        if cert:
            cert_block.set_root_key_hash(root_key_index, cert)
    return cert_block


def create_signature_provider(data_dir: str) -> SignatureProvider:
    priv_key_pem_path = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key_pem_path}")
    return signature_provider


#######################################################################################################################
# Tests functions for creation of bootable images
#######################################################################################################################


@pytest.mark.parametrize(
    "image_file_name",
    [
        "app_xip_mcux_unsigned.bin",
        "app_xip_iar_unsigned.bin",
    ],
)
def test_xip_crc(data_dir: str, image_file_name: str) -> None:
    """Create image with CRC

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    """
    assert image_file_name.endswith("_unsigned.bin")
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    unsigned_image = load_binary(path)

    mbi = create_mbi_class("crc_xip", "rt5xx")(app=unsigned_image, load_address=0x08001000)

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_crc.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name,ram_addr",
    [
        ("app_ram_mcux_unsigned.bin", 0x20080000),
        ("app_ram_iar_unsigned.bin", 0x80000),
    ],
)
def test_ram_crc(data_dir: str, image_file_name: str, ram_addr: int) -> None:
    """Create image with CRC

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    :param ram_addr: address in RAM, where the image should be located
    """
    assert image_file_name.endswith("_unsigned.bin")
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    unsigned_image = load_binary(path)

    mbi = create_mbi_class("crc_ram", "rt5xx")(app=unsigned_image, load_address=ram_addr)

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_crc.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name,ram_addr",
    [
        ("app_ram_mcux_unsigned.bin", 0x20080000),
        ("app_ram_iar_unsigned.bin", 0x80000),
    ],
)
def test_ram_signed_otp(data_dir: str, image_file_name: str, ram_addr: int) -> None:
    """Create signed load-to-RAM image with keys stored in OTP

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    :param ram_addr: address in RAM, where the image should be located
    """
    # read unsigned image (must be built without boot header)
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    unsigned_img = load_binary(path)

    keystore = KeyStore(KeySourceType.OTP)

    cert_block = create_cert_block(data_dir)
    signature_provider = create_signature_provider(data_dir)

    mbi = create_mbi_class("signed_ram", "rt5xx")(
        app=unsigned_img,
        load_address=ram_addr,
        key_store=keystore,
        hmac_key=MASTER_KEY,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_signed_otp.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name,ram_addr",
    [
        ("app_ram_mcux_unsigned.bin", 0x20080000),
        ("app_ram_iar_unsigned.bin", 0x80000),
    ],
)
def test_ram_signed_keystore(data_dir: str, image_file_name: str, ram_addr: int) -> None:
    """Create signed load-to-RAM image with keys stored in key-store

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    :param ram_addr: address in RAM, where the image should be located
    """
    # read unsigned image (must be built without boot header)
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    org_data = load_binary(path)

    cert_block = create_cert_block(data_dir)
    signature_provider = create_signature_provider(data_dir)

    key_store = get_keystore(data_dir)

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "userkey.txt"), "r") as f:
        hmac_user_key = f.readline()

    mbi = create_mbi_class("signed_ram", "rt5xx")(
        app=org_data,
        load_address=ram_addr,
        trust_zone=TrustZone.disabled(),
        key_store=key_store,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=hmac_user_key,
    )

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_signed_keystore.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name",
    [
        "app_xip_mcux_unsigned.bin",
        "app_xip_iar_unsigned.bin",
    ],
)
def test_xip_signed(data_dir: str, image_file_name: str) -> None:
    """Create signed XIP image

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    """
    # read unsigned image (must be built without boot header)
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    unsigned_img = load_binary(path)

    cert_block = create_cert_block(data_dir)
    signature_provider = create_signature_provider(data_dir)

    mbi = create_mbi_class("signed_xip", "rt5xx")(
        app=unsigned_img,
        load_address=0x08001000,
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_signed.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name,ram_addr",
    [
        ("app_ram_mcux_unsigned.bin", 0x20080000),
        ("app_ram_iar_unsigned.bin", 0x80000),
    ],
)
def test_ram_encrypted_otp(data_dir: str, image_file_name: str, ram_addr: int) -> None:
    """Test encrypted load-to-RAM image with key stored in OTP

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    :param ram_addr: address in RAM, where the image should be located
    """
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    org_data = load_binary(path)
    key_store = KeyStore(KeySourceType.OTP)

    cert_block = create_cert_block(data_dir)
    signature_provider = create_signature_provider(data_dir)

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "userkey.txt"), "r") as f:
        hmac_user_key = f.readline()

    mbi = create_mbi_class("encrypted_signed_ram", "rt5xx")(
        app=org_data,
        load_address=ram_addr,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=hmac_user_key,
        key_store=key_store,
        ctr_init_vector=ENCR_CTR_IV,
    )

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_encr_otp.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


@pytest.mark.parametrize(
    "image_file_name,ram_addr",
    [
        ("app_ram_mcux_unsigned.bin", 0x20080000),
        ("app_ram_iar_unsigned.bin", 0x80000),
    ],
)
def test_ram_encrypted_keystore(data_dir: str, image_file_name: str, ram_addr: int) -> None:
    """Test encrypted load-to-RAM image with key stored in key-store

    :param data_dir: absolute path with data files
    :param image_file_name: name of the input image file (including extension)
    :param ram_addr: address in RAM, where the image should be located
    """
    path = os.path.join(data_dir, INPUT_IMAGES_SUBDIR, image_file_name)
    org_data = load_binary(path)

    # load keystore with HMAC user key
    key_store = get_keystore(data_dir)

    cert_block = create_cert_block(data_dir)
    signature_provider = create_signature_provider(data_dir)

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "userkey.txt"), "r") as f:
        hmac_user_key = f.readline()

    mbi = create_mbi_class("encrypted_signed_ram", "rt5xx")(
        app=org_data,
        load_address=ram_addr,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=hmac_user_key,
        key_store=key_store,
        ctr_init_vector=ENCR_CTR_IV,
    )

    out_image_file_name = image_file_name.replace("_unsigned.bin", "_encr_keystore.bin")
    write_image(data_dir, out_image_file_name, mbi.export())


def test_production_disabled():
    """Ensure for unit test the configuration is not for production"""
    assert TEST_IMG_CONTENT


@pytest.mark.parametrize(
    "subdir,image_name",
    [
        # plain image, unsigned
        (INPUT_IMAGES_SUBDIR, "app_ram_iar_unsigned"),
        (INPUT_IMAGES_SUBDIR, "app_xip_mcux_unsigned"),
        # crc
        (OUTPUT_IMAGES_SUBDIR, "app_ram_iar_crc"),
    ],
)
def test_sb_unsigned_keystore(data_dir: str, subdir: str, image_name: str) -> None:
    """Test creation of SB file for RT5xx with unsigned image. SBKEK Key for SB file is stored in KEYSTORE.

    :param data_dir: absolute path of the directory with data files for the test
    :param image_name: file name of the unsigned image WITHOUT file extension
    """
    if not TEST_IMG_CONTENT:
        write_shadow_regis(data_dir, [(0x40130194, 0x00000080)])  # BOOT_CFG[5]: USE_PUF = 1

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "SBkek_PUF.txt"), "r") as f:
        sbkek_str = f.readline()

    adv_params = SBV2xAdvancedParams(
        dek=b"\xA0" * 32,
        mac=b"\x0B" * 32,
        nonce=bytes(16),
        timestamp=datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc),
    )
    # create boot image
    boot_image = BootImageV21(
        kek=bytes.fromhex(sbkek_str),
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        # parameters fixed for test only (to have always same output), do not use in production
        advanced_params=adv_params,
        flags=0x0008,
    )

    # certificate + private key
    cert_block = create_cert_block(data_dir)
    priv_key = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = get_signature_provider(local_file_key=priv_key)

    boot_image.cert_block = cert_block
    boot_image.signature_provider = signature_provider

    fcb_data = load_binary(os.path.join(data_dir, FCB_FILE_NAME))
    plain_image_data = load_binary(os.path.join(data_dir, subdir, image_name + ".bin"))

    # images are aligned for test purposes only, otherwise export will align with random data
    fcb_data = align_block(fcb_data, 16)
    plain_image_data = align_block(plain_image_data, 16)

    # create boot section 0
    boot_section = BootSectionV2(
        0,
        CmdFill(address=0x10C000, pattern=int("063040C0", 16)),
        CmdMemEnable(0x10C000, 4, ExtMemId.FLEX_SPI_NOR.tag),
        CmdErase(address=0x8000000, length=0x10000),
        CmdLoad(address=0x8000400, data=fcb_data),
        CmdLoad(address=0x8001000, data=plain_image_data),
    )
    boot_image.add_boot_section(boot_section)

    sb_file = boot_image.export(
        padding=bytes(8)
    )  # padding for unit test only, to avoid random data
    write_sb(data_dir, image_name + "_keystore.sb", sb_file, get_keystore(data_dir))


@pytest.mark.parametrize(
    "subdir,image_name",
    [
        # plain image, unsigned
        (INPUT_IMAGES_SUBDIR, "app_ram_iar_unsigned"),
        (INPUT_IMAGES_SUBDIR, "app_xip_mcux_unsigned"),
        # crc
        (OUTPUT_IMAGES_SUBDIR, "app_ram_iar_crc"),
    ],
)
def test_sb_unsigned_otp(data_dir: str, subdir: str, image_name: str) -> None:
    """Test creation of SB file for RT5xx with unsigned image. SBKEK Key for SB file is stored in KEYSTORE.

    :param data_dir: absolute path of the directory with data files for the test
    :param image_name: file name of the unsigned image WITHOUT file extension
    """
    write_shadow_regis(
        data_dir,
        [
            (0x40130194, 0x00000000),  # BOOT_CFG[5]: USE_OTP = 0
            # MASTER KEY - 000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff
            (0x401301C0, 0xCCDDEEFF),
            (0x401301C4, 0x8899AABB),
            (0x401301C8, 0x44556677),
            (0x401301CC, 0x00112233),
            (0x401301D0, 0x0C0D0E0F),
            (0x401301D4, 0x08090A0B),
            (0x401301D8, 0x04050607),
            (0x401301DC, 0x00010203),
        ],
    )

    sbkek = KeyStore.derive_sb_kek_key(bytes.fromhex(MASTER_KEY))

    adv_params = SBV2xAdvancedParams(
        dek=b"\xA0" * 32,
        mac=b"\x0B" * 32,
        nonce=bytes(16),
        timestamp=datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc),
    )

    # create SB file boot image
    boot_image = BootImageV21(
        kek=sbkek,
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        # parameters fixed for test only (to have always same output), do not use in production
        advanced_params=adv_params,
        flags=0x0008,
    )

    # certificate + private key
    cert_block = create_cert_block(data_dir)
    priv_key = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = get_signature_provider(local_file_key=priv_key)

    boot_image.cert_block = cert_block
    boot_image.signature_provider = signature_provider

    fcb_data = load_binary(os.path.join(data_dir, FCB_FILE_NAME))
    plain_image_data = load_binary(os.path.join(data_dir, subdir, image_name + ".bin"))

    # images are aligned for test purposes only, otherwise export will align with random data
    fcb_data = align_block(fcb_data, 16)
    plain_image_data = align_block(plain_image_data, 16)

    # create boot section 0
    boot_section = BootSectionV2(
        0,
        CmdFill(address=0x10C000, pattern=int("063040C0", 16)),
        CmdMemEnable(0x10C000, 4, ExtMemId.FLEX_SPI_NOR.tag),
        CmdErase(address=0x8000000, length=0x00800),
        CmdErase(address=0x8001000, length=0x10000),
        CmdLoad(address=0x8000400, data=fcb_data),
        CmdLoad(address=0x8001000, data=plain_image_data),
    )
    boot_image.add_boot_section(boot_section)

    sb_file = boot_image.export(
        padding=bytes(8)
    )  # padding for unit test only, to avoid random data
    write_sb(data_dir, image_name + "_otp.sb", sb_file, KeyStore(KeySourceType.OTP))


@pytest.mark.parametrize(
    "subdir,image_name",
    [
        # signed
        (OUTPUT_IMAGES_SUBDIR, "app_ram_iar_signed_keystore"),
        # encrypted
        (OUTPUT_IMAGES_SUBDIR, "app_ram_iar_encr_keystore"),
    ],
)
def test_sb_signed_encr_keystore(data_dir: str, subdir: str, image_name: str) -> None:
    """Test creation of SB file for RT5xx with signed or encrypted image. SBKEK Key for SB file is stored in KEYSTORE.

    :param data_dir: absolute path of the directory with data files for the test
    :param image_name: file name of the signed or encrypted image WITHOUT file extension
    """
    if not TEST_IMG_CONTENT:
        write_shadow_regis(
            data_dir,
            [
                (0x40130194, 0x00000080),  # BOOT_CFG[5]: USE_PUF = 1
                (
                    0x40130180,
                    0x00900010,
                ),  # BOOT_CFG[0]: DEFAULT_ISP = 1(USB); SECURE_BOOT_EN=1(enabled)
            ],
        )

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "SBkek_PUF.txt"), "r") as f:
        sbkek_str = f.readline()

    adv_params = SBV2xAdvancedParams(
        dek=b"\xA0" * 32,
        mac=b"\x0B" * 32,
        nonce=bytes(16),
        timestamp=datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc),
    )

    # create SB file boot image
    boot_image = BootImageV21(
        kek=bytes.fromhex(sbkek_str),
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        # parameters fixed for test only (to have always same output), do not use in production
        advanced_params=adv_params,
        flags=0x0008,
    )

    # certificate + private key
    cert_block = create_cert_block(data_dir)
    priv_key = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = get_signature_provider(local_file_key=priv_key)

    boot_image.cert_block = cert_block
    boot_image.signature_provider = signature_provider

    fcb_data = load_binary(os.path.join(data_dir, FCB_FILE_NAME))
    plain_image_data = load_binary(os.path.join(data_dir, subdir, image_name + ".bin"))

    # images are aligned for test purposes only, otherwise export will align with random data
    fcb_data = align_block(fcb_data, 16)
    plain_image_data = align_block(plain_image_data, 16)

    # create boot section 0
    boot_section = BootSectionV2(
        0,
        CmdFill(address=0x10C000, pattern=int("063040C0", 16)),
        CmdMemEnable(0x10C000, 4, ExtMemId.FLEX_SPI_NOR.tag),
        CmdErase(address=0x8000000, length=0x10000),
        CmdLoad(address=0x8000400, data=fcb_data),
        CmdLoad(address=0x8001000, data=plain_image_data),
    )
    boot_image.add_boot_section(boot_section)

    sb_file = boot_image.export(
        padding=bytes(8)
    )  # padding for unit test only, to avoid random data
    write_sb(data_dir, image_name + "_keystore.sb", sb_file, get_keystore(data_dir))


@pytest.mark.parametrize(
    "subdir,image_name,secure",
    [
        # signed XIP
        (OUTPUT_IMAGES_SUBDIR, "app_xip_iar_signed", True),
        # unsigned load-to-ram
        (INPUT_IMAGES_SUBDIR, "app_ram_iar_unsigned", False),
    ],
)
def test_sb_otfad_keystore(data_dir: str, subdir: str, image_name: str, secure: bool) -> None:
    """Test creation of SB file for RT5xx with OTFAD encrypted image. SBKEK Key for SB file is stored in KEYSTORE.

    :param data_dir: absolute path of the directory with data files for the test
    :param image_name: file name of the signed image WITHOUT file extension
    :param secure: whether security should be enabled
    """
    if not TEST_IMG_CONTENT:
        secure_boot_en = 0x900000 if secure else 0  # BOOT_CFG[0]: SECURE_BOOT_EN=?
        write_shadow_regis(
            data_dir,
            [
                (0x40130194, 0x00000080),  # BOOT_CFG[5]: USE_PUF = 1
                (0x401301A8, 0x00001000),  # OTFAD CFG
                (0x40130180, 0x00000010 + secure_boot_en),  # BOOT_CFG[0]: DEFAULT_ISP = 1(USB)
            ],
        )

    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "SBkek_PUF.txt"), "r") as f:
        sbkek_str = f.readline()

    key_store = get_keystore(data_dir)

    adv_params = SBV2xAdvancedParams(
        dek=b"\xA0" * 32,
        mac=b"\x0B" * 32,
        nonce=bytes(16),
        timestamp=datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc),
    )

    # create SB file boot image
    boot_image = BootImageV21(
        kek=bytes.fromhex(sbkek_str),
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        # parameters fixed for test only (to have always same output), do not use in production
        advanced_params=adv_params,
        flags=0x0008,
    )

    # certificate + private key
    cert_block = create_cert_block(data_dir)
    priv_key = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = get_signature_provider(local_file_key=priv_key)

    boot_image.cert_block = cert_block
    boot_image.signature_provider = signature_provider

    fcb_data = load_binary(os.path.join(data_dir, FCB_FILE_NAME))
    plain_image_data = load_binary(os.path.join(data_dir, subdir, image_name + ".bin"))

    # images are aligned for test purposes only, otherwise export will align with random data
    fcb_data = align_block(fcb_data, 16)
    plain_image_data = align_block(plain_image_data, 16)

    otfad = Otfad()
    # keys used to encrypt image, for RT5xx always define 4 key blobs!!
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    otfad.add_key_blob(
        KeyBlob(0x8001000, 0x80FFFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    # to use random keys: otfad.add_key_blob(KeyBlob(0x8001000, 0x80FFFFF))
    otfad.add_key_blob(
        KeyBlob(0x8FFD000, 0x8FFDFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    otfad.add_key_blob(
        KeyBlob(0x8FFE000, 0x8FFEFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    otfad.add_key_blob(
        KeyBlob(0x8FFF000, 0x8FFFFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    encr_image_data = otfad.encrypt_image(align_block(plain_image_data, 512), 0x8001000, False)
    with open(os.path.join(data_dir, KEYSTORE_SUBDIR, "OTFADKek_PUF.txt"), "r") as f:
        otfad_kek = f.readline()

    # create boot section 0
    boot_section = BootSectionV2(
        0,
        # configure external FLASH
        CmdFill(address=0x10C000, pattern=int("063040C0", 16)),
        CmdMemEnable(0x10C000, 4, ExtMemId.FLEX_SPI_NOR.tag),
        # erase the FLASH
        CmdErase(address=0x8000000, length=0x10000),
        # load key blobs allowing th decrypt the image
        CmdLoad(address=0x8000000, data=otfad.encrypt_key_blobs(kek=otfad_kek)),
        # load FCB data
        CmdLoad(address=0x8000400, data=fcb_data),
        # load key-store
        CmdLoad(address=0x8000800, data=key_store.export()),
        # load encrypted image
        CmdLoad(address=0x8001000, data=encr_image_data),
    )
    boot_image.add_boot_section(boot_section)

    sb_file = boot_image.export(
        padding=bytes(8)
    )  # padding for unit test only, to avoid random data
    write_sb(data_dir, image_name + "_otfad_keystore.sb", sb_file, key_store)


@pytest.mark.parametrize(
    "subdir,image_name,secure",
    [
        # signed XIP
        (OUTPUT_IMAGES_SUBDIR, "app_xip_iar_signed", True),
        # unsigned load-to-ram
        (INPUT_IMAGES_SUBDIR, "app_ram_iar_unsigned", False),
    ],
)
def test_sb_otfad_otp(data_dir: str, subdir: str, image_name: str, secure: bool) -> None:
    """Test creation of SB file for RT5xx with OTFAD encrypted image.
    SBKEK Key for SB file is derived from master key in OTP.

    :param data_dir: absolute path of the directory with data files for the test
    :param image_name: file name of the signed image WITHOUT file extension
    :param secure: whether security should be enabled
    """
    if not TEST_IMG_CONTENT:
        secure_boot_en = 0x900000 if secure else 0  # BOOT_CFG[0]: SECURE_BOOT_EN=?
        write_shadow_regis(
            data_dir,
            [
                (0x401301A8, 0x00001000),  # OTFAD CFG
                # OTFAD KEY INPUT - 12aaaaaabb34bbbbcccc56ccdddddd78
                (0x401301B0, 0xAAAAAA12),
                (0x401301B4, 0xBBBB34BB),
                (0x401301B8, 0xCC56CCCC),
                (0x401301BC, 0x78DDDDDD),
            ],
        )
        write_shadow_regis(
            data_dir,
            [
                # MASTER KEY - 000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff
                (0x401301C0, 0xCCDDEEFF),
                (0x401301C4, 0x8899AABB),
                (0x401301C8, 0x44556677),
                (0x401301CC, 0x00112233),
                (0x401301D0, 0x0C0D0E0F),
                (0x401301D4, 0x08090A0B),
                (0x401301D8, 0x04050607),
                (0x401301DC, 0x00010203),
                # BOOT_CFG[0]: DEFAULT_ISP = 1(USB)
                (0x40130180, 0x00000010 + secure_boot_en),
            ],
        )

    sbkek = KeyStore.derive_sb_kek_key(bytes.fromhex(MASTER_KEY))
    otfad_kek = KeyStore.derive_otfad_kek_key(
        bytes.fromhex(MASTER_KEY), bytes.fromhex("12aaaaaabb34bbbbcccc56ccdddddd78")
    )

    key_store = get_keystore(data_dir)

    adv_params = SBV2xAdvancedParams(
        dek=b"\xA0" * 32,
        mac=b"\x0B" * 32,
        nonce=bytes(16),
        timestamp=datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc),
    )

    # create SB file boot image
    boot_image = BootImageV21(
        kek=sbkek,
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        # parameters fixed for test only (to have always same output), do not use in production
        advanced_params=adv_params,
        flags=0x0008,
    )

    # certificate + private key
    cert_block = create_cert_block(data_dir)
    priv_key = os.path.join(data_dir, "keys_certs", "k0_cert0_2048.pem")
    signature_provider = get_signature_provider(local_file_key=priv_key)

    boot_image.cert_block = cert_block
    boot_image.signature_provider = signature_provider

    fcb_data = load_binary(os.path.join(data_dir, FCB_FILE_NAME))
    plain_image_data = load_binary(os.path.join(data_dir, subdir, image_name + ".bin"))

    # images are aligned for test purposes only, otherwise export will align with random data
    fcb_data = align_block(fcb_data, 16)
    plain_image_data = align_block(plain_image_data, 16)

    otfad = Otfad()
    # keys used to encrypt image, for RT5xx always define 4 key blobs!!
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    otfad.add_key_blob(
        KeyBlob(0x8001000, 0x80FFFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    # to use random keys: otfad.add_key_blob(KeyBlob(0x8001000, 0x80FFFFF))
    otfad.add_key_blob(
        KeyBlob(0x8FFD000, 0x8FFDFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    otfad.add_key_blob(
        KeyBlob(0x8FFE000, 0x8FFEFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    otfad.add_key_blob(
        KeyBlob(0x8FFF000, 0x8FFFFFF, key, counter, zero_fill=bytes(4), crc=bytes(4))
    )  # zero_fill and crc should be used only for testing !
    encr_image_data = otfad.encrypt_image(align_block(plain_image_data, 512), 0x8001000, False)

    # create boot section 0
    boot_section = BootSectionV2(
        0,
        # configure external FLASH
        CmdFill(address=0x10C000, pattern=int("063040C0", 16)),
        CmdMemEnable(0x10C000, 4, ExtMemId.FLEX_SPI_NOR.tag),
        # erase the FLASH
        CmdErase(address=0x8000000, length=0x10000),
        # load key blobs allowing th decrypt the image
        CmdLoad(address=0x8000000, data=otfad.encrypt_key_blobs(kek=otfad_kek)),
        # load FCB data
        CmdLoad(address=0x8000400, data=fcb_data),
        # load key-store
        CmdLoad(address=0x8000800, data=key_store.export()),
        # load encrypted image
        CmdLoad(address=0x8001000, data=encr_image_data),
    )
    boot_image.add_boot_section(boot_section)

    sb_file = boot_image.export(
        padding=bytes(8)
    )  # padding for unit test only, to avoid random data
    write_sb(data_dir, image_name + "_otfad_otp.sb", sb_file, key_store)
