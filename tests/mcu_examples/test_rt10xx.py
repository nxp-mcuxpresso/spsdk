#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for RT10xx boards testing."""

import os
from datetime import datetime, timezone
from struct import pack
from time import sleep
from typing import Optional, Sequence

import pytest
from cryptography import x509

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.image.bee import BeeFacRegion, BeeKIB, BeeProtectRegionBlock, BeeRegionHeader
from spsdk.image.images import BootImgRT, FlexSPIConfBlockFCB, PaddingFCB
from spsdk.image.secret import MAC, SrkItem, SrkTable
from spsdk.mboot.exceptions import McuBootConnectionError
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import ExtMemId, McuBoot, PropertyTag
from spsdk.sbfile.sb1 import (
    BootSectionV1,
    CmdErase,
    CmdFill,
    CmdLoad,
    CmdMemEnable,
    SecureBootFlagsV1,
    SecureBootV1,
)
from spsdk.sdp.interfaces.usb import SdpUSBInterface
from spsdk.sdp.sdp import SDP, ResponseValue, SdpCommandError, StatusCode
from spsdk.utils.misc import Endianness, align, align_block, load_binary
from tests.misc import compare_bin_files

# ############################## EXECUTION PARAMETERS ##############################
# Flag allowing to switch between testing expected image content and generating an output image
# - use True for "unit-test" mode: output images are not saved but are compared with existing images
# - use False for "production" mode: output images are saved to disk and burned into FLASH
TEST_IMG_CONTENT = True
# flag to export also '_nopadding.bin' images; these can be used on write tab in SPT
NO_PADDING = True
# flag whether SRK fuses shall be verified before image write
VERIFY_SRK_FUSES = False
# flag whether the burned image shall be authenticated and HAB logs parsed
AUTHENTICATE = True

# ############################## CONSTANTS ##############################
# name of the data sub-directory with output images
OUTPUT_IMAGES_SUBDIR = "output"
# name of the data sub-directory with keys
KEYS_SUBDIR = "keys"
# name of the data sub-directory with certificates
CERT_SUBDIR = "crts"
# name of the data sub-directory with SRK hashes
SRK_SUBDIR = "srk"
# private key password (used to store or load key from disk)
PRIV_KEY_PASSWORD = "SWTestTeam"
# name of the sub-directory with debug logs for generation of the output
DEBUG_LOG_SUBDIR = "debug_logs"
# name of the sub-directory with processor specific files; it is also used as ID of the test processor
ID_RT1020 = "rt102x"
ID_RT1050 = "rt105x"
ID_RT1060 = "rt106x"

# configuration words for external FLASH "IS26KS" on RT1050 EVKB
IS26KS_FLASH_CFG_WORD0 = 0xC0233007
IS26KS_FLASH_CFG_WORD1 = 0
# configuration words for external FLASH "IS25WP" on RT1060 EVK
IS25WP_FLASH_CFG_WORD0 = 0xC0000007
IS25WP_FLASH_CFG_WORD1 = 0

# configuration word to create Flash Config Block (FCB) in Flash NOR
FCB_FLASH_NOR_CFG_WORD = 0xF000000F

# CSF version format used as an output
CSF_VERSION = 0x42
# version of the SB file
SB_FILE_VERSION = "1.2"

# directory to the test_rt10xx.py (this file) "./"
MAIN_FILE_DIR = os.path.dirname(__file__)
# directory to the cpu specific data for test
DATA_DIR = os.path.join(MAIN_FILE_DIR, "data")


class CpuParams:
    """Processor specific parameters of the test."""

    def __init__(
        self,
        data_dir: str,
        data_subdir: str,
        com_processor_name: str,
        board: str,
        ext_flash_cfg_word0: int,
        encryption_supported: bool = True,
        xip_signature_supported: bool = True,
        none_xip_signature_supported: bool = True,
    ):
        """Constructor.

        :param data_dir: base absolute path for test data
        :param data_subdir: name of processor specific data sub-directory
        :param com_processor_name: SPSDK-specific name of the target processor for communication API (MBOOT and SDP)
        :param board: name of the board (used to select name of the source and output image)
        :param ext_flash_cfg_word0: configuration word 0 for external FLASH
        :param encryption_supported: Flag that CPU supports encryption HAB
        :param xip_signature_supported: Flag that CPU supports XIP signed HAB
        :param none_xip_signature_supported: Flag that CPU supports None XIP signed HAB
        """
        # ID of the test configuration
        self.id = data_subdir
        # processor specific data dir
        self.data_dir = os.path.join(data_dir, data_subdir)
        # data dir for all rt10xx
        self.rt10xx_data_dir = os.path.join(data_dir, "rt10xx")
        # data dir for keys and certificates
        self.keys_data_dir = os.path.join(self.rt10xx_data_dir, KEYS_SUBDIR)
        self.cert_data_dir = os.path.join(self.rt10xx_data_dir, CERT_SUBDIR)
        self.srk_data_dir = os.path.join(self.rt10xx_data_dir, SRK_SUBDIR)
        # other parameters
        self.com_processor_name = com_processor_name
        self.board = board
        self.ext_flash_cfg_word0 = ext_flash_cfg_word0
        self.ext_flash_cfg_word1 = 0  # currently zero for all RT
        self.encryption_supported = encryption_supported
        self.xip_signature_supported = xip_signature_supported
        self.none_xip_signature_supported = none_xip_signature_supported

    def __str__(self) -> str:
        return self.id + " " + self.__class__.__name__

    @classmethod
    def rt1020(cls) -> "CpuParams":
        """Parameters for RT1020."""
        return CpuParams(
            DATA_DIR,
            ID_RT1020,
            "MXRT20",
            "evkmimxrt1020",
            IS25WP_FLASH_CFG_WORD0,
            encryption_supported=False,
            none_xip_signature_supported=False,
        )

    @classmethod
    def rt1050(cls) -> "CpuParams":
        """Parameters for RT1050."""
        return CpuParams(
            DATA_DIR,
            ID_RT1050,
            "MXRT50",
            "evkbimxrt1050",
            IS26KS_FLASH_CFG_WORD0,
        )

    @classmethod
    def rt1060(cls) -> "CpuParams":
        """Parameters for RT1060."""
        return CpuParams(
            DATA_DIR,
            ID_RT1060,
            "MXRT60",
            "evkmimxrt1060",
            IS25WP_FLASH_CFG_WORD0,
        )


# ############################## PROCESSOR/BOARD SPECIFIC INFO ########################################
# The following constants might be processor specific. Currently they are same for all supported RTxxxx
# ############################## ############################# ########################################
# address of internal RAM for data
INT_RAM_ADDR_DATA = 0x2000
# internal RAM for code start address
INT_RAM_ADDR_CODE = 0x20000000
# external FLASH start address
EXT_FLASH_ADDR = 0x60000000
# start address of SD card
SD_CARD_ADDR = 0x0
# external SDRAM start address
SDRAM_ADDR = 0x80000000
# List of SRK fuses indexes
SRK_FUSES_INDEX = [0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]
# Enable HAB fuse index
ENABLE_HAB_FUSE_INDEX = 0x6
# Enable HAB fuse mask (bits that must be set)
ENABLE_HAB_FUSE_MASK = 0x00000002


def pytest_generate_tests(metafunc):
    """Create test configurations for all tested processors"""
    cpus = [CpuParams.rt1020(), CpuParams.rt1050(), CpuParams.rt1060()]
    metafunc.parametrize(
        "cpu_params", cpus, indirect=False, ids=[cpu_params.id for cpu_params in cpus]
    )


def srk_table4(cpu_params: CpuParams) -> SrkTable:
    """Create SRK table with four root SRK keys

    :param cpu_params: processor specific parameters of the test
    :return: SrkTable instance
    """
    result = SrkTable()
    for cert_prefix in ["SRK1", "SRK2", "SRK3", "SRK4"]:
        certificate = Certificate.load(
            os.path.join(cpu_params.cert_data_dir, cert_prefix + "_sha256_2048_65537_v3_ca_crt.pem")
        )
        result.append(SrkItem.from_certificate(certificate))
    return result


def _to_authenticated_image(
    cpu_params: CpuParams,
    boot_img: BootImgRT,
    app_data: bytes,
    srk_key_index: int,
    entry_addr: int = -1,
    dek: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> None:
    """Configures given bootable image to authenticated image or encrypted image

    :param cpu_params: processor specific parameters of the test
    :param boot_img: bootable image to be updated (converted to signed or encrypted)
    :param app_data: data of the binary application
    :param srk_key_index: index of the SRK key used, 0-3
    :param entry_addr: start address of the application; -1 to detect the address from the image
    :param dek: key for encrypted image:
                - None if image is not encrypted
                - empty value for image encrypted with random key
                - full key for test purposes
    :param nonce: optional initialization vector for AES encryption; None to use random value (recommended)
    :return: BootImageRT with application  configured as signed or encrypted
    """
    assert 0 <= srk_key_index <= 3
    boot_img.add_image(app_data, address=entry_addr, dek_key=dek, nonce=nonce)
    # test method `decrypted_app_data`
    if dek:
        decr_app = boot_img.decrypted_app_data
        assert (len(decr_app) == align(len(app_data), MAC.AES128_BLK_LEN)) and (
            decr_app[: len(app_data)] == app_data
        )
    else:
        assert boot_img.decrypted_app_data == app_data
    csf_prefix = "CSF" + str(srk_key_index + 1) + "_1_sha256_2048_65537_v3_usr_"
    img_prefix = "IMG" + str(srk_key_index + 1) + "_1_sha256_2048_65537_v3_usr_"
    csf_priv_key = PrivateKeyRsa.load(
        os.path.join(cpu_params.keys_data_dir, csf_prefix + "key.pem"),
        password=PRIV_KEY_PASSWORD,
    )
    img_priv_key = PrivateKeyRsa.load(
        os.path.join(cpu_params.keys_data_dir, img_prefix + "key.pem"),
        password=PRIV_KEY_PASSWORD,
    )
    assert isinstance(csf_priv_key, PrivateKeyRsa)
    assert isinstance(img_priv_key, PrivateKeyRsa)
    if dek is None:
        boot_img.add_csf_standard_auth(
            CSF_VERSION,
            srk_table4(cpu_params),
            srk_key_index,
            load_binary(os.path.join(cpu_params.cert_data_dir, csf_prefix + "crt.pem")),
            csf_priv_key,
            load_binary(os.path.join(cpu_params.cert_data_dir, img_prefix + "crt.pem")),
            img_priv_key,
        )
    else:
        boot_img.add_csf_encrypted(
            CSF_VERSION,
            srk_table4(cpu_params),
            srk_key_index,
            load_binary(os.path.join(cpu_params.cert_data_dir, csf_prefix + "crt.pem")),
            csf_priv_key,
            load_binary(os.path.join(cpu_params.cert_data_dir, img_prefix + "crt.pem")),
            img_priv_key,
        )


def init_flashloader(cpu_params: CpuParams) -> McuBoot:
    """Load an execute flash-loader binary in i.MX-RT
    The function signs the flashloader if needed (if HAB enabled)

    :param cpu_params: processor specific parameters of the test
    :return: McuBoot instance to communicate with flash-loader
    :raises McuBootConnectionError: if connection cannot be established
    """
    devs = MbootUSBInterface.scan_usb(
        cpu_params.com_processor_name
    )  # check whether flashloader is already running
    if len(devs) == 0:
        # if flash-loader not running yet, it must be downloaded to RAM and launched
        flshldr_img = BootImgRT.parse(
            load_binary(os.path.join(cpu_params.data_dir, "ivt_flashloader.bin"))
        )

        devs = SdpUSBInterface.scan_usb(cpu_params.com_processor_name)
        if len(devs) != 1:
            raise McuBootConnectionError("Cannot connect to ROM bootloader")

        with SDP(devs[0], cmd_exception=True) as sd:
            assert sd.is_opened
            try:
                sd.read(INT_RAM_ADDR_CODE, 4)  # dummy read to receive response
            except (
                SdpCommandError
            ):  # there is an exception if HAB is locked, cause read not supported
                pass

            if (sd.status_code == StatusCode.HAB_IS_LOCKED) and (
                sd.hab_status == ResponseValue.LOCKED
            ):
                auth_flshldr_img = BootImgRT(flshldr_img.address, BootImgRT.IVT_OFFSET_OTHER)
                _to_authenticated_image(
                    cpu_params,
                    auth_flshldr_img,
                    flshldr_img.app.data,
                    0,
                    flshldr_img.ivt.app_address,
                )  # entry addr cannot be detected from img
            else:
                auth_flshldr_img = flshldr_img
            assert sd.write_file(auth_flshldr_img.address, auth_flshldr_img.export())
            try:
                assert sd.jump_and_run(auth_flshldr_img.address + auth_flshldr_img.ivt_offset)
            except SdpCommandError:
                pass  # SDP may return an exception if HAB locked

        for _ in range(10):  # wait 10 sec until flash-loader is inited
            sleep(1)
            # Scan for MCU-BOOT device
            devs = MbootUSBInterface.scan_usb(cpu_params.com_processor_name)
            if len(devs) == 1:
                break

    if len(devs) != 1:
        raise ConnectionError("Cannot connect to Flash-Loader")

    result = McuBoot(devs[0], cmd_exception=True)
    result.open()
    assert result.is_opened
    result.reopen = False  # reopen not supported for RT1050???
    return result


def verify_srk_fuses(mboot: McuBoot, srk_table: SrkTable) -> bool:
    """Verify fuses in the processor

    :param mboot: result of `init_flashloader()`
    :param srk_table: Table of SRK root keys used to provide fuses value
    :return: True if matches, False if does not match
    """
    assert mboot.get_property(PropertyTag.CURRENT_VERSION)
    for index, srk_index in enumerate(SRK_FUSES_INDEX):
        val = mboot.efuse_read_once(srk_index)
        exp_val = srk_table.get_fuse(index)
        if val != exp_val:
            return False
    return True


def burn_srk_fuses(mboot: McuBoot, srk_table: SrkTable, enable_and_close_hab: bool) -> None:
    """Program SRK fuses into the processor; Not tested on hardware

    :param mboot: result of `init_flashloader()`
    :param srk_table: Table of SRK root keys used to provide fuses value
    :param enable_and_close_hab: optional parameter to enable and close HAB
    """
    assert mboot.get_property(PropertyTag.CURRENT_VERSION)
    for index, srk_index in enumerate(SRK_FUSES_INDEX):
        mboot.efuse_program_once(srk_index, srk_table.get_fuse(index))

    if enable_and_close_hab:
        # enable and close HAB
        mboot.efuse_program_once(ENABLE_HAB_FUSE_INDEX, ENABLE_HAB_FUSE_MASK)


def _burn_image_to_sd(cpu_params: CpuParams, img: BootImgRT, img_data: bytes) -> None:
    """Burn image into SD card. This function is called only in production mode.

    :param cpu_params: processor specific parameters of the test
    :param img: RT10xx image instance
    :param img_data: exported image data
    """
    assert TEST_IMG_CONTENT is False

    # start FLASH loader
    mboot = init_flashloader(cpu_params)
    assert mboot.get_property(PropertyTag.CURRENT_VERSION)
    # verify SRK fuses are properly burned
    if VERIFY_SRK_FUSES:
        assert verify_srk_fuses(mboot, srk_table4(cpu_params))

    # ### Configure external FLASH on EVK: flexspi-nor using options on address 0x2000 ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- fill-memory 0x2000 4 0xD0000000 word
    assert mboot.fill_memory(INT_RAM_ADDR_DATA, 4, 0xD0000000)
    # call "%blhost%" -u 0x15A2,0x0073 -j -- fill-memory 0x2004 4 0x00000000 word
    assert mboot.fill_memory(INT_RAM_ADDR_DATA + 4, 4, 0x00000000)
    # call "%blhost%" -u 0x15A2,0x0073 -j -- configure-memory 288 0x2000
    assert mboot.configure_memory(INT_RAM_ADDR_DATA, ExtMemId.SD_CARD.tag)

    img_data = align_block(img_data, 0x1000)

    # ### Erase memory before writing image ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- flash-erase-region 0x400 16384 288
    assert mboot.flash_erase_region(
        SD_CARD_ADDR + img.ivt_offset, len(img_data), ExtMemId.SD_CARD.tag
    )

    # @echo ### Write image ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- write-memory 0x00000400 image.bin 288
    assert mboot.write_memory(SD_CARD_ADDR + img.ivt_offset, img_data, ExtMemId.SD_CARD.tag)

    # for HAB encrypted image write KEY BLOB
    if img.dek_key:
        # call "blhost" -u 0x15A2,0x0073 -j -- generate-key-blob {BOARD}_iled_blinky_int_ram_hab_dek.bin blob.bin
        blob = mboot.generate_key_blob(img.dek_key)
        tgt_address = EXT_FLASH_ADDR + img.dek_img_offset
        # call "blhost" -u 0x15A2,0x0073 -j -- write-memory 0x60008000 blob.bin 9
        assert mboot.write_memory(tgt_address, blob, ExtMemId.FLEX_SPI_NOR.tag)

    mboot.close()


def _init_otpmk_bee_regions(mboot: McuBoot, bee_regions: Sequence[BeeFacRegion]) -> None:
    """Initialize PRDB regions for BEE encryption using master key.

    :param mboot: instance allowing communicate with processor/flashloader
    :param bee_regions: FAC regions to be created and encrypted
    """
    # 0xE0120000 is an option for PRDB construction and image encryption
    # bit[31:28] tag, fixed to 0x0E
    # bit[27:24] Key source, fixed to 0 (not known any RT device with supported non zero value)
    # bit[23:20] AES mode: 1 = CTR mode, 0 = ECB mode (fixed to 1)
    # bit[19:16] Encrypted region count
    # bit[15:00] reserved
    assert mboot.fill_memory(INT_RAM_ADDR_DATA, 4, (0xE010 + len(bee_regions)) << 16)
    offset = 4
    for fac in bee_regions:
        # init FAC region start and length
        assert mboot.fill_memory(INT_RAM_ADDR_DATA + offset, 4, fac.start_addr)
        offset += 4
        assert mboot.fill_memory(INT_RAM_ADDR_DATA + offset, 4, fac.length)
        offset += 4
    # apply the configuration
    assert mboot.configure_memory(INT_RAM_ADDR_DATA, ExtMemId.FLEX_SPI_NOR.tag)


def _burn_image_to_flash(
    cpu_params: CpuParams,
    img: BootImgRT,
    img_data: bytes,
    otpmk_bee_regions: tuple[BeeFacRegion, ...] = tuple(),
) -> None:
    """Burn image into external FLASH. This function is called only in production mode.

    :param cpu_params: processor specific parameters of the test
    :param img: RT10xx image instance
    :param img_data: exported image data
    :param otpmk_bee_regions: optional list of BEE regions for BEE OTPMK encryption
    """
    assert TEST_IMG_CONTENT is False

    # start FLASH loader
    mboot = init_flashloader(cpu_params)
    assert mboot.get_property(PropertyTag.CURRENT_VERSION)
    # verify SRK fuses are properly burned
    if VERIFY_SRK_FUSES:
        assert verify_srk_fuses(mboot, srk_table4(cpu_params))

    # ### Configure external FLASH on EVK: flexspi-nor using options on address 0x2000 ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- fill-memory 0x2000 4 0xC0233007 word
    assert mboot.fill_memory(INT_RAM_ADDR_DATA, 4, cpu_params.ext_flash_cfg_word0)
    # call "%blhost%" -u 0x15A2,0x0073 -j -- fill-memory 0x2004 4 0x00000000 word
    assert mboot.fill_memory(INT_RAM_ADDR_DATA + 4, 4, cpu_params.ext_flash_cfg_word1)
    # call "%blhost%" -u 0x15A2,0x0073 -j -- configure-memory 9 0x2000
    assert mboot.configure_memory(INT_RAM_ADDR_DATA, ExtMemId.FLEX_SPI_NOR.tag)

    if not img.fcb.enabled:
        write_addr_ofs = img.ivt_offset
        imgdata_offset = 0
    elif isinstance(img.fcb, PaddingFCB):
        write_addr_ofs = img.BEE_OFFSET if img.bee_encrypted else img.ivt_offset
        imgdata_offset = img.BEE_OFFSET if img.bee_encrypted else img.ivt_offset
    elif isinstance(img.fcb, FlexSPIConfBlockFCB):
        write_addr_ofs = 0
        imgdata_offset = 0
    else:
        assert False

    # ### Erase memory before writing image ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- flash-erase-region 0x60000000 21000 9
    size = align(len(img_data) + write_addr_ofs, 0x1000)
    assert mboot.flash_erase_region(EXT_FLASH_ADDR, size, ExtMemId.FLEX_SPI_NOR.tag)

    if not img.fcb.enabled or isinstance(img.fcb, PaddingFCB):  # FCB not part of the image
        # ### Use tag 0xF000000F to notify Flashloader to program FlexSPI NOR config block to the start of device###
        # call "%blhost%" -u 0x15A2,0x0073 -j -- fill-memory 0x3000 4 0xF000000F word
        assert mboot.fill_memory(INT_RAM_ADDR_DATA, 4, FCB_FLASH_NOR_CFG_WORD)
        # ### Program configuration block ###
        # call "%blhost%" -u 0x15A2,0x0073 -j -- configure-memory 9 0x3000
        assert mboot.configure_memory(INT_RAM_ADDR_DATA, ExtMemId.FLEX_SPI_NOR.tag)
        # read flex_spi.fcb
        mem = mboot.read_memory(EXT_FLASH_ADDR, 512, ExtMemId.FLEX_SPI_NOR.tag)
        with open(os.path.join(cpu_params.data_dir, "flex_spi.fcb"), "wb") as f:
            f.write(mem)

        if otpmk_bee_regions:
            assert img.address == EXT_FLASH_ADDR  # is applicable for XIP images only
            _init_otpmk_bee_regions(mboot, otpmk_bee_regions)

    else:
        assert len(otpmk_bee_regions) == 0

    # @echo ### Write image ###
    # call "%blhost%" -u 0x15A2,0x0073 -j -- write-memory 0x60001000 image.bin 9
    mboot.write_memory(EXT_FLASH_ADDR + write_addr_ofs, img_data[imgdata_offset:])

    # for HAB encrypted image write KEY BLOB
    if img.dek_key:
        # call "blhost" -u 0x15A2,0x0073 -j -- generate-key-blob hab_dek.bin blob.bin
        blob = mboot.generate_key_blob(img.dek_key)
        tgt_address = EXT_FLASH_ADDR + img.dek_img_offset
        # call "blhost" -u 0x15A2,0x0073 -j -- write-memory 0x60008000 blob.bin 9
        assert mboot.write_memory(tgt_address, blob, ExtMemId.FLEX_SPI_NOR.tag)

    if AUTHENTICATE and (img.address == EXT_FLASH_ADDR) and not otpmk_bee_regions:
        mboot.close()
        test_hab_audit(cpu_params)

    else:
        # detect XIP image
        app_data = img.decrypted_app_data
        initial_pc = int.from_bytes(app_data[4:8], byteorder=Endianness.LITTLE.value)
        if img.address == EXT_FLASH_ADDR:  # if XIP
            # run XIP image immediately
            stack_ptr = int.from_bytes(app_data[:4], byteorder=Endianness.LITTLE.value)
            assert mboot.execute(initial_pc, EXT_FLASH_ADDR + img.ivt_offset, stack_ptr)

        mboot.close()


def write_image(
    cpu_params: CpuParams,
    image_file_name: str,
    img: BootImgRT,
    otpmk_bee_regions: tuple[BeeFacRegion, ...] = tuple(),
) -> None:
    """Write image to the external flash
    The method behavior depends on TEST_IMG_CONTENT:
    - if True (TEST MODE), the method generates the image and compare with previous version
    - if False (PRODUCTION), the method generates the image and burn into FLASH

    :param cpu_params: processor specific parameters of the test
    :param image_file_name: of the image to be written (including file extension)
    :param img: image instance to be written
    :param otpmk_bee_regions: optional list of BEE regions for BEE OTPMK encryption
    """
    path = os.path.join(cpu_params.data_dir, OUTPUT_IMAGES_SUBDIR, image_file_name)
    # use zulu datetime for test purposes only, to produce stable output; remove the parameter for production
    zulu = datetime(year=2020, month=4, day=8, hour=5, minute=54, second=33, tzinfo=timezone.utc)
    img_data = img.export(zulu=zulu)
    assert len(img_data) == img.size
    if TEST_IMG_CONTENT:
        assert str(img)  # quick check info prints non-empty output
        compare_bin_files(path, img_data)
        # compare no-padding
        if (
            NO_PADDING
            and img.fcb.enabled
            and isinstance(img.fcb, PaddingFCB)
            and not img.bee_encrypted
        ):
            img.fcb.enabled = False
            compare_bin_files(path.replace(".bin", "_nopadding.bin"), img.export(zulu=zulu))
            img.fcb.enabled = False
        # test that parse image will return same content
        if img.fcb.enabled and not img.bee_encrypted:
            compare_bin_files(path, BootImgRT.parse(img_data).export())
            # test that size matches len of exported data
            assert img.size == len(img_data)
    else:
        with open(path, "wb") as f:
            f.write(img_data)
        if (
            NO_PADDING
            and img.fcb.enabled
            and isinstance(img.fcb, PaddingFCB)
            and not img.bee_encrypted
        ):
            with open(path.replace(".bin", "_nopadding.bin"), "wb") as f:
                f.write(img_data[img.ivt_offset :])

        if img.ivt_offset == BootImgRT.IVT_OFFSET_NOR_FLASH:
            _burn_image_to_flash(cpu_params, img, img_data, otpmk_bee_regions)
        else:
            assert len(otpmk_bee_regions) == 0
            _burn_image_to_sd(cpu_params, img, img_data)


def write_sb(cpu_params: CpuParams, image_file_name: str, img: SecureBootV1) -> None:
    """Write SB image to the external flash
    The method behavior depends on TEST_IMG_CONTENT:
    - if True (TEST MODE), the method generates the image and compare with previous version
    - if False (PRODUCTION), the method generates the image and burn into FLASH

    :param cpu_params: processor specific parameters of the test
    :param image_file_name: of the image to be written (including file extension)
    :param img: image instance to be written
    """
    path = os.path.join(cpu_params.data_dir, OUTPUT_IMAGES_SUBDIR, image_file_name)
    img_data = img.export(
        # use the following parameters only for unit test
        header_padding8=b"\xdb\x00\x76\x7a\xf4\x81\x0b\x86",
        auth_padding=b"\x36\x72\xf4\x99\x92\x05\x34\xd2\xd5\x17\xa0\xf7",
    )
    if TEST_IMG_CONTENT:
        assert str(img)  # quick check info prints non-empty output
        compare_bin_files(path, img_data)
        img = SecureBootV1.parse((b"0" + img_data)[1:])
        img_data2 = img.export(
            header_padding8=b"\xdb\x00\x76\x7a\xf4\x81\x0b\x86",
            auth_padding=b"\x36\x72\xf4\x99\x92\x05\x34\xd2\xd5\x17\xa0\xf7",
        )
        assert img_data == img_data2
    else:
        with open(path, "wb") as f:
            f.write(img_data)

        mboot = init_flashloader(cpu_params)
        assert mboot.receive_sb_file(img_data)
        mboot.close()


def test_configuration(cpu_params: CpuParams) -> None:
    """Verify the test is configured properly for `unit test` mode.

    :param cpu_params: the parameter is useless, but it must be used for all tests
    """
    assert TEST_IMG_CONTENT


# ####################################################################################
# ######################### example: UNSIGNED BOOTABLE IMAGE #########################
# ####################################################################################
@pytest.mark.parametrize(
    "image_name, tgt_address, dcd",
    [
        # XIP external FLASH
        ("iled_blinky_ext_FLASH", EXT_FLASH_ADDR, None),
        # FLASH -> internal RAM
        ("iled_blinky_int_RAM", INT_RAM_ADDR_CODE, None),
        # FLASH -> SDRAM
        ("iled_blinky_SDRAM", SDRAM_ADDR, "dcd_SDRAM.bin"),
    ],
)
def test_unsigned(
    cpu_params: CpuParams, image_name: str, tgt_address: int, dcd: Optional[str]
) -> None:
    """Test creation of unsigned image

    :param cpu_params: processor specific parameters of the test
    :param image_name: filename of the source image; without file extension; without {board} prefix
    :param tgt_address: address, where the image will be located in the memory (start address of the memory)
    :param dcd: file name of the DCD file to be included in the image; None if no DCD needed
    """
    image_name = cpu_params.board + "_" + image_name
    # create bootable image object
    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    boot_img = BootImgRT(tgt_address)
    boot_img.add_image(app_data)
    if dcd:
        boot_img.add_dcd_bin(load_binary(os.path.join(cpu_params.data_dir, dcd)))

    # write image to disk and to processor
    write_image(cpu_params, image_name + "_unsigned.bin", boot_img)


@pytest.mark.parametrize("fcb", [True, False])
def test_nor_flash_fcb(cpu_params: CpuParams, fcb: bool) -> None:
    """Test unsigned image with FCB NOR FLASH block

    :param cpu_params: processor specific parameters of the test
    :param fcb: True to include FCB block to output image; False to exclude
    """
    if (cpu_params.id != ID_RT1050) and (cpu_params.id != ID_RT1060):
        return  # this test case is supported only for RT1050 and RT1060

    image_name = f"{cpu_params.board}_iled_blinky_ext_FLASH"
    # create bootable image object
    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    boot_img = BootImgRT(EXT_FLASH_ADDR)
    boot_img.add_image(app_data)
    if fcb:
        boot_img.set_flexspi_fcb(load_binary(os.path.join(cpu_params.data_dir, "flex_spi.fcb")))
    else:
        boot_img.fcb = PaddingFCB(0, enabled=False)

    # write image to disk and to processor
    suffix = "_unsigned_fcb.bin" if fcb else "_unsigned_nofcb.bin"
    write_image(cpu_params, image_name + suffix, boot_img)


def test_srk_table(cpu_params: CpuParams) -> None:
    """Test creation of SRK table and SRK fuses"""
    srk_table = srk_table4(cpu_params)
    srk_table_path = os.path.join(cpu_params.srk_data_dir, "SRK_hash_table.bin")
    srk_fuses_path = os.path.join(cpu_params.srk_data_dir, "SRK_fuses.bin")

    # test valid fuse value
    assert srk_table.get_fuse(0) == 0x3B86E63F
    assert srk_table.get_fuse(7) == 0xC542AB47
    #
    if TEST_IMG_CONTENT:
        compare_bin_files(srk_table_path, srk_table.export())
        compare_bin_files(srk_fuses_path, srk_table.export_fuses())
    else:
        with open(srk_table_path, "wb") as f:
            f.write(srk_table.export())
        with open(srk_fuses_path, "wb") as f:
            f.write(srk_table.export_fuses())


# ####################################################################################
# ########################## example: SIGNED BOOTABLE IMAGE ##########################
# ####################################################################################
@pytest.mark.parametrize("srk_key_index", [0, 3])
def test_signed(cpu_params: CpuParams, srk_key_index: int) -> None:
    """Test creation of signed image

    :param cpu_params: processor specific parameters of the test
    :param srk_key_index: index of the SRK key used
    """
    if not cpu_params.xip_signature_supported:
        pytest.skip("Unsupported configuration")

    image_name = f"{cpu_params.board}_iled_blinky_ext_FLASH"
    tgt_address = EXT_FLASH_ADDR

    boot_img = BootImgRT(tgt_address)
    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    _to_authenticated_image(cpu_params, boot_img, app_data, srk_key_index)
    write_image(cpu_params, image_name + f"_signed_key{str(srk_key_index + 1)}.bin", boot_img)


def test_signed_flashloader(cpu_params: CpuParams) -> None:
    """Test creation of signed FLASHLOADER image

    :param cpu_params: processor specific parameters of the test
    """
    assert TEST_IMG_CONTENT  # this should be used in test mode only to verify the flashloader image creation process

    if not cpu_params.none_xip_signature_supported:
        pytest.skip("Unsupported configuration")

    image_name = "ivt_flashloader"
    tgt_address = INT_RAM_ADDR_CODE

    flashloader_unsigned_img = BootImgRT.parse(
        load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    )
    app_data = flashloader_unsigned_img.app.data
    assert app_data
    boot_img = BootImgRT(tgt_address, BootImgRT.IVT_OFFSET_OTHER)
    _to_authenticated_image(
        cpu_params, boot_img, app_data, 0, flashloader_unsigned_img.ivt.app_address
    )
    write_image(cpu_params, image_name + "_signed.bin", boot_img)


def x509_common_name(common_name: str) -> x509.Name:
    """Builds x509.Name with common-name (CN) attribute; Used for generation of additional certificates

    :param common_name: value
    :return: x509.Name instance
    """
    return x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
        ]
    )


@pytest.mark.parametrize(
    "srk_key_index,cert_name_prefix,cert_index",
    [
        (1, "CSF", 3),
        (1, "IMG", 3),
    ],
)
def test_generate_csf_img(
    cpu_params: CpuParams,
    srk_key_index: int,
    cert_name_prefix: str,
    cert_index: int,
    key_size: int = 2048,
) -> None:
    """Generate additional CSF or IMG certificate for selected SRK key

    :param cpu_params: processor specific parameters of the test
    :param srk_key_index: index of SRK, for which new certificate is going to be generated
    :param cert_name_prefix: prefix/type of the generated certificate: either 'CSF' or 'IMG'
    :param cert_index: index of the generated certificate
    :param key_size: size of the generated key in bits, 2048 by default
    """
    # validate arguments
    assert 1 <= srk_key_index <= 4
    assert cert_name_prefix == "CSF" or cert_name_prefix == "IMG"
    assert 1 <= cert_index
    # build names
    base_key_name = f"_sha256_{str(key_size)}_65537_v3_"  # middle path of the output filename
    srk_name = f"SRK{srk_key_index}" + base_key_name + "ca"
    out_name = cert_name_prefix + str(srk_key_index) + "_" + str(cert_index) + base_key_name + "usr"
    out_key_path = os.path.join(cpu_params.keys_data_dir, out_name + "_key")
    # generate private key
    gen_priv_key = PrivateKeyRsa.generate_key(key_size=key_size)
    gen_priv_key.save(out_key_path + ".pem", password=PRIV_KEY_PASSWORD, encoding=SPSDKEncoding.PEM)
    gen_priv_key.save(out_key_path + ".der", password=PRIV_KEY_PASSWORD, encoding=SPSDKEncoding.DER)
    # generate public key
    gen_pub_key = gen_priv_key.get_public_key()
    # load private key of the issuer (SRK)
    srk_priv_key = PrivateKeyRsa.load(
        os.path.join(cpu_params.keys_data_dir, srk_name + "_key.pem"),
        password=PRIV_KEY_PASSWORD,
    )
    # generate certificate
    gen_cert = Certificate.generate_certificate(
        x509_common_name(out_name),
        x509_common_name(srk_name),
        gen_pub_key,
        srk_priv_key,
        serial_number=0x199999A7,
        duration=3560,
    )
    gen_cert.save(os.path.join(cpu_params.cert_data_dir, out_name + "_crt.pem"), SPSDKEncoding.PEM)
    gen_cert.save(os.path.join(cpu_params.cert_data_dir, out_name + "_crt.der"), SPSDKEncoding.DER)


# ####################################################################################
# ########################## example: ENCRYPTED BOOTABLE IMAGE #######################
# ####################################################################################
def test_hab_encrypted(cpu_params: CpuParams) -> None:
    """Test HAB encrypted image.
    :param cpu_params: processor specific parameters of the test
    """
    if not cpu_params.encryption_supported:
        pytest.skip("Unsupported configuration")

    image_name = f"{cpu_params.board}_iled_blinky_int_RAM"
    tgt_address = INT_RAM_ADDR_CODE
    srk_key_index = 0

    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    # Encryption params (nonce + dek): use only for test purpose, for production use None
    nonce = bytes.fromhex("24eb311ce02a61d74cad460739")
    dek = load_binary(os.path.join(cpu_params.rt10xx_data_dir, "hab_dek.bin"))
    #
    boot_img = BootImgRT(tgt_address)
    _to_authenticated_image(cpu_params, boot_img, app_data, srk_key_index, -1, dek, nonce)
    assert boot_img.dek_ram_address == boot_img.ivt.csf_address + 0x2000
    assert boot_img.dek_img_offset == (boot_img.ivt.csf_address - INT_RAM_ADDR_CODE) + 0x2000
    write_image(cpu_params, image_name + f"_encrypted_key{str(srk_key_index + 1)}.bin", boot_img)


@pytest.mark.parametrize(
    "image_name, tgt_address, dcd, plain0_signed1_encr2",
    [
        # SD-card -> internal RAM; unsigned
        ("iled_blinky_int_RAM", INT_RAM_ADDR_CODE + 0x1000, None, 0),
        # SD-card -> internal RAM; signed
        ("iled_blinky_int_RAM", INT_RAM_ADDR_CODE + 0x1000, None, 1),
        # SD-card -> SDRAM; unsigned
        ("iled_blinky_SDRAM", SDRAM_ADDR + 0x1000, "dcd_SDRAM.bin", 0),
        # SD-card -> SDRAM; signed
        ("iled_blinky_SDRAM", SDRAM_ADDR + 0x1000, "dcd_SDRAM.bin", 1),
        # SD-card -> SDRAM; encrypted
        ("iled_blinky_SDRAM", SDRAM_ADDR + 0x1000, "dcd_SDRAM.bin", 2),
    ],
)
def test_sdhc(
    cpu_params: CpuParams,
    image_name: str,
    tgt_address: int,
    dcd: Optional[str],
    plain0_signed1_encr2: int,
) -> None:
    """Test creation of unsigned image

    :param cpu_params: processor specific parameters of the test
    :param image_name: filename of the source image; without file extension; without board prefix
    :param tgt_address: address, where the image will be located in the memory (start address of the memory)
    :param dcd: file name of the DCD file to be included in the image; None if no DCD needed
    :param plain0_signed1_encr2: 0 for unsigned; 1 for signed; 2 for encrypted
    """
    image_name = cpu_params.board + "_" + image_name
    # create bootable image object
    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    boot_img = BootImgRT(tgt_address, BootImgRT.IVT_OFFSET_OTHER)
    boot_img.fcb = PaddingFCB(0, enabled=False)
    if dcd:
        boot_img.add_dcd_bin(load_binary(os.path.join(cpu_params.data_dir, dcd)))

    if plain0_signed1_encr2 == 0:
        boot_img.add_image(app_data)
        suffix = "_sdhc_unsigned.bin"
    elif plain0_signed1_encr2 == 1:
        _to_authenticated_image(cpu_params, boot_img, app_data, 0)
        suffix = "_sdhc_signed.bin"
    elif plain0_signed1_encr2 == 2:
        _to_authenticated_image(cpu_params, boot_img, app_data, 0)
        suffix = "_sdhc_encrypted.bin"
    else:
        assert False

    # write image to disk and to processor
    write_image(cpu_params, image_name + suffix, boot_img)


# ####################################################################################
# ########################## example: SECURE BOOT IMAGE ##############################
# ####################################################################################
def test_sb(cpu_params: CpuParams) -> None:
    """Test creation of SB file.

    :param cpu_params: processor specific parameters of the test
    """
    # timestamp is fixed for the test, do not not for production
    timestamp = datetime(
        year=2020, month=4, day=24, hour=15, minute=33, second=32, tzinfo=timezone.utc
    )

    # load application to add into SB
    img_name = f"{cpu_params.board}_iled_blinky_ext_FLASH_unsigned_nopadding"
    app_data = load_binary(
        os.path.join(cpu_params.data_dir, OUTPUT_IMAGES_SUBDIR, img_name + ".bin")
    )
    boot_img = BootImgRT.parse(app_data)  # parse to retrieve IVT offset

    sb = SecureBootV1(version=SB_FILE_VERSION, timestamp=timestamp)
    sect = BootSectionV1(0, SecureBootFlagsV1.ROM_SECTION_BOOTABLE)
    # load 0xc0233007 > 0x2000;
    sect.append(
        CmdFill(
            INT_RAM_ADDR_DATA,
            int.from_bytes(pack("<I", cpu_params.ext_flash_cfg_word0), Endianness.LITTLE.value),
        )
    )
    # enable flexspinor 0x2000;
    sect.append(CmdMemEnable(INT_RAM_ADDR_DATA, 4, ExtMemId.FLEX_SPI_NOR.tag))
    # erase 0x60000000..0x60100000;
    sect.append(CmdErase(EXT_FLASH_ADDR, align(boot_img.ivt_offset + boot_img.size, 0x1000)))
    # load 0xf000000f > 0x3000;
    sect.append(
        CmdFill(
            INT_RAM_ADDR_DATA,
            int.from_bytes(pack("<I", FCB_FLASH_NOR_CFG_WORD), Endianness.LITTLE.value),
        )
    )
    # enable flexspinor 0x3000;
    sect.append(CmdMemEnable(INT_RAM_ADDR_DATA, 4, ExtMemId.FLEX_SPI_NOR.tag))
    # load myBinFile > kAbsAddr_Ivt;
    app_data = align_block(
        app_data, 0x10
    )  # this is padding fixed for the test, not needed for production
    sect.append(CmdLoad(EXT_FLASH_ADDR + boot_img.ivt_offset, app_data))
    #
    sb.append(sect)
    #
    write_sb(cpu_params, img_name + ".sb", sb)


def test_sb_multiple_sections(cpu_params: CpuParams) -> None:
    """Test creation of SB file with multiple sections.

    :param cpu_params: processor specific parameters of the test
    """
    if (cpu_params.id != ID_RT1050) and (cpu_params.id != ID_RT1060):
        return  # this test case is supported only for RT1050 and RT1060

    # timestamp is fixed for the test, do not not for production
    timestamp = datetime(
        year=2020, month=4, day=24, hour=15, minute=33, second=32, tzinfo=timezone.utc
    )

    # load application to add into SB
    img_name = f"{cpu_params.board}_iled_blinky_ext_FLASH_unsigned_nofcb"
    app_data = load_binary(
        os.path.join(cpu_params.data_dir, OUTPUT_IMAGES_SUBDIR, img_name + ".bin")
    )
    boot_img = BootImgRT.parse(app_data)  # parse to retrieve IVT offset

    sb = SecureBootV1(version=SB_FILE_VERSION, timestamp=timestamp)
    sect = BootSectionV1(0, SecureBootFlagsV1.ROM_SECTION_BOOTABLE)
    # load 0xc0233007 > 0x2000;
    sect.append(
        CmdFill(
            INT_RAM_ADDR_DATA,
            int.from_bytes(pack("<I", cpu_params.ext_flash_cfg_word0), Endianness.LITTLE.value),
        )
    )
    # enable flexspinor 0x2000;
    sect.append(CmdMemEnable(INT_RAM_ADDR_DATA, 4, ExtMemId.FLEX_SPI_NOR.tag))
    # erase 0x60000000..0x60010000;
    # Note: erasing of long flash region may fail on timeout
    # For example this fails on EVK-RT1060: sect.append(CmdErase(EXT_FLASH_ADDR, 0x100000))
    sect.append(CmdErase(EXT_FLASH_ADDR, 0x10000))
    # load 0xf000000f > 0x3000;
    sect.append(
        CmdFill(
            INT_RAM_ADDR_DATA,
            int.from_bytes(pack("<I", FCB_FLASH_NOR_CFG_WORD), Endianness.LITTLE.value),
        )
    )
    # enable flexspinor 0x3000;
    sect.append(CmdMemEnable(INT_RAM_ADDR_DATA, 4, ExtMemId.FLEX_SPI_NOR.tag))
    # load myBinFile > kAbsAddr_Ivt;
    app_data += b"\xdc\xe8\x6d\x5d\xe9\x8c\xf5\x7c"  # this is random padding fixed for the test, not use for production
    sect.append(CmdLoad(EXT_FLASH_ADDR + boot_img.ivt_offset, app_data))
    #
    sb.append(sect)
    # add second section, just for the test
    sect2 = BootSectionV1(1, SecureBootFlagsV1.ROM_SECTION_BOOTABLE)
    sect2.append(
        CmdLoad(
            0x6000F000, load_binary(os.path.join(cpu_params.srk_data_dir, "SRK_hash_table.bin"))
        )
    )
    sb.append(sect2)
    #
    write_sb(cpu_params, "sb_file_2_sections" + ".sb", sb)


# ####################################################################################
# ########################### example: BEE OTMPK signed ##############################
# ####################################################################################
def test_bee_otmpk(cpu_params: CpuParams) -> None:
    """Test creation of signed image BEE encrypted using master key.
    It is supposed the SRK fuses are burned and HAB is enabled.
    It is supposed the SRK_KEY_SEL fuse is burned.

    :param cpu_params: processor specific parameters of the test
    """
    image_name = f"{cpu_params.board}_iled_blinky_ext_FLASH"
    tgt_address = EXT_FLASH_ADDR

    boot_img = BootImgRT(tgt_address)
    boot_img.fcb.enabled = False
    app_data = load_binary(os.path.join(cpu_params.data_dir, image_name + ".bin"))
    _to_authenticated_image(cpu_params, boot_img, app_data, 0)  # use signed image
    write_image(
        cpu_params,
        image_name + "_bee_otmpk.bin",
        boot_img,
        (BeeFacRegion(EXT_FLASH_ADDR + 0x1000, 0x2000),),
    )


# ####################################################################################
# ######################## example: BEE SW_GPx unsigned ##############################
# ####################################################################################
# TODO: fix test
@pytest.mark.skip(reason="Take a look into this")
def test_bee_unsigned_sw_key(cpu_params: CpuParams) -> None:
    """Test encrypted XIP unsigned image with user keys.
    It is supposed the SRK_KEY_SEL fuse is burned.
    It is supposed the user key is burned in SW_GP2 fuses.

    :param cpu_params: processor specific parameters of the test
    """
    img = BootImgRT(EXT_FLASH_ADDR)
    img.add_image(
        load_binary(
            os.path.join(cpu_params.data_dir, f"{cpu_params.board}_iled_blinky_ext_FLASH.bin")
        )
    )
    # the following parameters are fixed for the test only, to produce stable result; for production use random number
    cntr1 = bytes.fromhex("112233445566778899AABBCC00000000")
    kib_key1 = bytes.fromhex("C1C2C3C4C5C6C7C8C9CACBCCCDCECFC0")
    kib_iv1 = bytes.fromhex("1112131415161718191A1B1C1D1E1F10")
    cntr2 = bytes.fromhex("2233445566778899AABBCCDD00000000")
    kib_key2 = bytes.fromhex("C1C2C3C4C5C6C7C8C9CACBCCCDCECFC2")
    kib_iv2 = bytes.fromhex("2122232425262728292A2B2C2D2E2F20")
    # Add two regions as an example (even this is probably not real use case)
    # BEE region 0
    sw_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    region = BeeRegionHeader(
        BeeProtectRegionBlock(counter=cntr1), sw_key, BeeKIB(kib_key1, kib_iv1)
    )
    region.add_fac(BeeFacRegion(EXT_FLASH_ADDR + 0x1000, 0x2000))
    region.add_fac(BeeFacRegion(EXT_FLASH_ADDR + 0x3800, 0x800))
    img.bee.add_region(region)
    # BEE region 1 (this is just example, the is no code in the region)
    sw_key = bytes.fromhex("F123456789abcdeffedcba987654321F")
    region = BeeRegionHeader(
        BeeProtectRegionBlock(counter=cntr2), sw_key, BeeKIB(kib_key2, kib_iv2)
    )
    region.add_fac(BeeFacRegion(EXT_FLASH_ADDR + 0x100000, 0x1000))
    img.bee.add_region(region)
    #
    out_name = cpu_params.board + "_iled_blinky_ext_FLASH_bee_userkey_unsigned.bin"
    write_image(cpu_params, out_name, img)
