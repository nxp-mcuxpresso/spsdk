#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for the mimxrtl3450 (i.MXRTL345x) device support.

The expected values describe the boot ROM behavior of the device: the OTP fuse
map, the SB4.0 command set, the xSPI NOR boot layout and the supported ISP
interfaces.
"""

import os

import pytest

from spsdk.apps import nxpimage
from spsdk.fuses.fuse_registers import FuseRegisters
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.sbfile.sb4.images import SecureBinary4
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_device
from spsdk.utils.misc import Endianness
from tests.cli_runner import CliRunner

FAMILY = FamilyRevision("mimxrtl3450")


@pytest.fixture(name="fuses")
def fuses_fixture() -> FuseRegisters:
    """Load the fuse registers of the device."""
    return FuseRegisters(family=FAMILY, base_endianness=Endianness.LITTLE)


def test_device_is_registered() -> None:
    """The device is present in the database with a single a0 revision."""
    device = get_device(FAMILY)
    assert device.name == "mimxrtl3450"
    assert [revision.name for revision in device.revisions] == ["a0"]


def test_supported_features() -> None:
    """Only features implemented by the RTL3450 ROM are enabled."""
    db = get_db(FAMILY)
    assert set(db.features) == {
        "ahab",
        "blhost",
        "bootable_image",
        "cert_block",
        "comm_buffer",
        "dat",
        "debug_probe",
        "devhsm",
        "fcb",
        "fuses",
        "mbi",
        "sb40",
        "tz",
        "xmcd",
    }


def test_isp_interfaces() -> None:
    """Boot ROM offers ISP over UART, SPI and I2C, USB HID is not available."""
    isp_rom = get_device(FAMILY).info.isp.rom
    assert isp_rom.protocol == "mboot"
    assert set(isp_rom.interfaces) == {"uart", "spi", "i2c"}
    assert "usb" not in isp_rom.interfaces


def test_comm_buffer_outside_rom_ram() -> None:
    """Boot ROM occupies DTCM 0x2000_0000 - 0x2001_7FFF, the buffer must be behind it."""
    db = get_db(FAMILY)
    address = db.get_int(DatabaseManager.COMM_BUFFER, "address")
    assert address >= 0x2001_8000
    assert address + db.get_int(DatabaseManager.COMM_BUFFER, "size") <= 0x2004_0000


def test_fuse_map_size(fuses: FuseRegisters) -> None:
    """OCOTP 8K holds 204 defined fuse words (indices 0 - 203)."""
    indexes = [
        reg.otp_index
        for reg in fuses.get_registers(include_group_regs=True)
        if reg.otp_index is not None
    ]
    assert min(indexes) == 0
    assert max(indexes) == 203
    assert len(set(indexes)) == 204


@pytest.mark.parametrize(
    "name,index",
    [
        ("LOCK_CFG0", 0),
        ("ECID0", 31),
        ("BOOT_CFG0", 36),
        ("BOOT_CFG20", 56),
        ("LIFE_CYCLE0", 64),
        ("SEC_FW_VER0", 86),
        ("CUST_MK_SK0", 99),
        ("CUST_RKTH0", 111),
        ("CUST_PQC_RKTH0", 123),
        ("DUK_SHARE7", 136),
        ("MTR_REPAIR11", 203),
    ],
)
def test_fuse_indexes(fuses: FuseRegisters, name: str, index: int) -> None:
    """Selected fuse words are placed on the indexes defined by the device fuse map."""
    assert fuses.find_reg(name, include_group_regs=True).otp_index == index


@pytest.mark.parametrize(
    "uid,name,first,last",
    [
        ("cust_mk_sk", "CUST_MK_SK", 99, 110),
        ("rkth", "RKTH", 111, 122),
        ("pqc_rkth", "PQC_RKTH", 123, 134),
    ],
)
def test_grouped_key_registers(
    fuses: FuseRegisters, uid: str, name: str, first: int, last: int
) -> None:
    """Key related fuses are grouped into 384 bit registers."""
    reg = fuses.get_reg(uid)
    assert reg.name == name
    assert reg.width == 384
    assert [sub.otp_index for sub in reg.sub_regs] == list(range(first, last + 1))


def test_boot_cfg0_bitfields(fuses: FuseRegisters) -> None:
    """BOOT_CFG0 bit layout matches the device fuse map."""
    reg = fuses.find_reg("BOOT_CFG0")
    offsets = {bf.name: (bf.offset, bf.width) for bf in reg.get_bitfields()}
    assert offsets["BOOT_SRC"] == (0, 2)
    assert offsets["BOOT_SPEED"] == (3, 2)
    assert offsets["ISP_FT_DIS"] == (6, 2)
    assert offsets["ISP_UART_DIS"] == (8, 1)
    assert offsets["ISP_I3C_DIS"] == (12, 1)
    assert offsets["ISP_API_DIS"] == (15, 1)
    boot_speed = reg.find_bitfield("BOOT_SPEED")
    assert [enum.name for enum in boot_speed.get_enums()] == [
        "SYSTEM_CLOCK",
        "HIGH_SPEED",
        "LOW_SPEED",
        "MID_SPEED",
    ]


def test_sb40_supported_commands() -> None:
    """SB4.0 command set matches the commands accepted by the boot ROM."""
    db = get_db(FAMILY)
    commands = db.get_list(DatabaseManager.SB40, "supported_commands")
    assert set(commands) == {
        "erase",
        "load",
        "execute",
        "programFuses",
        "copy",
        "loadKeyBlob",
        "configureMemory",
        "fillMemory",
        "checkFwVersion",
        "reset",
    }
    # Commands not implemented by the RTL3450 ROM
    assert "programIFR" not in commands
    assert "loadCMAC" not in commands
    assert "loadHashLocking" not in commands


def test_bootable_image_offsets() -> None:
    """xSPI NOR boot layout places FCB, XMCD and the boot image at fixed offsets."""
    db = get_db(FAMILY)
    segments = db.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types")["xspi_nor"]["segments"]
    assert segments == {"fcb": 0x0000, "xmcd": 0x0300, "mbi": 0x4000}


def test_ahab_core_id() -> None:
    """The boot core of the device is a Cortex-M55."""
    db = get_db(FAMILY)
    core_ids = db.get_dict(DatabaseManager.AHAB, "core_ids")
    assert list(core_ids) == ["CORTEX_M55"]
    assert core_ids["CORTEX_M55"][1] == "cortex-m55"


def test_ahab_srk_hash_fuses() -> None:
    """ECC and PQC root key hashes are stored in separate fuse groups."""
    db = get_db(FAMILY)
    assert db.get_dict(DatabaseManager.AHAB, "fuses_0")["rkth"] == "__srk_hash0"
    assert db.get_dict(DatabaseManager.AHAB, "fuses_1")["pqc_rkth"] == "__srk_hash1"


def test_mbi_supported_classes() -> None:
    """The device supports plain/CRC XIP and RAM images plus signed XIP images."""
    assert set(MasterBootImage.get_mbi_classes(FAMILY)) == {
        "mimxrtl3450_xip_plain",
        "mimxrtl3450_xip_crc",
        "mimxrtl3450_xip_signed",
        "mimxrtl3450_load_to_ram_plain",
        "mimxrtl3450_load_to_ram_crc",
    }


def test_sb40_family_is_supported() -> None:
    """The device is listed among SecureBinary4 supported families."""
    assert FAMILY in SecureBinary4.get_supported_families()


@pytest.mark.parametrize(
    "command,option",
    [
        ("mbi get-templates", "-o"),
        ("bootable-image get-templates", "-o"),
        ("bootable-image fcb get-templates", "-o"),
    ],
)
def test_get_templates(cli_runner: CliRunner, tmpdir: str, command: str, option: str) -> None:
    """Configuration templates can be generated for the device."""
    output = os.path.join(tmpdir, command.replace(" ", "_"))
    cli_runner.invoke(nxpimage.main, f"{command} -f {FAMILY.name} {option} {output}".split())
    assert os.listdir(output)


def test_sb40_get_template(cli_runner: CliRunner, tmpdir: str) -> None:
    """SB4.0 configuration template can be generated for the device."""
    template = os.path.join(tmpdir, "sb40.yaml")
    cli_runner.invoke(nxpimage.main, f"sb40 get-template -f {FAMILY.name} -o {template}".split())
    assert os.path.isfile(template)
