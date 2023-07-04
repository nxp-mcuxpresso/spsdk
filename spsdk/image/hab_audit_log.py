#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Utility allowing parsing of HAB audit log data."""

import os
from enum import Enum as PyEnum
from struct import unpack_from
from typing import List, Optional, Type

from spsdk import SPSDKError
from spsdk.mboot import McuBoot, PropertyTag
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import load_binary

from .commands import parse_command
from .header import CmdTag

# NOTE HAB Audit log executables have been moved to spsdk/examples/data/hab_audit


# pylint: disable=too-few-public-methods
class CpuInfo:
    """Cpu specific information, necessary for hw tests (HAB log reading)."""

    def __init__(
        self,
        cpu_name: str,
        hab_audit_bin: str,
        bin_base_address: int,
        bin_start_address: int,
    ):
        """Constructor of CpuInfo class."""
        # name of the supported cpus (for example rt1020, rt1050,...)
        self.cpu_name = cpu_name
        # name of the hab audit executable file
        self.hab_audit_bin = hab_audit_bin
        # base address of the hab audit executable file
        self.bin_base_address = bin_base_address
        # start address of the hab audit executable file
        self.bin_start_address = bin_start_address


# pylint: disable=no-member
class CpuData(PyEnum):
    """Data for all supported cpus."""

    MIMXRT1020 = CpuInfo(
        cpu_name="rt1020",
        hab_audit_bin="rt1020_exec_hab_audit.bin",
        bin_base_address=0x20200000,
        bin_start_address=0x20200358,
    )

    MIMXRT1050 = CpuInfo(
        cpu_name="rt1050",
        hab_audit_bin="rt1050_exec_hab_audit.bin",
        bin_base_address=0x20018000,
        bin_start_address=0x20018378,
    )

    MIMXRT1060 = CpuInfo(
        cpu_name="rt1060",
        hab_audit_bin="rt1060_exec_hab_audit.bin",
        bin_base_address=0x20018000,
        bin_start_address=0x200183A4,
    )

    @property
    def cpu_name(self) -> str:
        """:return: name of the cpu."""
        return self.value.cpu_name

    @property
    def bin(self) -> str:
        """:return: name of the hab audit binary."""
        return self.value.hab_audit_bin

    @property
    def base_address(self) -> int:
        """:return: base address of the hab audit bin."""
        return self.value.bin_base_address

    @property
    def start_address(self) -> int:
        """:return: start address of the hab audit bin."""
        return self.value.bin_start_address


class HabConfig(Enum):
    """HAB configurations."""

    HAB_CFG_RETURN = (0x33, "Field Return IC")
    HAB_CFG_OPEN = (0xF0, "Non - secure IC")
    HAB_CFG_CLOSED = (0xCC, "Secure IC")


class HabState(Enum):
    """HAB state definitions."""

    HAB_STATE_INITIAL = (0x33, "Initializing state(transitory)")
    HAB_STATE_CHECK = (0x55, "Check state(non - secure)")
    HAB_STATE_NONSECURE = (0x66, "Non - secure state")
    HAB_STATE_TRUSTED = (0x99, "Trusted state")
    HAB_STATE_SECURE = (0xAA, "Secure state")
    HAB_STATE_FAIL_SOFT = (0xCC, "Soft fail state")
    HAB_STATE_FAIL_HARD = (0xFF, "Hard fail state(terminal)")
    HAB_STATE_NONE = (0xF0, "No security state machine")


class HabStatus(Enum):
    """HAB Status."""

    HAB_STS_ANY = (0, "Match any status")
    HAB_FAILURE = (0x33, "Operation failed")
    HAB_WARNING = (0x69, "Operation completed with warning")
    HAB_SUCCESS = (0xF0, "Operation completed successfully")


class HabReason(Enum):
    """Further reason of the status."""

    HAB_RSN_ANY = (0x00, "Match any reason")
    HAB_ENG_FAIL = (0x30, "Engine failure")
    HAB_INV_ADDRESS = (0x22, "Invalid address: access denied")
    HAB_INV_ASSERTION = (0x0C, "Invalid assertion")
    HAB_INV_CALL = (0x28, "Function called out of sequence")
    HAB_INV_CERTIFICATE = (0x21, "Invalid certificate")
    HAB_INV_COMMAND = (0x06, "Invalid command: command malformed")
    HAB_INV_CSF = (0x11, "Invalid Command Sequence File")
    HAB_INV_DCD = (0x27, "Invalid Device Configuration Data")
    HAB_INV_INDEX = (0x0F, "Invalid index: access denied")
    HAB_INV_IVT = (0x05, "Invalid Image Vector Table")
    HAB_INV_KEY = (0x1D, "Invalid key")
    HAB_INV_RETURN = (0x1E, "Failed callback function")
    HAB_INV_SIGNATURE = (0x18, "Invalid signature")
    HAB_INV_SIZE = (0x17, "Invalid data size")
    HAB_MEM_FAIL = (0x2E, "Memory failure")
    HAB_OVR_COUNT = (0x2B, "Expired poll count")
    HAB_OVR_STORAGE = (0x2D, "Exhausted storage region")
    HAB_UNS_ALGORITHM = (0x12, "Unsupported algorithm")
    HAB_UNS_COMMAND = (0x03, "Unsupported command")
    HAB_UNS_ENGINE = (0x0A, "Unsupported engine")
    HAB_UNS_ITEM = (0x24, "Unsupported configuration item")
    HAB_UNS_KEY = (0x1B, "Unsupported key type or parameters")
    HAB_UNS_PROTOCOL = (0x14, "Unsupported protocol")
    HAB_UNS_STATE = (0x09, "Unsuitable state")


class HabContext(Enum):
    """Context from which the event is logged."""

    HAB_CTX_ANY = (0x00, "Match any context")
    HAB_CTX_ENTRY = (0xE1, "Event logged in hab_rvt.entry()")
    HAB_CTX_TARGET = (0x33, "Event logged in hab_rvt.check_target()")
    HAB_CTX_AUTHENTICATE = (0x0A, "Event logged in hab_rvt.authenticate_image()")
    HAB_CTX_DCD = (0xDD, "Event logged in hab_rvt.run_dcd()")
    HAB_CTX_CSF = (0xCF, "Event logged in hab_rvt.run_csf()")
    HAB_CTX_COMMAND = (0xC0, "Event logged executing CSF or DCD command")
    HAB_CTX_AUT_DAT = (0xDB, "Authenticated data block")
    HAB_CTX_ASSERT = (0xA0, "Event logged in hab_rvt.assert()")
    HAB_CTX_EXIT = (0xEE, "Event logged in hab_rvt.exit()")


class HabEngine(Enum):
    """Engine associated with the failure, or HAB_ENG_ANY if none."""

    HAB_ENG_ANY = (0x00, "Any engine")
    HAB_ENG_SCC = (0x03, "Security controller")
    HAB_ENG_RTIC = (0x05, "Run-time integrity checker")
    HAB_ENG_SAHARA = (0x06, "Crypto accelerator")
    HAB_ENG_CSU = (0x0A, "Central Security Unit")
    HAB_ENG_SRTC = (0x0C, "Secure clock")
    HAB_ENG_DCP = (0x1B, "Data Co-Processor")
    HAB_ENG_CAAM = (0x1D, "Cryptographic Acceleration and Assurance Module")
    HAB_ENG_SNVS = (0x1E, "Secure Non-Volatile Storage")
    HAB_ENG_OCOTP = (0x21, "Fuse controller")
    HAB_ENG_DTCP = (0x22, "DTCP co-processor")
    HAB_ENG_ROM = (0x36, "Protected ROM area")
    HAB_ENG_HDCP = (0x24, "HDCP co-processor")
    HAB_ENG_SW = (0xFF, "Software engine")


def check_reserved_regions(log_addr: int, reserved_regions: Optional[list] = None) -> bool:
    """Checks if the address of the log is not in conflict with CPU reserved regions.

    :param log_addr: address of the RAM, where we want to store hab log
    :param reserved_regions: list with reserved regions
    :return: True if the address of the log is not in conflict, otherwise return False
    """
    if reserved_regions is None:
        return True

    while not len(reserved_regions) % 2 and len(reserved_regions) != 0:
        # region_min and region_max determine one reserved region <region_min,region_max>
        region_max = reserved_regions.pop()
        region_min = reserved_regions.pop()
        # check conflict
        if region_min <= log_addr <= region_max:
            print(
                f"Conflict log address: - [ {hex(log_addr)} ] in region:"
                f" {hex(region_min)} - {hex(region_max)}"
            )
            return False
    return True


def get_hab_log_info(hab_log: Optional[bytes]) -> bool:
    """Gets information about hab log.

    It detects if the hab log is empty, invalid (4x 0xff) or prints out
    valid hab log status.
    :param hab_log: Log with data to test. It can be None.
    :return: False when flashloader is not accessible or problem with
             hab log occurred, otherwise return True.
    """
    if hab_log is None:
        print("Problem during Hab log reading. Hab log is empty.")
        return False
    if hab_log[0:4] == b"\xFF\xFF\xFF\xFF":
        print("Flash not accessible or application entry out of expected value")
        return False

    # first three bytes are HAB status, config and state
    for line in parse_hab_log(hab_log[0], hab_log[1], hab_log[2], hab_log[4:]):
        print(line)
    return True


def get_hab_enum_description(enum_cls: Type[Enum], value: int) -> str:
    """Converts integer value into description of the enumeration value.

    If the value does not match any value from enumeration, it is reported as `Unknown value`

    :param enum_cls: enumeration class used to convert integer to enum
    :param value: to be converted
    :return: description of the converted value
    """
    if value in enum_cls:
        return enum_cls.desc(enum_cls.from_int(value)) + f"  ({hex(value)})"
    return f"{hex(value)} = Unknown value"


def parse_hab_log(hab_sts: int, hab_cfg: int, hab_state: int, data: bytes) -> List[str]:
    """Parse the HAB audit log.

    :param hab_sts: HAB status; this is result of the HAB function `report_status`
    :param hab_cfg: HAB configuration; this is result of the HAB function `report_status`
    :param hab_state: HAB state; this is result of the HAB function `report_status`
    :param data: HAB log data in binary format; result of the HAB function `report_event`
    :return: list of lines to be displayed, that describes the HAB status and content of the LOG
    :raises SPSDKError: If a record has invalid data length
    """
    result = []
    result.append("=" * 60)
    result.append(f"HAB Status:  {get_hab_enum_description(HabStatus, hab_sts)}")
    result.append(f"HAB Config:  {get_hab_enum_description(HabConfig, hab_cfg)}")
    result.append(f"HAB State :  {get_hab_enum_description(HabState, hab_state)}")
    offset = 0
    while offset + 8 <= len(data):
        result.append("=" * 60)
        # parse header
        (cmd, length, version) = unpack_from(">BHB", data, offset)
        if (cmd != 0xDB) or ((version < 0x40) or (version > 0x43)):
            break
        if (length < 8) or (length > 1024):
            raise SPSDKError("invalid log length")
        # parse data
        (sts, rsn, ctx, eng) = unpack_from("4B", data, offset + 4)
        # print results
        result.append(f"Status:  {get_hab_enum_description(HabStatus, sts)}")
        result.append(f"Reason:  {get_hab_enum_description(HabReason, rsn)}")
        result.append(f"Context: {get_hab_enum_description(HabContext, ctx)}")
        result.append(f"Engine:  {get_hab_enum_description(HabEngine, eng)}")
        if length > 8:
            result.append(f"Data:    {data[offset + 8:offset + length].hex().upper()}")
            try:
                cmd = parse_command(data, offset + 8)
                result.append(f"Cmd :    {CmdTag.desc(cmd.tag)}")
                result.append(cmd.info())
            except ValueError:
                pass

        offset += length
    return result


def hab_audit_xip_app(
    cpu_data: CpuData, mboot: McuBoot, read_log_only: bool, hab_audit_path: str
) -> Optional[bytes]:
    """Authenticate the application in external FLASH.

    The function loads application into RAM and invokes its function, that authenticates the application and read the
    HAB log. Then the HAB log is downloaded and parsed and printed to stdout.
    :param cpu_data: target cpu data
    :param mboot: running flashloader
    :param read_log_only: true to read HAB log without invoking authentication; False to authenticate and read-log
        It is recommended to call the function firstly with parameter `True` and second time with parameter False to
        see the difference.
    :param hab_audit_path: Path to directory with HAB audit log executables
    :return: bytes contains result of the hab log, otherwise returns None when an error occurred
    :raises SPSDKError: When flashloader is not running
    :raises SPSDKError: When given cpu data were not provided
    :raises SPSDKError: When there is invalid address
    :raises SPSDKError: When Log address is in conflict with reserved regions
    :raises SPSDKError: When write memory failed
    :raises SPSDKError: When call failed
    """
    # check if the flashloader is running (not None)
    if not mboot:
        raise SPSDKError("Flashloader is not running")

    # get CPU data dir, hab_audit_base and hab_audit_start
    if not cpu_data:
        raise SPSDKError("Can not read the log, because given cpu data were not provided.")
    cpu_data_bin_dir = cpu_data.bin
    evk_exec_hab_audit_base = cpu_data.base_address
    evk_exec_hab_audit_start = cpu_data.start_address

    exec_hab_audit_path = os.path.join(hab_audit_path, cpu_data_bin_dir)

    if not os.path.isfile(exec_hab_audit_path):
        print("\nHAB logger not supported for the processor")
        return None

    # get executable file, that will be loaded into RAM
    exec_hab_audit_code = load_binary(exec_hab_audit_path)
    # find address of the buffer in RAM, where the HAB LOG will be stored
    log_addr = evk_exec_hab_audit_base + exec_hab_audit_code.find(
        b"\xA5\x5A\x11\x22\x33\x44\x55\x66"
    )
    if log_addr <= evk_exec_hab_audit_base:
        raise SPSDKError("Invalid address")
    # check if the executable binary is in collision with reserved region
    reserved_regions = mboot.get_property(PropertyTag.RESERVED_REGIONS)

    # check conflict between hab log address and any of reserved regions
    # we need 2 values (min and max) - that is why %2 is used
    if not check_reserved_regions(log_addr, reserved_regions):
        raise SPSDKError("Log address is in conflict with reserved regions")
    if not mboot.write_memory(evk_exec_hab_audit_base, exec_hab_audit_code, 0):
        raise SPSDKError("Write memory failed")
    if not mboot.call(evk_exec_hab_audit_start | 1, 0 if read_log_only else 1):
        raise SPSDKError("Call failed")

    log = mboot.read_memory(log_addr, 100, 0)
    return log
