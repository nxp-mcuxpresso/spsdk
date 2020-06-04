#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module that allows human-friendly interpretation of HAB logs."""

import struct

from .error_codes import HabStatusInfo, HabErrorReason


########################################################################################################################
# i.MX6 HAB Log Parser
########################################################################################################################
def parse_mx6_log(data: bytes) -> str:
    """Parses the HAB log data for i.MX6 devices.

    :param data: Data retrieved from the device
    :return: String representation of the data
    """
    log_single_desc = {
        0x00010000: "BOOTMODE - Internal Fuse",
        0x00010001: "BOOTMODE - Serial Bootloader",
        0x00010002: "BOOTMODE - Internal/Override",
        0x00010003: "BOOTMODE - Test Mode",
        0x00020000: "Security Mode - Fab",
        0x00020033: "Security Mode - Return",
        0x000200F0: "Security Mode - Open",
        0x000200CC: "Security Mode - Closed",
        0x00030000: "DIR_BT_DIS = 0",
        0x00030001: "DIR_BT_DIS = 1",
        0x00040000: "BT_FUSE_SEL = 0",
        0x00040001: "BT_FUSE_SEL = 1",
        0x00050000: "Primary Image Selected",
        0x00050001: "Secondary Image Selected",
        0x00060000: "NAND Boot",
        0x00060001: "USDHC Boot",
        0x00060002: "SATA Boot",
        0x00060003: "I2C Boot",
        0x00060004: "ECSPI Boot",
        0x00060005: "NOR Boot",
        0x00060006: "ONENAND Boot",
        0x00060007: "QSPI Boot",
        0x00061003: "Recovery Mode I2C",
        0x00061004: "Recovery Mode ECSPI",
        0x00061FFF: "Recovery Mode NONE",
        0x00062001: "MFG Mode USDHC",
        0x00070000: "Device INIT Call",
        0x000700F0: "Device INIT Pass",
        0x00070033: "Device INIT Fail",
        0x000800F0: "Device READ Data Pass",
        0x00080033: "Device READ Data Fail",
        0x000A00F0: "Plugin Image Pass",
        0x000A0033: "Plugin Image Fail",
        0x000C0000: "Serial Downloader Entry",
        0x000E0000: "ROMCP Patch"
    }

    log_double_desc = {
        0x00080000: "Device READ Data Call",
        0x00090000: "HAB Authentication Status Code:",
        0x000A0000: "Plugin Image Call",
        0x000B0000: "Program Image Call",
        0x000D0000: "Serial Downloader Call"
    }

    ret_msg = ''
    log_loop = 0
    while log_loop < 64:
        log_value = struct.unpack_from('I', data, log_loop * 4)[0]

        if log_value == 0x0:
            break

        if log_value in log_single_desc:
            ret_msg += " %02d. (0x%08X) -> %s\n" % (log_loop, log_value, log_single_desc[log_value])
            # TODO remove unused code> if log_value & 0xffff0000 == 0x00060000: boot_type = log_value & 0xff
        elif log_value in log_double_desc:
            ret_msg += " %02d. (0x%08X) -> %s\n" % (log_loop, log_value, log_double_desc[log_value])
            log_loop += 1
            log_data = struct.unpack_from('I', data, log_loop * 4)[0]
            if log_value == 0x00090000:
                ret_msg += " %02d. (0x%08X) -> HAB Status Code: 0x%02X  %s\n" % \
                            (log_loop, log_data, log_data & 0xff, HabStatusInfo.desc(log_data & 0xff))
                ret_msg += "                     HAB Reason Code: 0x%02X  %s\n" % \
                            ((log_data >> 8) & 0xff, HabErrorReason.desc((log_data >> 8) & 0xff))
            else:
                ret_msg += " %02d. (0x%08X) -> Address: 0x%08X\n" % (log_loop, log_data, log_data)
        else:
            ret_msg += " Log Buffer Code not found\n"

        log_loop += 1

    return ret_msg


########################################################################################################################
# i.MX7 HAB Log Parser
########################################################################################################################
def parse_mx7_log(data: bytes) -> str:
    """Parses the HAB log data for i.MX7 devices.

    :param data: Data retrieved from the device
    :return: String representation of the data
    """
    log_all_desc = {
        0x10: "BOOTMODE - Internal Fuse",
        0x11: "BOOTMODE - Serial Bootloader ",
        0x12: "BOOTMODE - Internal/Override ",
        0x13: "BOOTMODE - Test Mode ",
        0x20: "Security Mode - Fab ",
        0x21: "Security Mode - Return ",
        0x22: "Security Mode - Open ",
        0x23: "Security Mode - Closed ",
        0x30: "DIR_BT_DIS = 0 ",
        0x31: "DIR_BT_DIS = 1 ",
        0x40: "BT_FUSE_SEL = 0 ",
        0x41: "BT_FUSE_SEL = 1 ",
        0x50: "Primary Image Selected ",
        0x51: "Secondary Image Selected ",
        0x60: "NAND Boot ",
        0x61: "USDHC Boot ",
        0x62: "SATA Boot ",
        0x63: "I2C Boot ",
        0x64: "ECSPI Boot ",
        0x65: "NOR Boot ",
        0x66: "ONENAND Boot ",
        0x67: "QSPI Boot ",
        0x70: "Recovery Mode I2C ",
        0x71: "Recovery Mode ECSPI ",
        0x72: "Recovery Mode NONE ",
        0x73: "MFG Mode USDHC ",
        0xB1: "Plugin Image Pass ",
        0xBF: "Plugin Image Fail ",
        0xD0: "Serial Downloader Entry ",
        0xE0: "ROMCP Patch ",
        0x80: "Device INIT Call ",
        0x81: "Device INIT Pass ",
        0x91: "Device READ Data Pass ",
        0xA0: "HAB Authentication Status Code:  ",
        0x90: "Device READ Data Call ",
        0xB0: "Plugin Image Call ",
        0xC0: "Program Image Call ",
        0xD1: "Serial Downloader Call ",
        0x8F: "Device INIT Fail ",
        0x9F: "Device READ Data Fail "
    }

    log_error_desc = {
        0x8F: "Device INIT Fail ",
        0x9F: "Device READ Data Fail ",
        0xBF: "Plugin Image Fail "
    }

    log_tick_desc = {
        0x80: "Device INIT Call ",
        0x81: "Device INIT Pass ",
        0x8F: "Device INIT Fail ",
        0x91: "Device READ Data Pass ",
        0x9F: "Device READ Data Fail ",
        0xB0: "Plugin Image Call ",
        0xC0: "Program Image Call "
    }

    log_address_desc = {
        0x90: "Device READ Data Call ",
        0xB0: "Plugin Image Call ",
        0xC0: "Program Image Call ",
        0xD1: "Serial Downloader Call "
    }

    log_hab_desc = {
        0xA0: "HAB Authentication Status Code "
    }

    ret_msg = ''
    log_loop = 0
    while log_loop < 64:
        log_value_full = struct.unpack_from('I', data, log_loop * 4)[0]
        log_value = (log_value_full >> 24) & 0xff

        if log_value == 0x0:
            break

        if log_value in log_all_desc:
            ret_msg += " %02d. (0x%08X) -> %s\n" % (log_loop, log_value_full, log_all_desc[log_value])
        else:
            ret_msg += " %02d. Log Buffer Code not found\n"
        if log_value in log_address_desc:
            log_loop += 1
            log_data = struct.unpack_from('I', data, log_loop * 4)[0]
            ret_msg += " %02d. (0x%08X) -> Address: 0x%08X\n" % (log_loop, log_data, log_data)
        if log_value in log_hab_desc:
            log_loop += 1
            log_data = struct.unpack_from('I', data, log_loop * 4)[0]
            ret_msg += " %02d. (0x%08X) -> HAB Status Code: 0x%02X  %s\n" % \
                        (log_loop, log_data, log_data & 0xff, HabStatusInfo.desc(log_data & 0xff))
            ret_msg += "                     HAB Reason Code: 0x%02X  %s\n" % \
                        ((log_data >> 8) & 0xff, HabErrorReason.desc((log_data >> 8) & 0xff))
        if log_value in log_error_desc:
            ret_msg += "                     Error Code: 0x%06X\n" % (log_value_full & 0xffffff)
        if log_value in log_tick_desc:
            log_loop += 1
            log_data = struct.unpack_from('I', data, log_loop * 4)[0]
            ret_msg += " %02d. (0x%08X) -> Tick: 0x%08X\n" % (log_loop, log_data, log_data)

        log_loop = log_loop + 1

    return ret_msg


########################################################################################################################
# i.MXRT HAB Log Parser
########################################################################################################################
def parse_mxrt_log(_data: bytes) -> str:
    """Parses the HAB log data for i.MX RT devices.

    Function is not implemented yet.

    :param _data: Data retrieved from the device
    :return: String representation of the data
    """
    raise NotImplementedError()
