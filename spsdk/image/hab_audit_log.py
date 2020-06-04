#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Utility allowing parsing of HAB audit log data."""

from typing import List, Type
from struct import unpack_from

from spsdk.utils.easy_enum import Enum
from .header import CmdTag
from .commands import parse_command


class HabConfig(Enum):
    """HAB configurations."""
    HAB_CFG_RETURN = (0x33, 'Field Return IC')
    HAB_CFG_OPEN = (0xf0, 'Non - secure IC')
    HAB_CFG_CLOSED = (0xcc, 'Secure IC')


class HabState(Enum):
    """HAB state definitions."""
    HAB_STATE_INITIAL = (0x33, 'Initialising state(transitory)')
    HAB_STATE_CHECK = (0x55, 'Check state(non - secure)')
    HAB_STATE_NONSECURE = (0x66, 'Non - secure state')
    HAB_STATE_TRUSTED = (0x99, 'Trusted state')
    HAB_STATE_SECURE = (0xaa, 'Secure state')
    HAB_STATE_FAIL_SOFT = (0xcc, 'Soft fail state')
    HAB_STATE_FAIL_HARD = (0xff, 'Hard fail state(terminal)')
    HAB_STATE_NONE = (0xf0, 'No security state machine')


class HabStatus(Enum):
    """HAB Status."""
    HAB_STS_ANY = (0, 'Match any status')
    HAB_FAILURE = (0x33, 'Operation failed')
    HAB_WARNING = (0x69, 'Operation completed with warning')
    HAB_SUCCESS = (0xF0, 'Operation completed successfully')


class HabReason(Enum):
    """Further reason of the status."""
    HAB_RSN_ANY = (0x00, 'Match any reason')
    HAB_ENG_FAIL = (0x30, 'Engine failure')
    HAB_INV_ADDRESS = (0x22, 'Invalid address: access denied')
    HAB_INV_ASSERTION = (0x0c, 'Invalid assertion')
    HAB_INV_CALL = (0x28, 'Function called out of sequence')
    HAB_INV_CERTIFICATE = (0x21, 'Invalid certificate')
    HAB_INV_COMMAND = (0x06, 'Invalid command: command malformed')
    HAB_INV_CSF = (0x11, 'Invalid Command Sequence File')
    HAB_INV_DCD = (0x27, 'Invalid Device Configuration Data')
    HAB_INV_INDEX = (0x0f, 'Invalid index: access denied')
    HAB_INV_IVT = (0x05, 'Invalid Image Vector Table')
    HAB_INV_KEY = (0x1d, 'Invalid key')
    HAB_INV_RETURN = (0x1e, 'Failed callback function')
    HAB_INV_SIGNATURE = (0x18, 'Invalid signature')
    HAB_INV_SIZE = (0x17, 'Invalid data size')
    HAB_MEM_FAIL = (0x2e, 'Memory failure')
    HAB_OVR_COUNT = (0x2b, 'Expired poll count')
    HAB_OVR_STORAGE = (0x2d, 'Exhausted storage region')
    HAB_UNS_ALGORITHM = (0x12, 'Unsupported algorithm')
    HAB_UNS_COMMAND = (0x03, 'Unsupported command')
    HAB_UNS_ENGINE = (0x0a, 'Unsupported engine')
    HAB_UNS_ITEM = (0x24, 'Unsupported configuration item')
    HAB_UNS_KEY = (0x1b, 'Unsupported key type or parameters')
    HAB_UNS_PROTOCOL = (0x14, 'Unsupported protocol')
    HAB_UNS_STATE = (0x09, 'Unsuitable state')


class HabContext(Enum):
    """Context from which the event is logged."""
    HAB_CTX_ANY = (0x00, 'Match any context')
    HAB_CTX_ENTRY = (0xe1, 'Event logged in hab_rvt.entry()')
    HAB_CTX_TARGET = (0x33, 'Event logged in hab_rvt.check_target()')
    HAB_CTX_AUTHENTICATE = (0x0a, 'Event logged in hab_rvt.authenticate_image()')
    HAB_CTX_DCD = (0xdd, 'Event logged in hab_rvt.run_dcd()')
    HAB_CTX_CSF = (0xcf, 'Event logged in hab_rvt.run_csf()')
    HAB_CTX_COMMAND = (0xc0, 'Event logged executing CSF or DCD command')
    HAB_CTX_AUT_DAT = (0xdb, 'Authenticated data block')
    HAB_CTX_ASSERT = (0xa0, 'Event logged in hab_rvt.assert()')
    HAB_CTX_EXIT = (0xee, 'Event logged in hab_rvt.exit()')


class HabEngine(Enum):
    """Engine associated with the failure, or HAB_ENG_ANY if none."""
    HAB_ENG_ANY = (0x00, 'Any engine')
    HAB_ENG_SCC = (0x03, 'Security controller')
    HAB_ENG_RTIC = (0x05, 'Run-time integrity checker')
    HAB_ENG_SAHARA = (0x06, 'Crypto accelerator')
    HAB_ENG_CSU = (0x0a, 'Central Security Unit')
    HAB_ENG_SRTC = (0x0c, 'Secure clock')
    HAB_ENG_DCP = (0x1b, 'Data Co-Processor')
    HAB_ENG_CAAM = (0x1d, 'Cryptographic Acceleration and Assurance Module')
    HAB_ENG_SNVS = (0x1e, 'Secure Non-Volatile Storage')
    HAB_ENG_OCOTP = (0x21, 'Fuse controller')
    HAB_ENG_DTCP = (0x22, 'DTCP co-processor')
    HAB_ENG_ROM = (0x36, 'Protected ROM area')
    HAB_ENG_HDCP = (0x24, 'HDCP co-processor')
    HAB_ENG_SW = (0xff, 'Software engine')


def get_hab_enum_descr(enum_cls: Type[Enum], value: int) -> str:
    """Converts integer value into description of the enumeration value.

    If the value does not match any value from enumeration, it is reported as `Unknown value`

    :param enum_cls: enumeration class used to convert integer to enum
    :param value: to be converted
    :return: description of the converted value
    """
    if value in enum_cls:
        return enum_cls.desc(enum_cls.from_int(value)) + f'  ({hex(value)})'
    return f'{hex(value)} = Unknown value'


def parse_hab_log(hab_sts: int, hab_cfg: int, hab_state: int, data: bytes) -> List[str]:
    """Parse the HAB audit log.

    :param hab_sts: HAB status; this is result of the HAB function `report_status`
    :param hab_cfg: HAB configuration; this is result of the HAB function `report_status`
    :param hab_state: HAB state; this is result of the HAB function `report_status`
    :param data: HAB log data in binary format; result of the HAB function `report_event`
    :return: list of lines to be displayed, that describes the HAB status and content of the LOG
    :raise ValueError: If a record has invalid data length
    """
    result = list()
    result.append('=' * 60)
    result.append(f'HAB Status:  {get_hab_enum_descr(HabStatus, hab_sts)}')
    result.append(f'HAB Config:  {get_hab_enum_descr(HabConfig, hab_cfg)}')
    result.append(f'HAB State :  {get_hab_enum_descr(HabState, hab_state)}')
    offset = 0
    while offset + 8 <= len(data):
        result.append('=' * 60)
        # parse header
        (cmd, leng, ver) = unpack_from(">BHB", data, offset)
        if (cmd != 0xDB) or ((ver < 0x40) or (ver > 0x43)):
            break
        if (leng < 8) or (leng > 1024):
            raise ValueError('invalid log length')
        # parse data
        (sts, rsn, ctx, eng) = unpack_from("4B", data, offset + 4)
        # print results
        result.append(f'Status:  {get_hab_enum_descr(HabStatus, sts)}')
        result.append(f'Reason:  {get_hab_enum_descr(HabReason, rsn)}')
        result.append(f'Context: {get_hab_enum_descr(HabContext, ctx)}')
        result.append(f'Engine:  {get_hab_enum_descr(HabEngine, eng)}')
        if leng > 8:
            result.append(f'Data:    {data[offset + 8:offset + leng].hex().upper()}')
            try:
                cmd = parse_command(data, offset + 8)
                result.append(f'Cmd :    {CmdTag.desc(cmd.tag)}')
                result.append(cmd.info())
            except ValueError:
                pass

        offset += leng

    return result
