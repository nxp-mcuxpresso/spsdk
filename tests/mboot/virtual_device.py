#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from struct import pack

import pytest

from spsdk.mboot.commands import CommandTag, CmdPacket, ResponseTag, parse_cmd_response
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.interfaces import Interface


########################################################################################################################
# Helper functions
########################################################################################################################
def pack_response(tag, *params):
    return True, pack(f'<4B{len(params)}I', tag, 0, 0, len(params), *params)


########################################################################################################################
# Commands functions
########################################################################################################################
def cmd_flash_erase_all(*args, **_kwargs):
    assert len(args) == 1
    # TODO remove unused code: mem_id = args[0]
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.FLASH_ERASE_ALL)


def cmd_flash_erase_region(*args, **kwargs):
    assert len(args) == 3
    cfg = kwargs['config']
    address, length, mem_id = args
    # TODO: check arguments
    if address < cfg.flash_start_address or address >= cfg.flash_start_address + cfg.flash_size:
        status = StatusCode.FLASH_ADDRESS_ERROR
    elif length > (cfg.flash_size - address):
        status = StatusCode.FLASH_SIZE_ERROR
    else:
        status = StatusCode.SUCCESS
    return pack_response(ResponseTag.GENERIC, status, CommandTag.FLASH_ERASE_ALL)


def cmd_read_memory(*args, **kwargs):
    assert len(args) == 3
    address, length, mem_id = args
    cfg = kwargs['config']
    response_index = kwargs['index']
    if response_index == 0:
        # TODO: check arguments
        return pack_response(ResponseTag.READ_MEMORY, StatusCode.SUCCESS, length)
    if response_index == 1:
        return False, b'\x00' * cfg.max_packet_size
    elif response_index > 1 and (response_index - 1) * cfg.max_packet_size < length:
        return False, b'\x00' * cfg.max_packet_size
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.READ_MEMORY)


def cmd_write_memory(*args, **kwargs):
    assert len(args) == 3
    # TODO remove unused code: address, length, mem_id = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.WRITE_MEMORY)


def cmd_fill_memory(*args, **kwargs):
    assert len(args) == 3
    # TODO remove unused code: address, length, pattern = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.FILL_MEMORY)


def cmd_flash_security_disable(*args, **kwargs):
    assert len(args) == 2
    # TODO remove unused code: key1, key2 = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.FLASH_SECURITY_DISABLE)


def cmd_get_property(*args, **kwargs):
    assert len(args) == 2
    cfg = kwargs['config']
    tag, mem_id = args
    values = cfg.get_property_values(tag)
    if values:
        return pack_response(ResponseTag.GET_PROPERTY, StatusCode.SUCCESS, *values)
    return pack_response(ResponseTag.GET_PROPERTY, StatusCode.UNKNOWN_PROPERTY, tag)


def cmd_set_property(*args, **kwargs):
    assert len(args) == 2
    # TODO remove unused code: cfg = kwargs['config']
    tag, value = args
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, tag)


@pytest.mark.skip
def cmd_receive_sb_file(*args, **kwargs):
    # TODO implement the test
    pass


@pytest.mark.skip
def cmd_execute(*args, **kwargs):
    # TODO implement the test
    pass


@pytest.mark.skip
def cmd_call(*args, **kwargs):
    # TODO implement the test
    pass


def cmd_reset(*args, **kwargs):
    assert len(args) == 0
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.RESET)


########################################################################################################################
# Virtual Device Class
########################################################################################################################
class VirtualDevice(Interface):
    CMD = {
        CommandTag.FLASH_ERASE_ALL: cmd_flash_erase_all,
        CommandTag.FLASH_ERASE_REGION: cmd_flash_erase_region,
        CommandTag.READ_MEMORY: cmd_read_memory,
        CommandTag.WRITE_MEMORY: cmd_write_memory,
        CommandTag.FILL_MEMORY: cmd_fill_memory,
        CommandTag.FLASH_SECURITY_DISABLE: cmd_flash_security_disable,
        CommandTag.GET_PROPERTY: cmd_get_property,
        CommandTag.RECEIVE_SB_FILE: cmd_receive_sb_file,
        CommandTag.EXECUTE: cmd_execute,
        CommandTag.CALL: cmd_call,
        CommandTag.RESET: cmd_reset,
        CommandTag.SET_PROPERTY: cmd_set_property,
        CommandTag.FLASH_ERASE_ALL_UNSECURE: None,
        CommandTag.FLASH_PROGRAM_ONCE: None,
        CommandTag.FLASH_READ_ONCE: None,
        CommandTag.FLASH_READ_RESOURCE: None,
        CommandTag.CONFIGURE_MEMORY: None,
        CommandTag.RELIABLE_UPDATE: None,
        CommandTag.GENERATE_KEY_BLOB: None,
        CommandTag.KEY_PROVISIONING: None
    }

    @property
    def is_opened(self):
        return self._opened

    def __init__(self, config, **kwargs):
        super().__init__(**kwargs)
        self._opened = False
        self._dev_conf = config
        self._cmd_tag = 0
        self._cmd_params = []
        self._cmd_data = bytes()
        self._response_index = 0

    def open(self):
        self._opened = True

    def close(self):
        self._opened = False

    def read(self, timeout=1000):
        if self._dev_conf.valid_cmd(self._cmd_tag):
            cmd, raw_data = self.CMD[self._cmd_tag](*self._cmd_params,
                                                    index=self._response_index,
                                                    config=self._dev_conf)
            self._response_index += 1
        else:
            cmd, raw_data = pack_response(ResponseTag.GENERIC, StatusCode.UNKNOWN_COMMAND, self._cmd_tag)
        logging.debug(f"RAW-IN [{len(raw_data)}]: " + ', '.join(f"{b:02X}" for b in raw_data))
        return parse_cmd_response(raw_data) if cmd else raw_data

    def write(self, packet):
        if isinstance(packet, CmdPacket):
            self._cmd_tag = packet.header.tag
            self._cmd_params = packet.params
            self._response_index = 0
            raw_data = packet.to_bytes()
        elif isinstance(packet, (bytes, bytearray)):
            self._cmd_data = packet
            raw_data = packet
        else:
            raise Exception('Not valid packet type !')
        logging.debug(f"RAW-OUT[{len(raw_data)}]: " + ', '.join(f"{b:02X}" for b in raw_data))

    def info(self):
        return "Virtual Device"
