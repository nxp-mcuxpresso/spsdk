#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from struct import pack

from spsdk.mboot.commands import (
    CmdPacket,
    CommandTag,
    KeyProvOperation,
    ResponseTag,
    parse_cmd_response,
)
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootDataAbortError
from spsdk.mboot.interfaces import Interface
from spsdk.mboot.memories import ExtMemId


########################################################################################################################
# Helper functions
########################################################################################################################
def pack_response(tag, *params):
    return True, pack(f"<4B{len(params)}I", tag, 0, 0, len(params), *params)


def set_error_code(step_index: int, fail_step: int) -> int:
    if fail_step is not None and fail_step == step_index:
        return StatusCode.FAIL
    return StatusCode.SUCCESS


########################################################################################################################
# Commands functions
########################################################################################################################
def cmd_call(*args, **kwargs):
    assert len(args) == 2
    address, _ = args
    status = StatusCode.FAIL if address == 0 else StatusCode.SUCCESS
    return pack_response(ResponseTag.GENERIC, status, CommandTag.CALL)


def cmd_configure_memory(*args, **kwargs):
    assert len(args) == 2
    memory_id, address = args
    assert address >= 0
    status = StatusCode.FAIL if memory_id not in ExtMemId.tags() + [0] else StatusCode.SUCCESS
    return pack_response(ResponseTag.GENERIC, status, CommandTag.CONFIGURE_MEMORY)


def cmd_flash_erase_all(*args, **_kwargs):
    assert len(args) == 1
    # TODO remove unused code: mem_id = args[0]
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.FLASH_ERASE_ALL)


def cmd_flash_erase_region(*args, **kwargs):
    assert len(args) == 3
    cfg = kwargs["config"]
    address, length, mem_id = args
    # TODO: check arguments
    if address < cfg.flash_start_address or address >= cfg.flash_start_address + cfg.flash_size:
        status = StatusCode.FLASH_ADDRESS_ERROR
    elif length > (cfg.flash_size - address):
        status = StatusCode.FLASH_SIZE_ERROR
    else:
        status = StatusCode.SUCCESS
    return pack_response(ResponseTag.GENERIC, status, CommandTag.FLASH_ERASE_ALL)


def cmd_execute(*args, **kwargs):
    assert len(args) == 3
    address, arg, _ = args
    status = StatusCode.SUCCESS if arg < address else StatusCode.FAIL
    return pack_response(ResponseTag.GENERIC, status, CommandTag.EXECUTE)


def cmd_read_memory(*args, **kwargs):
    assert len(args) == 3
    address, length, mem_id = args
    cfg = kwargs["config"]
    response_index = kwargs["index"]
    fail_step = kwargs["fail_step"]
    caller = kwargs["full_ref"]

    if fail_step is not None:
        if response_index == 0:
            return pack_response(ResponseTag.READ_MEMORY, StatusCode.SUCCESS, 0)
        if response_index == 1:
            caller._response_index += 1
            error = McuBootDataAbortError if fail_step else TimeoutError
            raise error()
        return pack_response(ResponseTag.GENERIC, fail_step, CommandTag.READ_MEMORY)

    if response_index == 0:
        # TODO: check arguments
        return pack_response(ResponseTag.READ_MEMORY, StatusCode.SUCCESS, length)
    if response_index == 1:
        return False, b"\x00" * cfg.max_packet_size
    elif response_index > 1 and (response_index - 1) * cfg.max_packet_size < length:
        return False, b"\x00" * cfg.max_packet_size
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


def cmd_load_image(*args, **kwargs):
    assert len(args) == 1
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, 0)


def cmd_get_property(*args, **kwargs):
    assert len(args) == 2
    cfg = kwargs["config"]
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


def cmd_receive_sb_file(*args, **kwargs):
    assert len(args) == 1
    response_index = kwargs["index"]
    fail_step = kwargs["fail_step"]
    caller = kwargs["full_ref"]
    if not fail_step:
        return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.RECEIVE_SB_FILE)
    # introducing failures
    if response_index == 0:
        return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.RECEIVE_SB_FILE)
    if response_index == 1:
        caller._response_index += 1
        raise McuBootDataAbortError()
    return pack_response(ResponseTag.GENERIC, fail_step, CommandTag.RECEIVE_SB_FILE)


def cmd_reset(*args, **kwargs):
    assert len(args) == 0
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.RESET)


def cmd_generate_keyblob(*args, index, fail_step, **kwargs):
    response = {
        0: pack_response(ResponseTag.KEY_BLOB_RESPONSE, set_error_code(index, fail_step), 20),
        1: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.GENERATE_KEY_BLOB
        )
        if args[2] == 0
        else (False, bytes(20)),
        2: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.GENERATE_KEY_BLOB
        ),
    }[index]
    return response


######################################
# Key Provisioning support functions #
######################################
def cmd_key_prov_no_data(index, fail_step):
    return pack_response(
        ResponseTag.KEY_PROVISIONING_RESPONSE, set_error_code(index, fail_step), 20
    )


def cmd_key_prov_write(index, fail_step):
    return {
        0: cmd_key_prov_no_data(index, fail_step),
        1: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.KEY_PROVISIONING
        ),
    }[index]


def cmd_key_prov_read(index, fail_step):
    return {
        0: cmd_key_prov_no_data(index, fail_step),
        1: (False, bytes(20)),
        2: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.KEY_PROVISIONING
        ),
    }[index]


def cmd_key_provisioning(*args, index, fail_step, **kwargs):
    response_function = {
        KeyProvOperation.ENROLL: cmd_key_prov_no_data,
        KeyProvOperation.SET_INTRINSIC_KEY: cmd_key_prov_no_data,
        KeyProvOperation.WRITE_NON_VOLATILE: cmd_key_prov_no_data,
        KeyProvOperation.READ_NON_VOLATILE: cmd_key_prov_no_data,
        KeyProvOperation.SET_USER_KEY: cmd_key_prov_write,
        KeyProvOperation.WRITE_KEY_STORE: cmd_key_prov_write,
        KeyProvOperation.READ_KEY_STORE: cmd_key_prov_read,
    }[args[0]]
    response = response_function(index, fail_step)
    return response


def cmd_no_command(*args, **kwargs):
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS, CommandTag.NO_COMMAND)


########################################################################################################################
# Virtual Device Class
########################################################################################################################
class VirtualDevice(Interface):
    CMD = {
        CommandTag.NO_COMMAND: cmd_no_command,
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
        CommandTag.CONFIGURE_MEMORY: cmd_configure_memory,
        CommandTag.RELIABLE_UPDATE: None,
        CommandTag.GENERATE_KEY_BLOB: cmd_generate_keyblob,
        CommandTag.KEY_PROVISIONING: cmd_key_provisioning,
    }

    @property
    def is_opened(self):
        return self._opened

    @property
    def need_data_split(self) -> bool:
        return self._need_data_split

    def __init__(self, config, **kwargs):
        super().__init__(**kwargs)
        self._opened = False
        self._dev_conf = config
        self._cmd_tag = 0
        self._cmd_params = []
        self._cmd_data = bytes()
        self._response_index = 0
        self._need_data_split = True
        self.fail_step = None

    def open(self):
        self._opened = True

    def close(self):
        self._opened = False

    def read(self, timeout=1000):
        if self._dev_conf.valid_cmd(self._cmd_tag):
            cmd, raw_data = self.CMD[self._cmd_tag](
                *self._cmd_params,
                index=self._response_index,
                config=self._dev_conf,
                fail_step=self.fail_step,
                full_ref=self,
            )
            self._response_index += 1
        else:
            cmd, raw_data = pack_response(
                ResponseTag.GENERIC, StatusCode.UNKNOWN_COMMAND, self._cmd_tag
            )
        logging.debug(f"RAW-IN [{len(raw_data)}]: " + ", ".join(f"{b:02X}" for b in raw_data))
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
            raise Exception("Not valid packet type !")
        logging.debug(f"RAW-OUT[{len(raw_data)}]: " + ", ".join(f"{b:02X}" for b in raw_data))

    def info(self):
        return "Virtual Device"
