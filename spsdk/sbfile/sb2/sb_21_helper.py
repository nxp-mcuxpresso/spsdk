#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB 2.1 helper utilities.

This module provides helper functionality for Secure Binary (SB) 2.1 file format
operations, including key blob handling and cryptographic operations support.
"""

import logging
import struct
from typing import Callable, Optional, Union

from spsdk.exceptions import SPSDKError
from spsdk.image.otfad.otfad import KeyBlob
from spsdk.mboot.memories import ExtMemId, MemId
from spsdk.sbfile.sb2.commands import (
    CmdBaseClass,
    CmdErase,
    CmdFill,
    CmdJump,
    CmdKeyStoreBackup,
    CmdKeyStoreRestore,
    CmdLoad,
    CmdMemEnable,
    CmdProg,
    CmdVersionCheck,
    VersionCheckType,
)
from spsdk.utils.misc import (
    align_block,
    get_bytes_cnt_of_int,
    load_binary,
    swap32,
    value_to_bytes,
    value_to_int,
)

logger = logging.getLogger(__name__)


class SB21Helper:
    """SB21 Helper for Secure Binary 2.1 command processing.

    This class provides utilities for processing and converting Boot Descriptor (BD) file
    commands into corresponding SB2.1 command objects. It manages command mapping,
    memory ID resolution, and handles various secure boot operations including
    loading, encryption, key management, and memory operations.
    """

    def __init__(
        self, search_paths: Optional[list[str]] = None, zero_filling: bool = False
    ) -> None:
        """Initialize SB21 helper for processing secure boot commands.

        The helper manages command execution with configurable search paths for data files
        and optional zero filling for memory operations.

        :param search_paths: List of paths to search for data files, defaults to None
        :param zero_filling: Enable zero filling for memory operations, defaults to False
        """
        self.search_paths = search_paths
        self.cmds = {
            "load": self._load,
            "fill": self._fill_memory,
            "erase": self._erase_cmd_handler,
            "enable": self._enable,
            "encrypt": self._encrypt,
            "keywrap": self._keywrap,
            "keystore_to_nv": self._keystore_to_nv,
            "keystore_from_nv": self._keystore_from_nv,
            "version_check": self._version_check,
            "jump": self._jump,
            "programFuses": self._prog,
        }
        self.zero_filling = zero_filling

    @staticmethod
    def get_mem_id(mem_opt: Union[int, str]) -> int:
        """Get memory ID from string or integer in BD file.

        Converts memory option from BD file format to integer memory ID. Supports
        integer values, string representations of integers (including hex with 0x prefix),
        and legacy string identifiers that are resolved through MemId class.

        :param mem_opt: Memory option from BD file, either as integer or string identifier.
        :raises SPSDKError: If memory option format is not supported or cannot be resolved.
        :return: Integer memory ID corresponding to the input option.
        """
        if isinstance(mem_opt, int):
            return mem_opt
        if isinstance(mem_opt, str):
            try:
                return int(mem_opt, 0)
            except ValueError:
                mem_id = MemId.get_legacy_str(mem_opt)
                if mem_id:
                    return mem_id
        raise SPSDKError(f"Unsupported memory option: {mem_opt}")

    def get_command(self, cmd_name: str) -> Callable[[dict], CmdBaseClass]:
        """Get command factory function by name.

        Retrieves a callable function that creates command objects based on the provided
        command name. The command names correspond to those used in JSON files generated
        by the bd file parser (load, fill, erase, etc.).

        :param cmd_name: Command name identifier. Valid values are 'load', 'fill',
            'erase', 'enable', 'reset', 'encrypt', 'keywrap'.
        :return: Callable function that takes a dictionary and returns a command object.
        """
        command_object = self.cmds[cmd_name]
        return command_object

    def _fill_memory(self, cmd_args: dict) -> CmdFill:
        """Create CmdFill object for memory pattern filling operation.

        Fill is a type of load command used for filling a region of memory with pattern.

        Example:
        section(0) {
            // pattern fill
            load 0x55.b > 0x2000..0x3000;
            // load two bytes at an address
            load 0x1122.h > 0xf00;
        }

        :param cmd_args: Dictionary containing 'address' and 'pattern' keys for fill operation.
        :return: CmdFill object configured with specified address and pattern.
        """
        address = value_to_int(cmd_args["address"])
        pattern = value_to_int(cmd_args["pattern"])
        return CmdFill(address=address, pattern=pattern, zero_filling=self.zero_filling)

    def _load(self, cmd_args: dict) -> Union[CmdLoad, CmdProg]:
        """Create load command from command arguments.

        The load statement is used to store data into the memory.
        The load command is also used to write to the flash memory.
        When loading to the flash memory, the region being loaded to must be erased before to the load operation.
        The most common form of a load statement is loading a source file by name.
        Only plain binary images are supported.

        Example:
        section (0) {
            // load an entire binary file to an address
            load myBinFile > 0x70000000;
            // load an eight byte blob
            load {{ ff 2e 90 07 77 5f 1d 20 }} > 0xa0000000;
            // 4 byte load IFR statement
            load ifr 0x1234567 > 0x30;
            // Program fuse statement
            load fuse {{00 00 00 01}} > 0x01000188;
            // load to sdcard
            load sdcard {{aa bb cc dd}} > 0x08000188;
            load @288 {{aa bb cc dd}} > 0x08000188;
        }

        :param cmd_args: Dictionary containing command arguments with file path or values and address.
        :raises SPSDKError: If command arguments are invalid or unsupported.
        :return: CmdLoad or CmdProg object based on memory type and command arguments.
        """
        prog_mem_id = 4
        address = value_to_int(cmd_args["address"])
        load_opt = cmd_args.get("load_opt")
        mem_id = 0
        if load_opt:
            mem_id = self.get_mem_id(load_opt)

        # general non-authenticated load command
        if cmd_args.get("file"):
            data = load_binary(cmd_args["file"], self.search_paths)
            return CmdLoad(
                address=address, data=data, mem_id=mem_id, zero_filling=self.zero_filling
            )
        if cmd_args.get("values"):
            # if the memory ID is fuse or IFR change load command to program command
            if mem_id == prog_mem_id:
                return self._prog(cmd_args)

            values = [int(s, 16) for s in cmd_args["values"].split(",")]
            if max(values) > 0xFFFFFFFF or min(values) < 0:
                raise SPSDKError(
                    f"Invalid values for load command, values: {(values)}"
                    + ", expected unsigned 32bit comma separated values"
                )
            data = struct.pack(f"<{len(values)}L", *values)
            return CmdLoad(
                address=address, data=data, mem_id=mem_id, zero_filling=self.zero_filling
            )
        if cmd_args.get("pattern"):
            # if the memory ID is fuse or IFR change load command to program command
            # pattern in this case represents 32b int data word 1
            if mem_id == prog_mem_id:
                return self._prog(cmd_args)

        raise SPSDKError(f"Unsupported LOAD command args: {cmd_args}")

    def _prog(self, cmd_args: dict) -> CmdProg:
        """Create a CmdProg object initialized from command arguments.

        This method processes command arguments containing either binary values or integer patterns
        to create a program command object. It handles 4 or 8 byte data segments and performs
        necessary byte order swapping for binary values.

        :param cmd_args: Dictionary containing address, optional load_opt, and either 'values'
                         (hex string for binary blob) or 'pattern' (integer value)
        :raises SPSDKError: If data words are wrong size, unsupported arguments provided,
                            or program operation requires invalid byte segment
        :return: CmdProg object with initialized address, data words, and memory ID
        """
        address = value_to_int(cmd_args["address"])
        mem_id = self.get_mem_id(cmd_args.get("load_opt", 4))
        data_word1 = 0
        data_word2 = 0
        # values provided as binary blob {{aa bb cc dd}} either 4 or 8 bytes:
        if cmd_args.get("values"):
            int_value = int(cmd_args["values"], 16)
            byte_count = get_bytes_cnt_of_int(int_value)

            if byte_count <= 4:
                data_word1 = int_value
            elif byte_count <= 8:
                data_words = value_to_bytes(int_value, byte_cnt=8)
                data_word1 = value_to_int(data_words[:4])
                data_word2 = value_to_int(data_words[4:])
            else:
                raise SPSDKError("Program operation requires 4 or 8 byte segment")

            # swap byte order
            data_word1 = swap32(data_word1)
            data_word2 = swap32(data_word2)

        # values provided as integer e.g. 0x1000 represents data_word1
        elif cmd_args.get("pattern"):
            int_value = value_to_int(cmd_args["pattern"])
            byte_count = get_bytes_cnt_of_int(int_value)

            if byte_count <= 4:
                data_word1 = int_value
            else:
                raise SPSDKError("Data word 1 must be 4 bytes long")
        else:
            raise SPSDKError("Unsupported program command arguments")

        return CmdProg(address=address, data_word1=data_word1, data_word2=data_word2, mem_id=mem_id)

    def _erase_cmd_handler(self, cmd_args: dict) -> CmdErase:
        """Create CmdErase object from command arguments.

        The erase statement inserts a bootloader command to erase the flash memory.
        There are two forms of the erase statement. The simplest form (erase all)
        creates a command that erases the available flash memory.
        The actual effect of this command depends on the runtime settings
        of the bootloader and whether the bootloader resides in the flash, ROM, or RAM.

        Example:
        section (0){
            // Erase all
            erase all;
            // Erase unsecure all
            erase unsecure all;
            // erase statements specifying memory ID and range
            erase @8 all;
            erase @288 0x8001000..0x80074A4;
            erase sdcard 0x8001000..0x80074A4;
            erase mmccard 0x8001000..0x80074A4;
        }

        :param cmd_args: Dictionary containing erase command parameters including address,
            optional length, flags, and memory option.
        :return: Configured CmdErase object.
        """
        address = value_to_int(cmd_args["address"])
        length = value_to_int(cmd_args.get("length", 0))
        flags = value_to_int(cmd_args.get("flags", 0))

        mem_opt = cmd_args.get("mem_opt")
        mem_id = 0
        if mem_opt:
            mem_id = self.get_mem_id(mem_opt)

        return CmdErase(address=address, length=length, flags=flags, mem_id=mem_id)

    def _enable(self, cmd_args: dict) -> CmdMemEnable:
        """Create CmdMemEnable object from command arguments.

        Enable statement is used for initialization of external memories using a parameter block
        that was previously loaded to RAM.

        Example:
        section (0){
            # Load quadspi config block bin file to RAM, use it to enable QSPI.
            load myBinFile > 0x20001000;
            enable qspi 0x20001000;
        }

        :param cmd_args: Dictionary containing 'address', optional 'size' and 'mem_opt' keys.
        :return: Configured CmdMemEnable object with specified parameters.
        """
        address = value_to_int(cmd_args["address"])
        size = value_to_int(cmd_args.get("size", 4))
        mem_opt = cmd_args.get("mem_opt")
        mem_id = 0
        if mem_opt:
            mem_id = self.get_mem_id(mem_opt)
        return CmdMemEnable(address=address, size=size, mem_id=mem_id)

    def _encrypt(self, cmd_args: dict) -> CmdLoad:
        """Create encrypted load command from configuration arguments.

        Processes encryption configuration including keyblob ID, data source (file or values),
        and target address. The method validates the keyblob, loads the data, and performs
        encryption if the keyblob has appropriate flags (ADE and VLD) set.

        Example configuration:
        encrypt (0){
            load myImage > 0x0810000;
        }

        :param cmd_args: Dictionary containing 'keyblob_id', 'keyblobs' list, 'address',
                         and either 'file' or 'values' for data source
        :raises SPSDKError: If keyblob is invalid, missing, or data source is not provided
        :return: CmdLoad object with encrypted or plain data
        """
        keyblob_id = cmd_args["keyblob_id"]
        keyblobs = cmd_args.get("keyblobs", [])

        address = value_to_int(cmd_args["address"])

        if cmd_args.get("file"):
            data = load_binary(cmd_args["file"], self.search_paths)
        elif cmd_args.get("values"):
            values = [int(s, 16) for s in cmd_args["values"].split(",")]
            data = struct.pack(f"<{len(values)}L", *values)
        else:
            raise SPSDKError("Neither 'file' nor 'values' is provided in config to get data.")

        # Ensure keyblobs is a list and keyblob_id is a Number
        if not isinstance(keyblobs, list):
            raise SPSDKError(f"Expected list of keyblobs, got {type(keyblobs).__name__}")
        if not isinstance(keyblob_id, int):
            try:
                keyblob_id = int(str(keyblob_id), 0)
            except (ValueError, TypeError) as exc:
                raise SPSDKError(f"Invalid keyblob_id: {keyblob_id}, must be a number") from exc
        try:
            valid_keyblob = self._validate_keyblob(keyblobs, keyblob_id)
        except SPSDKError as exc:
            raise SPSDKError(f"Invalid key blob {str(exc)}") from exc

        if valid_keyblob is None:
            raise SPSDKError(f"Missing keyblob {keyblob_id} for encryption.")

        start_addr = value_to_int(valid_keyblob["keyblob_content"][0]["start"])
        end_addr = value_to_int(valid_keyblob["keyblob_content"][0]["end"])
        key = bytes.fromhex(valid_keyblob["keyblob_content"][0]["key"])
        counter = bytes.fromhex(valid_keyblob["keyblob_content"][0]["counter"])
        byte_swap = valid_keyblob["keyblob_content"][0].get("byte_swap", False)

        keyblob = KeyBlob(start_addr=start_addr, end_addr=end_addr, key=key, counter_iv=counter)

        # Encrypt only if the ADE and VLD flags are set
        if bool(end_addr & keyblob.KEY_FLAG_ADE) and bool(end_addr & keyblob.KEY_FLAG_VLD):
            encoded_data = keyblob.encrypt_image(
                base_address=address, data=align_block(data, 512), byte_swap=byte_swap
            )
        else:
            encoded_data = data

        return CmdLoad(address, encoded_data)

    def _keywrap(self, cmd_args: dict) -> CmdLoad:
        """Create a CmdLoad object with wrapped keyblob data.

        Keywrap holds keyblob ID to be encoded by a value stored in load command and
        stored to address defined in the load command.

        Example:
        keywrap (0) {
            load {{ 00000000 }} > 0x08000000;
        }

        :param cmd_args: Dictionary containing 'keyblobs' (list), 'keyblob_id' (int),
                        'address' (int/str), and 'values' (bytes) for keyblob wrapping
        :raises SPSDKError: If keyblob validation fails, keyblob ID is invalid, or
                           required parameters are missing
        :return: CmdLoad object with wrapped keyblob data
        """
        # iterate over keyblobs
        keyblobs = cmd_args.get("keyblobs", [])
        keyblob_id = cmd_args.get("keyblob_id")

        address = value_to_int(cmd_args["address"])
        otfad_key = cmd_args["values"]

        # Ensure keyblobs is a list and keyblob_id is a Number
        if not isinstance(keyblobs, list):
            raise SPSDKError(f"Expected list of keyblobs, got {type(keyblobs).__name__}")
        if keyblob_id is None:
            raise SPSDKError("keyblob_id is required but was not provided")
        if not isinstance(keyblob_id, int):
            try:
                keyblob_id = int(str(keyblob_id), 0)
            except (ValueError, TypeError) as exc:
                raise SPSDKError(f"Invalid keyblob_id: {keyblob_id}, must be a number") from exc
        try:
            valid_keyblob = self._validate_keyblob(keyblobs, keyblob_id)
        except SPSDKError as exc:
            raise SPSDKError(f" Key blob validation failed: {str(exc)}") from exc
        if valid_keyblob is None:
            raise SPSDKError(f"Missing keyblob {keyblob_id} for given keywrap")

        start_addr = value_to_int(valid_keyblob["keyblob_content"][0]["start"])
        end_addr = value_to_int(valid_keyblob["keyblob_content"][0]["end"])
        key = bytes.fromhex(valid_keyblob["keyblob_content"][0]["key"])
        counter = bytes.fromhex(valid_keyblob["keyblob_content"][0]["counter"])

        blob = KeyBlob(start_addr=start_addr, end_addr=end_addr, key=key, counter_iv=counter)

        encoded_keyblob = blob.export(kek=otfad_key)
        logger.info(f"Creating wrapped keyblob: \n{str(blob)}")

        return CmdLoad(address=address, data=encoded_keyblob)

    def _keystore_to_nv(self, cmd_args: dict) -> CmdKeyStoreRestore:
        """Create CmdKeyStoreRestore command for keystore restoration.

        The keystore_to_nv statement instructs the bootloader to load the backed up
        keystore values back into keystore memory region on non-volatile memory.

        Example:
        section (0) {
            keystore_to_nv @9 0x8000800;
        }

        :param cmd_args: Dictionary containing memory type and address parameters.
        :return: CmdKeyStoreRestore object initialized with specified parameters.
        """
        mem_opt = value_to_int(cmd_args["mem_opt"])
        address = value_to_int(cmd_args["address"])
        return CmdKeyStoreRestore(address, ExtMemId.from_tag(mem_opt))

    def _keystore_from_nv(self, cmd_args: dict) -> CmdKeyStoreBackup:
        """Create keystore restore command from non-volatile memory parameters.

        The keystore_from_nv statement instructs the bootloader to load the backed up
        keystore values back into keystore memory region from non-volatile memory.

        Example:
        section (0) {
            keystore_from_nv @9 0x8000800;
        }

        :param cmd_args: Dictionary containing memory type and address parameters.
        :return: CmdKeyStoreBackup object initialized with specified parameters.
        """
        mem_opt = value_to_int(cmd_args["mem_opt"])
        address = value_to_int(cmd_args["address"])
        return CmdKeyStoreBackup(address, ExtMemId.from_tag(mem_opt))

    def _version_check(self, cmd_args: dict) -> CmdVersionCheck:
        """Create version check command for SB2.1 file.

        Validates version of secure or non-secure firmware version with the value stored in the OTP or PFR,
        to prevent the FW rollback. The command fails if version provided in command is lower than version
        stored in the OTP/PFR.

        Example:
        section (0) {
            version_check sec 0x2;
            version_check nsec 2;
        }

        :param cmd_args: Dictionary holding the version type and fw version.
        :return: CmdVersionCheck object initialized with version check type and version.
        """
        ver_type = value_to_int(cmd_args["ver_type"])
        fw_version = value_to_int(cmd_args["fw_version"])
        return CmdVersionCheck(VersionCheckType.from_tag(ver_type), fw_version)

    def _validate_keyblob(self, keyblobs: list, keyblob_id: int) -> Optional[dict]:
        """Validate keyblob definition for correctness.

        Validates that a keyblob with the specified ID exists in the provided list and contains
        all required fields ('start', 'end', 'key', 'counter'). The keyblob definition must not
        be empty and must include all mandatory keys for proper keyblob creation.

        :param keyblobs: List of dictionaries containing keyblob definitions
        :param keyblob_id: ID of the keyblob to validate
        :raises SPSDKError: If the keyblob definition is empty
        :raises SPSDKError: If the keyblob definition is missing required keys
        :return: Valid keyblob dictionary if found and valid, None otherwise
        """
        for keyblob in keyblobs:
            if keyblob_id == keyblob["keyblob_id"]:
                kb_content = keyblob["keyblob_content"]
                if len(kb_content) == 0:
                    raise SPSDKError(f"Keyblob {keyblob_id} definition is empty!")

                for key in ["start", "end", "key", "counter"]:
                    if key not in kb_content[0]:
                        raise SPSDKError(f"Keyblob {keyblob_id} is missing '{key}' definition!")

                return keyblob

        return None

    def _jump(self, cmd_args: dict) -> CmdJump:
        """Create CmdJump object for ROM jump command.

        The "jump" command produces the ROM_JUMP_CMD for secure boot file format.
        See the boot image format design document for specific details about these commands,
        such as the function prototypes they expect.
        Jump to entrypoint is not supported. Only fixed address is supported.

        Example:
        section (0) {
            # jump to a fixed address
            jump 0xffff0000;
        }

        :param cmd_args: Dictionary containing jump command arguments including 'address' (required),
                         'argument' (optional, defaults to 0), and 'spreg' (optional).
        :return: CmdJump object initialized with specified address, argument and stack pointer register.
        """
        argument = value_to_int(cmd_args.get("argument", 0))
        address = value_to_int(cmd_args["address"])
        spreg = value_to_int(cmd_args["spreg"]) if "spreg" in cmd_args else None

        return CmdJump(address, argument, spreg)
