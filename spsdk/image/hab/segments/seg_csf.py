#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB CSF (Command Sequence File) segment implementation.

This module provides functionality for creating, manipulating, and parsing
CSF segments used in High Assurance Boot (HAB) for NXP devices. CSF contains
commands for authentication and configuration operations during the secure
boot process.
"""

import logging
from datetime import datetime, timezone
from typing import Iterator, Optional

from typing_extensions import Self

from spsdk.crypto.symmetric import aes_ccm_encrypt
from spsdk.exceptions import SPSDKCorruptedException, SPSDKError, SPSDKValueError
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.commands.cmd_auth_data import CmdAuthData, CmdDecryptData
from spsdk.image.hab.commands.cmd_install_key import CmdInstallSecretKey
from spsdk.image.hab.commands.commands import CmdBase, CmdSecretRefType, ImageBlock, parse_command
from spsdk.image.hab.constants import CmdName, CmdTag
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.image.hab.hab_mac import MAC
from spsdk.image.hab.hab_signature import Signature
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum, PaddingSegment
from spsdk.image.hab.utils import (
    get_app_image,
    get_header_version,
    get_initial_load_size,
    get_ivt_offset_from_cfg,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align, align_block, extend_block, find_file, load_binary

logger = logging.getLogger(__name__)


class SegCSF(PaddingSegment):
    """Command Sequence File (CSF) segment for HAB Secure Boot.

    Represents a CSF segment containing a script of commands used to guide image authentication
    and device configuration operations during the secure boot process. The segment manages
    CSF commands and their associated data such as keys and certificates.

    :cvar _COMMANDS: Tuple of supported CSF command tags for validation.
    """

    # list of supported CSF commands
    _COMMANDS: tuple[CmdTag, ...] = (
        CmdTag.WRT_DAT,
        CmdTag.CHK_DAT,
        CmdTag.NOP,
        CmdTag.SET,
        CmdTag.INIT,
        CmdTag.UNLK,
        CmdTag.INS_KEY,
        CmdTag.AUT_DAT,
    )

    def __init__(self, version: int = 0x40, enabled: bool = False):
        """Initialize CSF segment.

        Creates a new Command Sequence File (CSF) segment with specified version and enabled state.
        The CSF segment contains HAB commands and associated data like keys and certificates.

        :param version: CSF segment version, defaults to 0x40
        :param enabled: Whether the CSF segment is enabled, defaults to False
        """
        super().__init__()
        self._header = Header(SegmentTag.CSF.tag, version)
        self.enabled = enabled
        self._commands: list[CmdBase] = []
        # additional command data: keys and certificates; these data are stored after the commands
        #   - key is an offset of the data section in segment
        #   - value is an instance of the data section
        self._cmd_data: dict[int, CmdSecretRefType] = {}
        # this allows to export segment, that was parsed, but certificate and private keys are not available
        self.no_signature_updates = False

    @classmethod
    def _is_csf_command(cls, cmd: object) -> bool:
        """Test whether given object is instance of supported CSF command.

        The method validates if the provided object is both an instance of CmdBase
        and has a tag that exists in the supported commands list.

        :param cmd: Object instance to be tested for CSF command compatibility.
        :return: True if object is a supported CSF command, False otherwise.
        """
        return isinstance(cmd, CmdBase) and (cmd.tag in cls._COMMANDS)

    @property
    def version(self) -> int:
        """Get version of CSF segment.

        :return: Version number of the CSF segment.
        """
        return self._header.param

    @property
    def commands(self) -> list[CmdBase]:
        """Get list of CSF commands in the segment.

        :return: List of CSF command objects contained in this segment.
        """
        return self._commands

    @property
    def size(self) -> int:
        """Get the size of the binary representation of the segment.

        Returns 0 if the segment is not enabled. For enabled segments, calculates the maximum
        size needed based on the header length and all command data offsets and sizes.

        :return: Size in bytes of the binary representation, or 0 if segment is disabled.
        """
        if not self.enabled:
            return 0

        result = self._header.length
        for offset, cmd_data in self._cmd_data.items():
            result = max(result, offset + cmd_data.size)
        return result

    @property
    def space(self) -> int:
        """Get the size of the binary representation of the segment including padding.

        :return: Size in bytes including padding if segment is enabled, 0 if disabled.
        """
        return self.size + self.padding_len if self.enabled else 0

    @property
    def macs(self) -> Iterator[MAC]:
        """Get iterator of all MAC sections.

        :return: Iterator containing all MAC command sections from the CSF data.
        """
        return filter(lambda m: isinstance(m, MAC), self._cmd_data.values())  # type: ignore

    def __repr__(self) -> str:
        """Return string representation of CSF segment.

        Provides a concise string representation showing the number of commands
        contained in the CSF segment.

        :return: String representation in format "CSF <Commands: {count}>".
        """
        return f"CSF <Commands: {len(self.commands)}>"

    def __len__(self) -> int:
        """Get the number of commands in the CSF segment.

        :return: Number of commands stored in this CSF segment.
        """
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBase:
        """Get command at specified index.

        Retrieves a command from the commands list using index-based access.

        :param key: Index of the command to retrieve.
        :raises IndexError: If the index is out of range.
        :return: Command object at the specified index.
        """
        return self.commands[key]

    def __setitem__(self, key: int, value: CmdBase) -> None:
        """Set a CSF command at the specified index.

        Assigns a CSF command to the specified position in the commands list. The command
        must be a valid CSF command type.

        :param key: Index position where to set the command.
        :param value: CSF command object to be set at the specified index.
        :raises SPSDKError: If the provided command is not a valid CSF command type.
        """
        if not SegCSF._is_csf_command(value):
            raise SPSDKError("Invalid command")
        self._commands[key] = value

    def __iter__(self) -> Iterator[CmdBase]:
        """Return an iterator over the commands in the CSF segment.

        :return: Iterator yielding CmdBase objects from the commands collection.
        """
        return self.commands.__iter__()

    def __str__(self) -> str:
        """String representation of the SegCSF.

        Creates a formatted string containing CSF version, number of commands,
        and detailed information about each command and command data.

        :return: Formatted string representation of the CSF segment.
        """
        msg = ""
        msg += f"CSF Version        : {hex(self.version)}\n"
        msg += f"Number of commands : {len(self.commands)}\n"
        for cmd in self.commands:
            msg += str(cmd) + "\n"

        # certificates and signatures
        msg += "[CMD-DATA]\n"
        for offset, cmd_data in self._cmd_data.items():
            msg += f"- OFFSET : {offset}\n"
            msg += str(cmd_data)

        return msg

    def append_command(self, cmd: CmdBase) -> None:
        """Append CSF command to the segment.

        The method validates the command type and adds it to the internal command list,
        updating the header length and segment accordingly.

        :param cmd: CSF command to be added to the segment
        :raises SPSDKError: If the provided command is not a valid CSF command
        """
        if not SegCSF._is_csf_command(cmd):
            raise SPSDKError("Invalid command")
        self._commands.append(cmd)
        self._header.length += cmd.size
        self.update(False)

    def clear_commands(self) -> None:
        """Clear all commands from the CSF segment.

        This method removes all commands from the segment and updates the header
        length to reflect only the header size. The segment is automatically
        updated after clearing.
        """
        self._commands.clear()
        self._header.length = self._header.size
        self.update(True)

    def update(self, reset_cmddata_offsets: bool) -> None:
        """Update the offsets for the export.

        This method recalculates and updates command data offsets for all commands that require
        data references. It processes commands sequentially, assigning new offsets based on the
        current position and data size alignment requirements.

        :param reset_cmddata_offsets: True to reset all cmd-data offsets if cmd-data not
            specified in the command, False to avoid any reset. Note: reset should be done
            during parsing process as the data are incomplete.
        """
        cur_ofs = self._header.length
        new_cmd_data: dict[int, CmdSecretRefType] = {}
        for cmd in filter(lambda c: c.needs_cmd_data_reference, self.commands):
            key = cmd.cmd_data_reference
            if key is not None:
                cmd.cmd_data_offset = cur_ofs
                new_cmd_data[cur_ofs] = key
                cur_ofs += align(key.size, 4)
            elif reset_cmddata_offsets and (cmd.cmd_data_offset > 0):
                cmd.cmd_data_offset = 0

        self._cmd_data = new_cmd_data

    def _export_base(self) -> bytes:
        """Export base part of the CSF section without keys and signatures.

        The method updates the segment and exports the header followed by all commands
        in binary format, excluding cryptographic keys and signature data.

        :return: Binary data containing the CSF header and commands.
        """
        self.update(True)
        data = self._header.export()
        for command in self.commands:
            cmd_data = command.export()
            data += cmd_data
        return data

    def update_signatures(self, zulu: datetime, data: bytes, base_data_addr: int) -> None:
        """Update signatures in all CmdAuthData commands.

        The method iterates through all commands and updates signatures for CmdAuthData instances.
        For commands with blocks, it signs the image data. For commands without blocks, it signs
        the CSF section itself.

        :param zulu: Current UTC time and date for signature generation.
        :param data: Currently generated binary data; empty to create fake signature for size update.
        :param base_data_addr: Base address of the generated data.
        :raises SPSDKError: If invalid length of data during signature update.
        """
        if self.no_signature_updates:
            return

        for cmd in self.commands:
            if isinstance(cmd, CmdAuthData):
                if len(cmd) > 0:  # any blocks defined? => sign image data
                    if not cmd.update_signature(zulu, data, base_data_addr):
                        if len(data) != 0:
                            raise SPSDKError("Invalid length of data")
                else:  # sign CSF section
                    if not cmd.update_signature(zulu, self._export_base()):
                        if len(data) != 0:
                            raise SPSDKError("Invalid length of data")

    def export(self) -> bytes:
        """Export segment as bytes array (serialization).

        The method exports the CSF segment data including base segment information,
        command data sorted by offset, and padding. Returns empty bytes if segment
        is disabled.

        :return: Serialized segment data as bytes array.
        """
        data = b""
        if self.enabled:
            data = self._export_base()
            cmd_data_by_offset = sorted(self._cmd_data.items(), key=lambda t: str(t[0]).zfill(8))
            for offset, cmd_data in cmd_data_by_offset:
                data = extend_block(data, offset)
                data += cmd_data.export()
            # padding
            data += self._padding_export()

        return data

    def _parse_cmd_data(self, cmd: CmdBase, data: bytes) -> None:
        """Parse data for key installation or key authentication commands.

        Processes certificate or signature data for commands that require command data references.
        The method validates the command requirements and parses the binary data at the specified
        offset.

        :param cmd: Command with reference to command data that needs parsing.
        :param data: Binary data array containing the data to be parsed.
        :raises SPSDKError: If command doesn't need command data reference.
        :raises SPSDKError: If command data at the offset already exists.
        :return: Parsed instance, either Certificate or Signature.
        """
        if not cmd.needs_cmd_data_reference:
            raise SPSDKError("Invalid cmd")
        if self._cmd_data.get(cmd.cmd_data_offset) is not None:
            raise SPSDKError("Invalid cmd's data")
        result = cmd.parse_cmd_data(data[cmd.cmd_data_offset :])
        self._cmd_data[cmd.cmd_data_offset] = result

        return result

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse CSF segment from bytes array.

        This method parses a Command Sequence File (CSF) segment by first extracting the header,
        then iterating through and parsing individual commands within the segment data.

        :param data: The bytes array containing CSF segment data to parse.
        :raises SPSDKCorruptedException: When there is an unknown command in the segment.
        :raises SPSDKCorruptedException: When a command cannot be parsed successfully.
        :return: SegCSF instance with parsed commands and configuration.
        """
        header = Header.parse(data, SegmentTag.CSF.tag)
        index = header.size
        obj = cls(version=header.param, enabled=True)
        obj.no_signature_updates = True
        while index < header.length:
            try:
                cmd_obj = parse_command(data[index:])
                obj.append_command(cmd_obj)
            except ValueError as exc:
                raise SPSDKCorruptedException(
                    "Failed to parse command at position: " + hex(index)
                ) from exc
            index += cmd_obj.size

        for cmd in obj.commands:
            if cmd.needs_cmd_data_reference:
                obj._parse_cmd_data(cmd, data)

        obj.update(True)
        return obj


class HabSegmentCSF(HabSegmentBase):
    """HAB CSF (Command Sequence File) segment implementation.

    This class represents a CSF segment in HAB (High Assurance Boot) images, managing
    cryptographic commands and operations for secure boot verification. The CSF segment
    contains authentication and decryption commands that are processed by the HAB ROM code
    during the boot process.

    :cvar CSF_SIZE: Default size of CSF segment (0x2000 bytes).
    :cvar KEYBLOB_SIZE: Size of key blob data (0x200 bytes).
    :cvar SEGMENT_IDENTIFIER: HAB segment type identifier for CSF segments.
    """

    CSF_SIZE = 0x2000
    KEYBLOB_SIZE = 0x200
    SEGMENT_IDENTIFIER = HabSegmentEnum.CSF

    def __init__(self, csf: SegCSF, signature_timestamp: Optional[datetime] = None):
        """Initialize CSF segment with command sequence and timestamp.

        Creates a new CSF (Command Sequence File) segment containing security commands
        and signature timestamp for HAB (High Assurance Boot) image processing.

        :param csf: CSF segment containing the command sequence to be processed.
        :param signature_timestamp: Optional timestamp for signature creation. If None,
                                   current UTC time is used.
        """
        super().__init__()
        self.csf = csf
        self.signature_timestamp = signature_timestamp or datetime.now(timezone.utc)
        self.commands = self.csf.commands

    def update(self, reset_cmddata_offsets: bool) -> None:
        """Update the offsets for the export.

        :param reset_cmddata_offsets: Flag indicating whether to reset command data offsets.
        """
        self.csf.update(reset_cmddata_offsets)

    def append_command(self, cmd: CmdBase) -> None:
        """Append CSF command to the segment.

        :param cmd: CSF command to be appended to the segment.
        """
        self.csf.append_command(cmd)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the CSF HAB segment from HAB configuration.

        Creates a CSF (Command Sequence File) HAB segment by parsing the provided
        configuration, calculating offsets, processing commands, and setting up
        signature timestamps if specified.

        :param config: HAB configuration object containing segment definitions.
        :raises SPSDKSegmentNotPresent: When sections are missing or command not found.
        :return: Instance of CSF HAB segment with configured commands.
        """
        image_len = get_initial_load_size(config) + len(get_app_image(config))
        offset = cls.align_offset(image_len)
        offset = offset - get_ivt_offset_from_cfg(config)
        if not config.get("sections"):
            raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")
        signature_timestamp = None
        if "signatureTimestamp" in config.get_dict("options"):
            signature_timestamp = datetime.strptime(
                config.get_dict("options")["signatureTimestamp"], "%d/%m/%Y %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        segment = cls(
            SegCSF(enabled=True, version=get_header_version(config)),
            signature_timestamp=signature_timestamp,
        )
        segment.offset = offset
        cmd_configs = config.get_list_of_configs("sections")
        for cmd_config in cmd_configs:
            cmd_name = CmdName.from_label(next(iter(cmd_config.keys())))
            if cmd_name in [CmdName.HEADER, CmdName.INSTALL_NOCAK]:
                continue
            # Get the index of command from all commands of a same type
            same_command_configs = [
                cfg for cfg in cmd_configs if next(iter(cfg.keys())) == cmd_name.label
            ]
            cmd_index = same_command_configs.index(cmd_config)
            # Get the actual command class
            command_class = next(
                (
                    klass
                    for klass in CmdBase.get_all_command_types()
                    if klass.CMD_IDENTIFIER == cmd_name
                ),
                None,
            )
            if not command_class:
                raise SPSDKSegmentNotPresent(f"Command {cmd_name} not found")
            segment.append_command(command_class.load_from_config(config, cmd_index))

        segment.update(True)
        return segment

    def export(self) -> bytes:
        """Export CSF segment into bytes array.

        The method exports the CSF (Command Sequence File) segment and aligns it to the required CSF_SIZE.

        :return: Raw binary block of aligned CSF segment.
        """
        return align_block(self.csf.export(), self.CSF_SIZE)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse CSF segment block from image binary.

        Extracts and parses the Command Sequence File (CSF) segment from HAB container
        binary data using the IVT to locate the CSF address.

        :param data: Binary data of HAB container to be parsed.
        :param family: Target device family revision.
        :raises SPSDKSegmentNotPresent: When CSF segment is not present in the image.
        :return: Instance of CSF HAB segment.
        """
        ivt = HabSegmentIvt.parse(data)
        if ivt.csf_address:
            offset = ivt.csf_address - ivt.ivt_address
            segment = cls(SegCSF.parse(data[offset : offset + cls.CSF_SIZE]))
            segment.offset = offset
            return segment
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    @property
    def dek(self) -> Optional[bytes]:
        """Get the Data Encryption Key (DEK) from install key command.

        This property searches for a CmdInstallSecretKey command in the commands list
        and returns its secret key if found.

        :return: The DEK (Data Encryption Key) if present, None otherwise.
        """
        install_key_cmd = next(
            (cmd for cmd in self.commands if isinstance(cmd, CmdInstallSecretKey)), None
        )
        if not install_key_cmd:
            return None
        return install_key_cmd.secret_key

    @property
    def size(self) -> int:
        """Get size of the segment.

        :return: Size of the CSF segment in bytes.
        """
        return self.CSF_SIZE

    @property
    def mac_len(self) -> Optional[int]:
        """Get MAC length from decrypt data command.

        Searches through the CSF commands to find a CmdDecryptData instance and returns
        its MAC length value.

        :return: MAC length if CmdDecryptData command exists, None otherwise.
        """
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            return None
        return decrypt_data.mac_len

    @property
    def nonce(self) -> Optional[bytes]:
        """Get nonce value from decrypt data command.

        Retrieves the nonce from the first CmdDecryptData command found in the
        command list, if any exists.

        :return: Nonce bytes from decrypt data command, or None if no decrypt data command exists.
        """
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            return None
        return decrypt_data.nonce

    def generate_nonce(self, data: bytes) -> None:
        """Generate nonce corresponding to length of data to be encrypted.

        This method finds the DecryptData command within the CSF segments and generates
        a nonce based on the provided data length for encryption purposes.

        :param data: Data bytes used to determine the nonce length.
        :raises SPSDKValueError: When no DecryptData command is found in segments.
        """
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            raise SPSDKValueError("No DecryptData command found in segments")
        decrypt_data.generate_nonce(data)

    @staticmethod
    def align_offset(image_len: int) -> int:
        """Calculate CSF offset from image length.

        The method aligns the image length to 16-byte boundary and then aligns the result
        to 4KB (0x1000) page boundary to determine the proper CSF (Command Sequence File)
        offset position.

        :param image_len: Length of the image in bytes.
        :return: Calculated CSF offset aligned to page boundary.
        """
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000
        return csf_offset

    def update_signature(
        self, image_data: bytes, blocks: list[ImageBlock], base_data_address: int
    ) -> None:
        """Sign the HAB image and update the signature in CSF command.

        This method processes image blocks by adding them to the authenticate data command,
        updates signatures with timestamps, and handles variable-length ECC signatures by
        iteratively updating until the CSF segment data references stabilize.

        :param image_data: Padding image binary data to be signed
        :param blocks: List of ImageBlock objects to be signed
        :param base_data_address: Base address corresponding to the actual start address
        :raises SPSDKValueError: When authenticate data or CSF command is not present
        """
        auth_data = self.get_authenticate_data_cmd()
        if auth_data is None:
            raise SPSDKValueError("Authenticate data command not present.")
        for block in blocks:
            auth_data.append(block.base_address, block.size)
            self.csf._header.length += 8
        auth_data.update_signature(
            zulu=self.signature_timestamp,
            data=image_data,
            base_data_addr=base_data_address,
        )
        auth_csf = self.get_authenticate_csf_cmd()
        if auth_csf is None:
            raise SPSDKValueError("Authenticate CSF command not present.")
        # In order to sign the CSF segment, a dummy signature is created first, so the data references are updated
        # ECC keys create a signature with variable length (depending on r and s values), therefore
        # we need to get a signature which does not change the CSF segment data references
        updated = True
        while updated:
            assert isinstance(auth_csf.cmd_data_reference, (Signature, MAC))
            auth_cfs_size = align(auth_csf.cmd_data_reference.size, 4)
            auth_csf.update_signature(zulu=self.signature_timestamp, data=self.csf._export_base())
            if auth_cfs_size == align(auth_csf.cmd_data_reference.size, 4):
                updated = False

    def encrypt(self, image_data: bytes, blocks: list[ImageBlock]) -> bytes:
        """Encrypt the HAB image using AES-CCM encryption.

        The method encrypts specified blocks of the image data using the configured DEK (Data Encryption Key)
        and generates necessary MAC (Message Authentication Code) for verification. If no nonce is set,
        it will be automatically generated from the image data.

        :param image_data: Padding image binary data to be encrypted
        :param blocks: List of ImageBlock objects defining memory regions to encrypt
        :raises SPSDKError: When DEK is not set or encrypted data has invalid length
        :raises SPSDKValueError: When MAC length is not set or decrypt data command is not present
        :return: Encrypted image data without MAC and nonce
        """
        if self.dek is None:
            raise SPSDKError("Dek must be set.")
        if self.nonce is None:
            self.generate_nonce(image_data)
        assert self.nonce is not None
        if not self.mac_len:
            raise SPSDKValueError("Mac length not set.")
        command = self.get_decrypt_data_cmd()
        if command is None:
            raise SPSDKValueError("Decrypt data command not present.")
        data_to_encrypt = bytes()
        for block in blocks:
            command.append(block.base_address, block.size)
            data_to_encrypt += image_data[block.start : block.start + block.size]
        encr = aes_ccm_encrypt(
            key=self.dek,
            plain_data=data_to_encrypt,
            nonce=self.nonce,
            associated_data=bytes(),
            tag_len=self.mac_len,
        )
        if len(encr) != len(data_to_encrypt) + self.mac_len:
            raise SPSDKError("Invalid length of encrypted data")
        mac = encr[-self.mac_len :]
        enc_data = encr[: -self.mac_len]
        assert self.nonce is not None
        command.signature = MAC(
            version=self.csf.version,
            nonce_len=len(self.nonce),
            mac_len=self.mac_len,
            data=self.nonce + mac,
        )
        self.csf._header.length += len(blocks) * 8
        return enc_data

    def get_authenticate_csf_cmd(self) -> Optional[CmdAuthData]:
        """Get authenticate CSF segment command.

        Searches through all commands in the CSF segment to find the first
        CmdAuthData command that handles authentication operations.

        :return: First authenticate command found, or None if no such command exists.
        """
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[0] if len(commands) >= 1 else None

    def get_authenticate_data_cmd(self) -> Optional[CmdAuthData]:
        """Get authenticate image data command.

        Retrieves the second authenticate data command from the CSF commands list.
        This method filters commands to find CmdAuthData instances and returns the
        second one if available, which typically represents the authenticate image
        data command.

        :return: Second authenticate data command if at least two exist, None otherwise.
        """
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[1] if len(commands) >= 2 else None

    def get_decrypt_data_cmd(self) -> Optional[CmdAuthData]:
        """Get decrypt data command from CSF segment.

        Retrieves the third CmdAuthData command from the commands list, which represents
        the decrypt data command in the CSF (Command Sequence File) structure.

        :return: The decrypt data command if at least 3 CmdAuthData commands exist, None otherwise.
        """
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[2] if len(commands) >= 3 else None

    def save_dek(self) -> None:
        """Save DEK (Data Encryption Key) to file if conditions are met.

        The method searches for an InstallSecretKey command and saves the DEK key to the
        specified path if the key exists and either the file doesn't exist or contains
        different data than the current secret key.

        :raises SPSDKValueError: If there are issues with file operations during key saving.
        """
        install_key_cmd = next(
            (cmd for cmd in self.commands if isinstance(cmd, CmdInstallSecretKey)), None
        )
        if install_key_cmd is None:
            return
        if not install_key_cmd.secret_key_path:
            logger.warning("No secret key path specified for saving DEK")
            return
        if install_key_cmd.secret_key_path and install_key_cmd.secret_key:
            if (
                not find_file(install_key_cmd.secret_key_path, raise_exc=False)
                or load_binary(install_key_cmd.secret_key_path) != install_key_cmd.secret_key
            ):
                install_key_cmd.save_secret_key()
