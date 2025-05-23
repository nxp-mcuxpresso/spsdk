#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB CSF (Command Sequence File) segment implementation.

This module contains classes for creating, manipulating, and parsing
CSF segments used in High Assurance Boot (HAB) for NXP devices.
CSF contains commands for authentication and configuration operations
during the secure boot process.
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
    """Command Sequence File (CSF), signature block for Secure Boot.

    A script of commands used to guide image authentication and device configuration operations.
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
        """Initialize CSF segment."""
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
        """Test whether given class is instance of supported CSF command.

        :param cmd: instance to be tested
        :return: True if yes, False otherwise
        """
        return isinstance(cmd, CmdBase) and (cmd.tag in cls._COMMANDS)

    @property
    def version(self) -> int:
        """Version of CSF segment."""
        return self._header.param

    @property
    def commands(self) -> list[CmdBase]:
        """List of CSF commands in the segment."""
        return self._commands

    @property
    def size(self) -> int:
        """Size of the binary representation of the segment; 0 is not enabled."""
        if not self.enabled:
            return 0

        result = self._header.length
        for offset, cmd_data in self._cmd_data.items():
            result = max(result, offset + cmd_data.size)
        return result

    @property
    def space(self) -> int:
        """Size of the binary representation of the segment including padding; 0 is not enabled."""
        return self.size + self.padding_len if self.enabled else 0

    @property
    def macs(self) -> Iterator[MAC]:
        """Iterator of all MAC sections."""
        return filter(lambda m: isinstance(m, MAC), self._cmd_data.values())  # type: ignore

    def __repr__(self) -> str:
        return f"CSF <Commands: {len(self.commands)}>"

    def __len__(self) -> int:
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBase:
        return self.commands[key]

    def __setitem__(self, key: int, value: CmdBase) -> None:
        if not SegCSF._is_csf_command(value):
            raise SPSDKError("Invalid command")
        self._commands[key] = value

    def __iter__(self) -> Iterator[CmdBase]:
        return self.commands.__iter__()

    def __str__(self) -> str:
        """String representation of the SegCSF."""
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

        :param cmd: to be added
        :raises SPSDKError: If invalid command
        """
        if not SegCSF._is_csf_command(cmd):
            raise SPSDKError("Invalid command")
        self._commands.append(cmd)
        self._header.length += cmd.size
        self.update(False)

    def clear_commands(self) -> None:
        """Removes= all commands."""
        self._commands.clear()
        self._header.length = self._header.size
        self.update(True)

    def update(self, reset_cmddata_offsets: bool) -> None:
        """Update the offsets for the export.

        :param reset_cmddata_offsets: True to reset all cmd-data offsets, if cmd-data not specified in the command;
                                    False to avoid any reset;
                                    Note: reset should be done during parsing process as the data are incomplete

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
        """Export base part of the CSF section (header and commands) without keys and signatures.

        :return: exported binary data
        """
        self.update(True)
        data = self._header.export()
        for command in self.commands:
            cmd_data = command.export()
            data += cmd_data
        return data

    def update_signatures(self, zulu: datetime, data: bytes, base_data_addr: int) -> None:
        """Update signatures in all CmdAuthData commands.

        :param zulu: current UTC time+date
        :param data: currently generated binary data; empty to create "fake" signature to update size of the segment
        :param base_data_addr: base address of the generated data
        :raises SPSDKError: If invalid length of data
        :raises SPSDKError: If invalid length of data
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

        :return: bytes
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
        """Parse data for key installation or key authentication commands (certificate or signature).

        :param cmd: command with reference to a cmd-data
        :param data: binary data array to be parsed
        :return: parsed instance, either Certificate or Signature
        :raises SPSDKError: If invalid cmd
        :raises SPSDKError: If invalid cmd's data
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
        """Parse segment from bytes array.

        :param data: The bytes array of CSF segment
        :raises SPSDKCorruptedException: When there is unknown command
        :raises SPSDKCorruptedException: When command can not be parsed
        :return: SegCSF instance
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
    """CSF HAB segment class."""

    CSF_SIZE = 0x2000
    KEYBLOB_SIZE = 0x200
    SEGMENT_IDENTIFIER = HabSegmentEnum.CSF

    def __init__(self, csf: SegCSF, signature_timestamp: Optional[datetime] = None):
        """Initialization of CSF segment."""
        super().__init__()
        self.csf = csf
        self.signature_timestamp = signature_timestamp or datetime.now(timezone.utc)
        self.commands = self.csf.commands

    def update(self, reset_cmddata_offsets: bool) -> None:
        """Update the offsets for the export."""
        self.csf.update(reset_cmddata_offsets)

    def append_command(self, cmd: CmdBase) -> None:
        """Append CSF command to the segment."""
        self.csf.append_command(cmd)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the CSF HAB segment from HAB configuration.

        :param config: Hab configuration object
        :return: Instance of CSF HAB segment.
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
        """Export object into bytes array.

        :return: Raw binary block of segment
        """
        return align_block(self.csf.export(), self.CSF_SIZE)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse CSF segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :param family: Target device family revision
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
        """Get size of the segment."""
        return self.CSF_SIZE

    @property
    def mac_len(self) -> Optional[int]:
        """Mac length property."""
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            return None
        return decrypt_data.mac_len

    @property
    def nonce(self) -> Optional[bytes]:
        """Mac length property."""
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            return None
        return decrypt_data.nonce

    def generate_nonce(self, data: bytes) -> None:
        """Generate nonce corresponding to length of data to be encrypted."""
        decrypt_data = next((cmd for cmd in self.commands if isinstance(cmd, CmdDecryptData)), None)
        if decrypt_data is None:
            raise SPSDKValueError("No DecryptData command found in segments")
        decrypt_data.generate_nonce(data)

    @staticmethod
    def align_offset(image_len: int) -> int:
        """Calculate CSF offset from image length.

        :param image_len: Image length
        :return: CSF offset
        """
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000
        return csf_offset

    def update_signature(
        self, image_data: bytes, blocks: list[ImageBlock], base_data_address: int
    ) -> None:
        """Sign the HAB image and update the signature in CSF command.

        :param image_data: Padding image binary
        :param blocks: Blocks to be signed
        :param base_data_address: Base address corresponding to the actual start address
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
        """Encrypt the HAB image.

        :param image_data: Padding image binary
        :param blocks: Blocks to be encrypted
        :return: Encrypted image.
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
        """Get authenticate CSF segment command."""
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[0] if len(commands) >= 1 else None

    def get_authenticate_data_cmd(self) -> Optional[CmdAuthData]:
        """Get authenticate image data command."""
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[1] if len(commands) >= 2 else None

    def get_decrypt_data_cmd(self) -> Optional[CmdAuthData]:
        """Get decrypt data command."""
        commands = [cmd for cmd in self.commands if isinstance(cmd, CmdAuthData)]
        return commands[2] if len(commands) >= 3 else None

    def save_dek(self) -> None:
        """Save DEK key."""
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
