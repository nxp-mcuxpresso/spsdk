#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains code related to HAB segments."""

import logging
import os
from abc import abstractmethod
from datetime import datetime, timezone
from typing import Mapping, Optional, Type

from typing_extensions import Self

from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import aes_ccm_encrypt
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.commands import CmdAuthData
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.commands.commands import (
    COMMANDS_MAPPING,
    ImageBlock,
    SecCommandBase,
    SecCsfHeader,
)
from spsdk.image.hab.commands.commands_enum import SecCommand
from spsdk.image.hab.hab_config import HabConfig
from spsdk.image.images import BootImgRT
from spsdk.image.secret import MAC, Signature
from spsdk.image.segments import SegBDT, SegCSF, SegDCD, SegIVT2, SegXMCD, XMCDHeader
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import align, align_block, find_file, get_abs_path, load_binary, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class HabSegment(SpsdkEnum):
    """Enum definition for HAB segments."""

    IVT = (0, "ivt", "IVT segment")
    BDT = (1, "bdt", "BDT segment")
    DCD = (2, "dcd", "DCD segment")
    XMCD = (3, "xmcd", "XMCD segment")
    CSF = (4, "csf", "CSF segment")
    APP = (5, "app", "APP segment")


class HabSegmentBase:
    """Base class for individual HAB segment."""

    def __init__(self, offset: int) -> None:
        """HAB segment initialization.

        :param offset: Segment offset
        """
        self.offset = offset

    @abstractmethod
    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of HAB segment.
        """

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of HAB segment.
        """

    @property
    @abstractmethod
    def size(self) -> int:
        """Get size of the segment."""


class IvtHabSegment(HabSegmentBase):
    """IVT HAB segment class."""

    IVT_VERSION = 0x40
    OFFSET = 0x0

    def __init__(self, offset: int, segment: SegIVT2) -> None:
        """IVT HAB segment initialization.

        :param offset: Segment offset
        :param segment: Actual IVT segment
        """
        super().__init__(offset)
        self.segment: SegIVT2 = segment

    def __repr__(self) -> str:
        return "IVT HAB segment"

    def __str__(self) -> str:
        """Get info of IvtHabSegment as a string."""
        info = "IVT HAB segment"
        info += f" Offset:                      {self.offset}\n"
        info += str(self.segment)
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the IVT HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of IVT HAB segment.
        """
        segment = SegIVT2(cls.IVT_VERSION)
        segment.app_address = cls.get_entrypoint_address(
            config.options.entrypoint_address, config.app_image
        )
        segment.ivt_address = config.options.start_address + config.options.get_ivt_offset()
        segment.bdt_address = segment.ivt_address + segment.size
        if bool(config.options.flags >> 3):
            image_len = config.options.get_initial_load_size() + len(config.app_image)
            csf_offset = CsfHabSegment.align_offset(image_len)
            csf_offset = csf_offset - config.options.get_ivt_offset()
            segment.csf_address = segment.ivt_address + csf_offset
        else:
            segment.csf_address = 0
        if config.options.dcd_file_path:
            segment.dcd_address = segment.ivt_address + SegIVT2.SIZE + BootImgRT.BDT_SIZE
        return cls(cls.OFFSET, segment)

    @staticmethod
    def get_entrypoint_address(entrypoint_address: Optional[int], app_image: BinaryImage) -> int:
        """Get entrypoint address."""
        if entrypoint_address is not None:
            if (
                app_image.execution_start_address is not None
                and entrypoint_address != app_image.execution_start_address
            ):
                logger.warning(
                    f"Given entrypoint address {entrypoint_address:#x} does not match the "
                    f"execution start address {app_image.execution_start_address:#x}."
                )
            return entrypoint_address
        reset_vector = AppHabSegment.get_reset_vector(app_image.export())
        if app_image.execution_start_address is not None:
            if app_image.execution_start_address != reset_vector:
                logger.warning(
                    f"Execution start address {app_image.execution_start_address:#x} "
                    f"doesn't match the reset vector {reset_vector:#x} of the application."
                )
            return app_image.execution_start_address
        return reset_vector

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.segment.export()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse IVT segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of IVT segment.
        """
        segment = SegIVT2.parse(data)
        return cls(cls.OFFSET, segment)

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return self.segment.size


class BdtHabSegment(HabSegmentBase):
    """BDT HAB segment class."""

    def __init__(self, offset: int, segment: SegBDT) -> None:
        """BDT HAB segment initialization.

        :param offset: Segment offset
        :param segment: Actual BDT segment
        """
        super().__init__(offset)
        self.segment: SegBDT = segment

    def __repr__(self) -> str:
        return "BDT HAB segment"

    def __str__(self) -> str:
        """Get info of BdtHabSegment as a string."""
        info = "BDT HAB segment"
        info += f" Segment:                     {self.segment}\n"
        info += f" Offset:                      {self.offset}\n"
        info += str(self.segment)
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the BDT HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of BDT HAB segment.
        """
        segment = SegBDT(app_start=config.options.start_address)
        end_segments: dict[int, Type[HabSegmentBase]] = {
            0: AppHabSegment,
            1: CsfHabSegment,
        }
        end_seg_class = end_segments[(config.options.flags & 0xF) >> 3]
        end_seg = end_seg_class.load_from_config(config, search_paths)
        segment.app_length = config.options.get_ivt_offset() + end_seg.offset + end_seg.size
        offset = IvtHabSegment.OFFSET + SegIVT2.SIZE
        return cls(offset, segment)

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.segment.export()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse BDT segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of BDT HAB segment.
        """
        ivt = IvtHabSegment.parse(data)
        offset = ivt.segment.bdt_address - ivt.segment.ivt_address
        segment = SegBDT.parse(data[offset:])
        return cls(offset, segment)

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return BootImgRT.BDT_SIZE


class DcdHabSegment(HabSegmentBase):
    """DCD HAB segment class."""

    def __init__(self, offset: int, segment: SegDCD) -> None:
        """DCD HAB segment initialization.

        :param offset: Segment offset
        :param segment: Actual DCD segment
        """
        super().__init__(offset)
        self.segment = segment

    def __repr__(self) -> str:
        return "DCD HAB segment"

    def __str__(self) -> str:
        """Get info of Dcd Segment as a string."""
        info = "DCD HAB segment"
        info += f" Segment:                     {self.segment}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the DCD HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of DCD HAB segment.
        """
        offset = SegIVT2.SIZE + BootImgRT.BDT_SIZE
        if config.options.dcd_file_path is not None:
            dcd_bin = load_binary(config.options.dcd_file_path, search_paths=search_paths)
            segment = SegDCD.parse(dcd_bin)
            return cls(offset, segment)
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.segment.export()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse DCD segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of DCD HAB segment.
        """
        ivt = IvtHabSegment.parse(data)
        if ivt.segment.dcd_address:
            offset = ivt.segment.dcd_address - ivt.segment.ivt_address
            segment = SegDCD.parse(data[offset:])
            return cls(offset, segment)
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return self.segment.size


class XmcdHabSegment(HabSegmentBase):
    """XMCD HAB segment class."""

    OFFSET = 0x40

    def __init__(self, offset: int, segment: SegXMCD) -> None:
        """XMCD HAB segment initialization.

        :param offset: Segment offset
        :param segment: Actual XMCD segment
        """
        super().__init__(offset)
        self.segment = segment

    def __repr__(self) -> str:
        return "XMCD HAB segment"

    def __str__(self) -> str:
        """Get info of Xmcd Segment as a string."""
        info = "XMCD HAB segment"
        info += f" Segment:                     {self.segment}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the XMCD HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of XMCD HAB segment.
        """
        if config.options.xmcd_file_path is not None:
            xmcd_bin = load_binary(config.options.xmcd_file_path, search_paths=search_paths)
            segment = SegXMCD.parse(xmcd_bin)
            return cls(cls.OFFSET, segment)
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.segment.export()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse XMCD segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of XMCD HAB segment.
        """
        try:
            xmcd_header = XMCDHeader.parse(data[cls.OFFSET :])
            xmcd_data_offset = cls.OFFSET + XMCDHeader.SIZE
            xmcd_data = data[xmcd_data_offset : xmcd_data_offset + xmcd_header.config_data_size]
            segment = SegXMCD(header=xmcd_header, config_data=xmcd_data)
            return cls(cls.OFFSET, segment)
        except SPSDKParsingError as exc:
            raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present") from exc

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return self.segment.size


class CsfHabSegment(HabSegmentBase):
    """CSF HAB segment class."""

    CSF_SIZE = 0x2000
    KEYBLOB_SIZE = 0x200

    def __init__(
        self,
        offset: int,
        segment: SegCSF,
        dek: Optional[bytes] = None,
        mac_len: int = 16,
        nonce: Optional[bytes] = None,
        signature_timestamp: Optional[datetime] = None,
    ) -> None:
        """XMCD HAB segment initialization.

        :param offset: Segment offset
        :param commands: List of commands
        :param signature_timestamp: Signature timestamp
        """
        super().__init__(offset)
        self.segment = segment
        self.dek = dek
        self.mac_len = mac_len
        self.nonce = nonce
        self.signature_timestamp = signature_timestamp or datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return "CSF HAB segment"

    def __str__(self) -> str:
        """Get info of Csf Segment as a string."""
        info = "CSF HAB segment"
        info += f" Segment:                     {self.segment}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the CSF HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of CSF HAB segment.
        """
        image_len = config.options.get_initial_load_size() + len(config.app_image)
        offset = cls.align_offset(image_len)
        offset = offset - config.options.get_ivt_offset()
        if not config.commands:
            raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

        header = SecCsfHeader.load_from_config(config, search_paths=search_paths)
        commands: list[SecCommandBase] = []
        for cmd_config in config.commands:
            if cmd_config.index in [SecCommand.HEADER.tag, SecCommand.INSTALL_NOCAK.tag]:
                continue
            command_class = COMMANDS_MAPPING.get(SecCommand.from_tag(cmd_config.index))
            if not command_class:
                raise SPSDKValueError(f"Command with index does not exist {cmd_config.index}")
            commands.append(command_class.load_from_config(config, search_paths=search_paths))
        segment = SegCSF(enabled=True, version=header.version)
        for command in commands:
            segment.append_command(command.cmd)
        segment.update(True)
        return cls(
            offset=offset,
            segment=segment,
            dek=cls.get_dek_from_config(config, search_paths),
            mac_len=cls.get_mac_len_from_config(config),
            nonce=cls.get_nonce_from_config(config, search_paths),
            signature_timestamp=config.options.signature_timestamp,
        )

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return align_block(self.segment.export(), self.CSF_SIZE)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse CSF segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of CSF HAB segment.
        """
        ivt = IvtHabSegment.parse(data)
        if ivt.segment.csf_address:
            offset = ivt.segment.csf_address - ivt.segment.ivt_address
            segment = SegCSF.parse(data[offset : offset + cls.CSF_SIZE])
            mac_obj = next(segment.macs, None)
            nonce = mac_obj.nonce if mac_obj else None
            mac_len = mac_obj.mac_len if mac_obj else 16
            dek = bytes([0]) * MAC.AES128_BLK_LEN
            return cls(segment=segment, offset=offset, dek=dek, nonce=nonce, mac_len=mac_len)
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return self.CSF_SIZE

    @property
    def mac_len(self) -> int:
        """Mac length property."""
        return self._mac_len

    @mac_len.setter
    def mac_len(self, value: int) -> None:
        """Mac length property setter."""
        if value < 4 or value > 16 or value % 2:
            raise SPSDKValueError(
                "Invalid mac length. Valid options are 4, 6, 8, 10, 12, 14 and 16."
            )
        self._mac_len = value

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
        if not self.segment:
            raise SPSDKValueError("CSF segment is not defined")
        auth_data = self.get_authenticate_data_cmd()
        if auth_data is None:
            raise SPSDKValueError("Authenticate data command not present.")
        for block in blocks:
            auth_data.append(block.base_address, block.size)
            self.segment._header.length += 8
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
            auth_csf.update_signature(
                zulu=self.signature_timestamp, data=self.segment._export_base()
            )
            if auth_cfs_size == align(auth_csf.cmd_data_reference.size, 4):
                updated = False

    def encrypt(self, image_data: bytes, blocks: list[ImageBlock]) -> bytes:
        """Encrypt the HAB image.

        :param image_data: Padding image binary
        :param blocks: Blocks to be encrypted
        :return: Encrypted image.
        """
        if not self.segment:
            raise SPSDKValueError("CSF segment is not defined")
        if self.dek is None:
            raise SPSDKError("Dek must be set.")
        if self.nonce is None:
            self.nonce = self.generate_nonce(image_data)
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

        command.signature = MAC(
            version=self.segment.version,
            nonce_len=len(self.nonce),
            mac_len=self.mac_len,
            data=self.nonce + mac,
        )
        self.segment._header.length += len(blocks) * 8
        return enc_data

    def get_authenticate_csf_cmd(self) -> Optional[CmdAuthData]:
        """Get authenticate CSF segment command."""
        commands = [cmd for cmd in self.segment.commands if isinstance(cmd, CmdAuthData)]
        return commands[0] if len(commands) >= 1 else None

    def get_authenticate_data_cmd(self) -> Optional[CmdAuthData]:
        """Get authenticate image data command."""
        commands = [cmd for cmd in self.segment.commands if isinstance(cmd, CmdAuthData)]
        return commands[1] if len(commands) >= 2 else None

    def get_decrypt_data_cmd(self) -> Optional[CmdAuthData]:
        """Get decrypt data command."""
        commands = [cmd for cmd in self.segment.commands if isinstance(cmd, CmdAuthData)]
        return commands[2] if len(commands) >= 3 else None

    @staticmethod
    def get_dek_from_config(
        config: HabConfig, search_paths: Optional[list[str]] = None
    ) -> Optional[bytes]:
        """Get dek binary from configuration if exists, None otherwise."""
        if not config.commands.contains(SecCommand.INSTALL_SECRET_KEY):
            return None
        params = config.commands.get_command_params(SecCommand.INSTALL_SECRET_KEY)
        length = int(params.get("SecretKey_Length", 128))
        if length not in [128, 192, 256]:
            raise SPSDKValueError(f"Invalid sectet key length {length}")
        reuse_dek = bool(params.get("SecretKey_ReuseDek", 0) == 1)
        key_length = length // 8
        if reuse_dek:
            secret_key_path = find_file(params["SecretKey_Name"], search_paths=search_paths)
            secret_key = load_binary(secret_key_path)
            if len(secret_key) != key_length:
                raise SPSDKError(
                    f"Loaded secret key length does not match the expected length: {length}"
                )
        else:
            base_dir = search_paths[0] if search_paths else os.getcwd()
            secret_key_path = get_abs_path(params["SecretKey_Name"], base_dir)
            secret_key = random_bytes(key_length)
            write_file(secret_key, secret_key_path, "wb")
        return secret_key

    @staticmethod
    def get_nonce_from_config(
        config: HabConfig, search_paths: Optional[list[str]] = None
    ) -> Optional[bytes]:
        """Get nonce binary from configuration if exists, None otherwise."""
        if not config.commands.contains(SecCommand.DECRYPT_DATA):
            return None
        params = config.commands.get_command_params(SecCommand.DECRYPT_DATA)
        nonce = params.get("Decrypt_Nonce")
        if not nonce:
            return None
        return load_binary(nonce, search_paths=search_paths)

    @staticmethod
    def get_mac_len_from_config(config: HabConfig, default: int = 16) -> int:
        """Get mac length from configuration."""
        if not config.commands.contains(SecCommand.DECRYPT_DATA):
            return default
        params = config.commands.get_command_params(SecCommand.DECRYPT_DATA)
        return int(params.get("Decrypt_MacBytes", default))

    @staticmethod
    def generate_nonce(encryption_data: bytes) -> bytes:
        """Generate nonce corresponding to length of data to be encrypted."""
        nonce_len = BootImgRT.aead_nonce_len(len(encryption_data))
        return random_bytes(nonce_len)


class AppHabSegment(HabSegmentBase):
    """APP HAB segment class."""

    def __init__(self, offset: int, binary: bytes) -> None:
        """XMCD HAB segment initialization.

        :param offset: Segment offset
        :param binary: Application binary
        """
        super().__init__(offset)
        self.binary = binary

    def __repr__(self) -> str:
        return "APP HAB segment"

    def __str__(self) -> str:
        """Get info of App Segment as a string."""
        info = "CSF APP segment"
        info += f" Length:                      {len(self.binary)}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load the APP HAB segment from HAB configuration.

        :param config: Hab configuration object
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of APP HAB segment.
        """
        app_bin = config.app_image.export()
        if (config.options.flags & 0xF) >> 3:
            app_bin = align_block(app_bin, 16)
        offset = config.options.get_initial_load_size() - config.options.get_ivt_offset()
        return cls(offset, app_bin)

    def export(self) -> bytes:
        """Serialize object into bytes array.

        :return: Raw binary block of segment
        """
        return self.binary

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse APP segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of APP HAB segment.
        """
        ivt = IvtHabSegment.parse(data)

        def get_app_offset() -> int:
            """Get app offset from known possible offsets."""
            known_offsets = [0x100, 0x400, 0xC00, 0x1000, 0x2000]
            for offset in known_offsets:
                logger.debug(f"Testing the potential application on offset {offset}")
                reset_vector = cls.get_reset_vector(data[offset:])
                if reset_vector == 0:
                    logger.debug("The reset vector cannot be 0x0")
                    continue
                # there are some cases where the reset vector and the entrypoint address are not same
                # reset vector inside the given range is accepted
                range_start = ivt.segment.app_address - 0x400
                range_end = ivt.segment.app_address + len(data)
                if reset_vector not in range(range_start, range_end):
                    logger.debug(
                        f"The reset vector {reset_vector:#x} is not inside the range {range_start:#x}:{range_end:#x}"
                    )
                    continue
                if not reset_vector % 2:
                    logger.debug(
                        "The least significant bit is not set to 1, indicating Thumb state execution"
                    )
                    continue
                return offset
            raise SPSDKParsingError("Application offset could not be found")

        offset = get_app_offset()
        end = (
            ivt.segment.csf_address - ivt.segment.ivt_address
            if ivt.segment.csf_address > 0
            else len(data)
        )
        binary = data[offset:end]
        return cls(offset, binary)

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return len(self.binary)

    @staticmethod
    def get_reset_vector(data: bytes) -> int:
        """Get application reset vector."""
        return int.from_bytes(data[4:8], "little")

    @staticmethod
    def get_stack_pointer(data: bytes) -> int:
        """Get application reset vector."""
        return int.from_bytes(data[0:4], "little")


class HabSegments(list[HabSegmentBase]):
    """Extension of segments list."""

    def get_segment(self, segment: HabSegment) -> HabSegmentBase:
        """Get HAB segment.

        :param segment: HAB segment
        :raises SPSDKSegmentNotPresent: If HAB segment not found.
        :return: HAB segment instance
        """
        for seg in self:
            if isinstance(seg, SEGMENTS_MAPPING[segment]):
                assert isinstance(seg, SEGMENTS_MAPPING[segment])
                return seg
        raise SPSDKSegmentNotPresent(f"Segment '{segment.label}'is not present in the image.")

    def contains(self, segment: HabSegment) -> bool:
        """Return True if the segment exists and is defined, false otherwise."""
        try:
            self.get_segment(segment)
            return True
        except SPSDKSegmentNotPresent:
            return False


SEGMENTS_MAPPING: Mapping[HabSegment, Type[HabSegmentBase]] = {
    HabSegment.IVT: IvtHabSegment,
    HabSegment.BDT: BdtHabSegment,
    HabSegment.DCD: DcdHabSegment,
    HabSegment.XMCD: XmcdHabSegment,
    HabSegment.CSF: CsfHabSegment,
    HabSegment.APP: AppHabSegment,
}
