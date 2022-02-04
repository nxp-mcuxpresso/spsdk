#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Segments within image module."""

import logging
from abc import ABC
from datetime import datetime
from struct import calcsize, pack, unpack_from
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

from spsdk import SPSDKError
from spsdk.utils.misc import DebugInfo, align, align_block, extend_block, size_fmt

from .bee import BEE_ENCR_BLOCK_SIZE, BeeRegionHeader
from .commands import (
    CmdAuthData,
    CmdBase,
    CmdCheckData,
    CmdNop,
    CmdTag,
    CmdUnlock,
    CmdWriteData,
    EnumCheckOps,
    EnumEngine,
    EnumWriteOps,
    parse_command,
)
from .header import CorruptedException, Header, Header2, SegTag
from .secret import MAC, BaseClass

logger = logging.getLogger(__name__)


########################################################################################################################
# Base Segment Class
########################################################################################################################


class BaseSegment(ABC):
    """Base segment."""

    # padding fill value
    PADDING_VALUE = 0x00

    @property
    def padding_len(self) -> int:
        """Length of padding data in bytes (zero for no padding)."""
        return self.padding

    @padding_len.setter
    def padding_len(self, value: int) -> None:
        """New length (in bytes) of padding applied at the end of exported data."""
        if value < 0:
            raise SPSDKError("Length of padding must be >= 0")
        self.padding = value

    @property
    def space(self) -> int:
        """Return length (in bytes) of the exported data including padding (if any).

        Please mind, padding is exported optionally.
        """
        return self.size + self.padding_len

    @property
    def size(self) -> int:
        """Size of base segment."""
        return 0

    def _padding_export(self) -> bytes:
        """Padding binary data, see `padding_len` for length."""
        return bytes([self.PADDING_VALUE] * self.padding_len) if self.padding_len > 0 else b""

    def __init__(self) -> None:
        """Initialize the base  segment."""
        self.padding = 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def info(self) -> str:
        """String representation of the BaseSegment.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def export(self) -> bytes:
        """Export interface.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def parse(cls, buffer: bytes) -> "BaseSegment":
        """Parse interfaces.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")


########################################################################################################################
# Boot Image V1 Segments (i.MX5)
########################################################################################################################

# Obsolete, will not be implemented


########################################################################################################################
# Boot Image V2 Extra Segments for i.MX-RT
########################################################################################################################
class AbstractFCB(BaseSegment):
    """Abstract class, predecessor for all FCB classes."""

    TAG = b"FCB"

    def __init__(self) -> None:
        """Constructor."""
        super().__init__()
        self._enabled = True

    @property
    def enabled(self) -> bool:
        """Whether FCB is enabled. Note: it is not generated to output is disabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Setter.

        :param value: whether FCB is enabled
        """
        self._enabled = value

    @property
    def space(self) -> int:
        """Return length (in bytes) of the exported data including padding (if any)."""
        return super(AbstractFCB, self).space if self.enabled else 0

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary representation (serialization).

        :param dbg_info: instance allowing to debug output
        :return: binary representation
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")


class SegFCB(AbstractFCB, ABC):
    """FCB."""

    SIZE = 1024
    FINGERPRINT = b"NFCB"

    @property
    def crc(self) -> int:
        """Cyclic redundancy check."""
        return 0

    def __init__(self) -> None:
        """Initialize FCB segment."""
        super().__init__()
        self.version = 1
        self.search_start_page = 0
        self.search_stride = 0
        self.search_count = 0
        self.firmware_copies = 0
        self.firmware_info_table = None
        self.config_block = None

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form."""
        data = pack(
            "<Is2I2HI",
            self.crc,
            self.FINGERPRINT,
            self.version,
            self.search_start_page,
            self.search_stride,
            self.search_count,
            self.firmware_copies,
        )
        # Reserved 40 bytes for future use, must be set to 0
        data += b"\x00" * 40
        if self.firmware_info_table:
            data += self.firmware_info_table
        # Reserved 128 bytes, must be set to 0
        data += b"\x00" * 128
        if self.config_block:
            data += self.config_block
        # Reserved 256 bytes, must be set to 0
        data += b"\x00" * 256
        return data


class PaddingFCB(AbstractFCB):
    """Padding FCB."""

    def __init__(self, size: int, padding_value: int = 0, enabled: bool = True):
        """Constructor.

        :param size: of the exported padding
        :param padding_value: byte value used as padding; 0 by default
        :param enabled: whether enabled
        :raises SPSDKError: If invalid size of the exported padding
        :raises SPSDKError: If invalid padding
        """
        super().__init__()
        if size < 0 or size > 0xFFFF:
            raise SPSDKError("Invalid size of the exported padding")
        if padding_value < 0 or padding_value > 0xFF:
            raise SPSDKError("Invalid padding")
        self._size = size
        self._padding_byte = bytes([padding_value])
        self.enabled = enabled

    @property
    def size(self) -> int:
        """Return size of the exported data in bytes."""
        return self._size if self.enabled else 0

    def info(self) -> str:
        """Return text description of the instance."""
        return f"PaddingFCB: {self.size} bytes"

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: instance allowing to debug output format
        :return: binary representation
        """
        if not self.enabled:
            return b""

        result = self._padding_byte * self._size + self._padding_export()
        dbg_info.append_section(f"FCB-padding: {len(result)} bytes")
        return result


# pylint: disable=too-many-instance-attributes
class FlexSPIConfBlockFCB(AbstractFCB):
    """Flex SPI configuration block; FCB."""

    # tag used in header to be able identify the block
    TAG = b"FCFB"
    # default version
    VERSION = b"V\x01\x00\x00"
    # format for the export
    FORMAT = "<6BH7I5I4B2I4I6I4H"

    def __init__(self) -> None:
        """Initialize FlexSPIConfBlockFCB."""
        super().__init__()
        self.version = self.VERSION
        # ### Fields descriptions are taken from RT1050 manual ###

        # [00C:8-bit] 0 = internal loopback; 1 = loopback from DQS pad; 3 = Flash provided DQS
        self.read_sample_clk_src = 0
        # [00D:8-bit] Serial Flash CS Hold Time Recommend default value is 0x03
        self.cs_hold_time = 3
        # [00E:8-bit] Serial Flash CS setup time. Recommended default value is 0x03
        self.cs_setup_time = 3
        # [00F:8-bit] 3 = For HyperFlash; 12/13 = For Serial NAND, see datasheet to find correct value; 0=Other devices
        self.column_address_width = 0
        # [010:8-bit] Device Mode Configuration Enable feature (0 – Disabled, 1 – Enabled)
        self.device_mode_cfg_enable = 0
        # [011:8-bit] Reserved
        self.device_mode_type = 0
        # [012:16-bit] Wait time for all configuration commands, unit 100us.
        # Available for device that support v1.1.0 FlexSPI configuration block. If it is greater than 0, ROM will wait
        # waitTimeCfgCommands * 100us for all device memory configuration commands instead of using read status to wait
        # until these commands complete.
        self.wait_time_cfg_commands = 0
        # [014:32-bit] Sequence parameter for device mode configuration
        # Bit[7:0] - number of LUT sequences for Device mode configuration command
        # Bit[15:8] - starting LUT index of Device mode configuration command
        # Bit[31:16] - must be 0
        self.device_mode_seq = 0
        # [018:32-bit] Device Mode argument, effective only when device_mode_cfg_enable = 1
        self.device_mode_arg = 0
        # [01C:32-bit] Config Command Enable feature (0 – Disabled, 1 – Enabled)
        self.config_cmd_enable = 0
        # [020:3 x 32-bit] Sequences for Config Command, allow 3 separate configuration command sequences.
        self.config_cmd_0 = 0
        self.config_cmd_1 = 0
        self.config_cmd_2 = 0
        # [02C:32-bit] reserved
        # [030:3 x 32-bit] Arguments for each separate configuration command sequence
        self.cfg_cmd_arg_0 = 0
        self.cfg_cmd_arg_1 = 0
        self.cfg_cmd_arg_2 = 0
        # [03C:32-bit] reserved
        # [040:32-bit]
        # Bit0 – differential clock enable
        # Bit1 – CK2 enable, must set to 0 in this silicon
        # Bit2 – ParallelModeEnable, must set to 0 for this silicon
        # Bit3 – wordAddressableEnable
        # Bit4 – Safe Configuration Frequency enable set to 1 for the devices that support DDR Read instructions
        # Bit5 – Pad Setting Override Enable
        # Bit6 – DDR Mode Enable, set to 1 for device supports DDR read command
        self.controller_misc_option = 0
        # [044:8-bit] 1 – Serial NOR, 2 – Serial NAND
        self.device_type = 0
        # [045:8-bit] 1 – Single pad; 2 – Dual pads; 4 – Quad pads; 8 – Octal pads
        self.sflash_pad_type = 0
        # [046:8-bit] Chip specific value, for RT1050
        # 1 – 30 MHz; 2 – 50 MHz; 3 – 60 MHz; 4 – 75 MHz; 5 – 80 MHz; 6 – 100 MHz; 7 – 133 MHz; 8 – 166 MHz;
        # Other value: 30 MHz
        self.serial_clk_freq = 0
        # [047:8-bit] 0=Use predefined LUT sequence index and number;
        #             1=Use LUT sequence parameters provided in this block
        self.lut_custom_seq_enable = 0
        # [048:8B] reserverd
        # [050:4x32-bit] For SPI NOR, need to fill with actual size; For SPI NAND, need to fill with actual size * 2
        self.sflash_a1_size = 0
        self.sflash_a2_size = 0
        self.sflash_b1_size = 0
        self.sflash_b2_size = 0
        # [060:4x32-bit] Set to 0 if it is not supported
        self.cs_pad_setting_override = 0
        self.sclk_pad_setting_override = 0
        self.data_pad_setting_override = 0
        self.dqs_pad_setting_override = 0
        # [070:32-bit] Maximum wait time during read busy status
        # 0 – Disabled timeout checking feature; Other value – Timeout if the wait time exceeds this value.
        self.timeout_in_ms = 0
        # [074:32-bit] Unit: ns; RT1050: Currently, it is used for SPI NAND only at high frequency
        self.command_interval = 0
        # [078:2x16-bit] Time from clock edge to data valid edge. unit 0.1 ns. This field is used when the FlexSPI Root
        # clock is less than 100 MHz and the read sample clock source is device provided DQS signal without CK2 support.
        self.data_valid_time_dlla = 0
        self.data_valid_time_dllb = 0
        # [07C:16-bit] busy bit offset, valid range 0-31
        self.busy_offset = 0
        # [07E:16-bit] 0 – busy bit is 1 if device is busy; 1 – busy bit is 0 if device is busy
        self.busy_bit_polarity = 0
        # [080:256B] Lookup table
        self.lookup_table = b"\x00" * 256
        # [180:48B] Customized LUT sequence
        self.lut_custom_seq = b"\x00" * 48
        # [1B0:16B] reserved
        self.reserved_padding1 = b"\x00" * 16
        self.reserved_padding2 = b"\x00" * 64

    @property
    def size(self) -> int:
        """Length of the binary exported data without padding."""
        if not self.enabled:
            return 0

        return (
            len(self.export_header())
            + calcsize(self.FORMAT)
            + len(self.lookup_table)
            + len(self.lut_custom_seq)
            + len(self.reserved_padding1)
            + len(self.reserved_padding2)
        )

    def export_header(self) -> bytes:
        """Export FCB header info binary form."""
        return self.TAG + self.version[::-1] + b"\x00\x00\x00\x00"

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export into binary form.

        :param dbg_info: instance allowing to debug output
        :return: binary representation used in the bootable image
        """
        if not self.enabled:
            return b""

        data = self.export_header()
        data += pack(
            self.FORMAT,
            # B
            self.read_sample_clk_src,
            self.cs_hold_time,
            self.cs_setup_time,
            self.column_address_width,
            self.device_mode_cfg_enable,
            self.device_mode_type,
            # H
            self.wait_time_cfg_commands,
            # I
            self.device_mode_seq,
            self.device_mode_arg,
            self.config_cmd_enable,
            self.config_cmd_0,
            self.config_cmd_1,
            self.config_cmd_2,
            0,
            # I
            self.cfg_cmd_arg_0,
            self.cfg_cmd_arg_1,
            self.cfg_cmd_arg_2,
            0,
            self.controller_misc_option,
            # B
            self.device_type,
            self.sflash_pad_type,
            self.serial_clk_freq,
            self.lut_custom_seq_enable,
            # I
            0,
            0,
            # I
            self.sflash_a1_size,
            self.sflash_a2_size,
            self.sflash_b1_size,
            self.sflash_b2_size,
            # I
            self.cs_pad_setting_override,
            self.sclk_pad_setting_override,
            self.data_pad_setting_override,
            self.dqs_pad_setting_override,
            self.timeout_in_ms,
            self.command_interval,
            # H
            self.data_valid_time_dlla,
            self.data_valid_time_dllb,
            self.busy_offset,
            self.busy_bit_polarity,
        )
        data += (
            self.lookup_table
            + self.lut_custom_seq
            + self.reserved_padding1
            + self.reserved_padding2
        )

        dbg_info.append_binary_section("FCB", data)

        if self.padding_len > 0:
            data += self._padding_export()
            dbg_info.append_section(f"FCB-padding: {self.padding_len} bytes")

        return data

    def info(self) -> str:
        """String representation of the FlexSPIConfBlockFCB."""
        if not self.enabled:
            return " No FCB\n\n"
        msg = f" Length: {self.size} bytes\n"
        msg += "\n"
        return msg

    @classmethod
    def parse(cls, buffer: bytes) -> "FlexSPIConfBlockFCB":
        """Parse binary data and creates instance of the class.

        :param buffer: data to be parsed
        :return: instance of the class representing the data
        :raises SPSDKError: If data are not valid Flex SPI configuration block
        """
        if buffer[:4] != FlexSPIConfBlockFCB.TAG:
            raise SPSDKError("TAG does not match: " + buffer[:4].hex())

        version = buffer[7:3:-1]
        if (
            (version[0] != ord("V"))
            or (version[1] != 1)
            or (version[2] not in range(0, 9))
            or (version[3] not in range(0, 9))
        ):
            raise SPSDKError("Invalid version number format")

        result = FlexSPIConfBlockFCB()
        if len(buffer) < result.size:
            raise SPSDKError("Insufficient data length")

        offset = len(result.export_header())
        result.version = version
        (  # B
            result.read_sample_clk_src,
            result.cs_hold_time,
            result.cs_setup_time,
            result.column_address_width,
            result.device_mode_cfg_enable,
            result.device_mode_type,
            # H
            result.wait_time_cfg_commands,
            # I
            result.device_mode_seq,
            result.device_mode_arg,
            result.config_cmd_enable,
            result.config_cmd_0,
            result.config_cmd_1,
            result.config_cmd_2,
            _reserved1,
            # I
            result.cfg_cmd_arg_0,
            result.cfg_cmd_arg_1,
            result.cfg_cmd_arg_2,
            _reserved2,
            result.controller_misc_option,
            # B
            result.device_type,
            result.sflash_pad_type,
            result.serial_clk_freq,
            result.lut_custom_seq_enable,
            # I
            _reserved3,
            _reserved4,
            # I
            result.sflash_a1_size,
            result.sflash_a2_size,
            result.sflash_b1_size,
            result.sflash_b2_size,
            # I
            result.cs_pad_setting_override,
            result.sclk_pad_setting_override,
            result.data_pad_setting_override,
            result.dqs_pad_setting_override,
            result.timeout_in_ms,
            result.command_interval,
            # H
            result.data_valid_time_dlla,
            result.data_valid_time_dllb,
            result.busy_offset,
            result.busy_bit_polarity,
        ) = unpack_from(FlexSPIConfBlockFCB.FORMAT, buffer, offset)
        offset += calcsize(FlexSPIConfBlockFCB.FORMAT)
        # lookup table
        result.lookup_table = buffer[offset : offset + len(result.lookup_table)]
        offset += len(result.lookup_table)
        # lookup table
        result.lut_custom_seq = buffer[offset : offset + len(result.lut_custom_seq)]
        offset += len(result.lut_custom_seq)
        # reserved padding
        result.reserved_padding1 = buffer[offset : offset + len(result.reserved_padding1)]
        offset += len(result.reserved_padding1)
        result.reserved_padding2 = buffer[offset : offset + len(result.reserved_padding2)]

        return result


########################################################################################################################
# KIB and PRDB (i.MX-RT) for BEE Encrypted XIP mode
########################################################################################################################


class SegBEE(BaseSegment):
    """BEE keys and regions segment."""

    @property
    def size(self) -> int:
        """:return: size of the exported binary data in bytes."""
        result = 0
        for region in self._regions:
            result += region.size
        return result

    def __init__(self, regions: Sequence[BeeRegionHeader], max_facs: int = 3):
        """Constructor.

        :param regions: list of regions
        :param max_facs: maximum total number of FAC in all regions, used for validation
        """
        super().__init__()
        self._regions = list(regions)
        self.max_facs = max_facs

    def add_region(self, region: BeeRegionHeader) -> None:
        """Add region.

        :param region: to be added
        """
        self._regions.append(region)

    def info(self) -> str:
        """:return: test description of the instance."""
        result = f"BEE Segment, with {len(self._regions)} regions\n"
        for region in self._regions:
            result += region.info()
        return result

    def update(self) -> None:
        """Updates internal fields of the instance."""
        for region in self._regions:
            region.update()

    def validate(self) -> None:
        """Validates settings of the instance.

        :raises SPSDKError: If number of FAC regions exceeds the limit
        """
        total_facs = 0
        for region in self._regions:
            region.validate()
            total_facs += len(region.fac_regions)
        if total_facs > self.max_facs:
            raise SPSDKError(
                f"Totally {total_facs} FAC regions, but only {self.max_facs} supported"
            )

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Serialization to binary representation.

        :param dbg_info: instance allowing to provide debug info about exported data
        :return: binary representation of the region (serialization).
        """
        self.update()
        self.validate()
        result = b""
        for index, region in enumerate(self._regions):
            dbg_info.append_section(f"BEE Region {index}")
            result += region.export(dbg_info=dbg_info)
        if self.padding_len:
            result += self._padding_export()
            if self.size == 0:
                dbg_info.append_section(f"BEE-padding {self.padding_len} bytes")

        return result

    @classmethod
    def parse(cls, data: bytes, offset: int = 0, decrypt_keys: List[bytes] = list()) -> "SegBEE":
        """Deserialization.

        :param data: binary data to be parsed
        :param offset: to start parsing the data
        :param decrypt_keys: list of SW_GP keys used to decrypt EKIB
                The number of keys must match number of regions to be parsed
        :return: instance created from binary data
        """
        regions: List[BeeRegionHeader] = list()
        for sw_gp_key in decrypt_keys:
            region = BeeRegionHeader.parse(data, offset, sw_gp_key)
            regions.append(region)
            offset += region.size
        return SegBEE(regions)

    def encrypt_data(self, start_addr: int, data: bytes) -> bytes:
        """Encrypt image data located in any PRDB block.

        :param start_addr: start address of the data; must be aligned to block size
        :param data: to be encrypted
        :return: encrypted data, aligned to block size; blocks outside any FAC region kept untouched
        :raises SPSDKError: If invalid start address
        """
        if align(start_addr, BEE_ENCR_BLOCK_SIZE) != start_addr:
            raise SPSDKError("Invalid start address")
        orig_len = len(data)
        data = align_block(data, BEE_ENCR_BLOCK_SIZE)
        result = bytes()
        offset = 0
        while offset < len(data):
            blck = data[offset : offset + BEE_ENCR_BLOCK_SIZE]
            for region in self._regions:
                blck = region.encrypt_block(start_addr + offset, blck)
            result += blck
            offset += BEE_ENCR_BLOCK_SIZE
        return result[:orig_len]


########################################################################################################################
# Boot Image V2 Segments (i.MX-RT, i.MX6, i.MX7, i.MX8M)
########################################################################################################################
class SegIVT2(BaseSegment):
    """Image Vector Table, IVT2 segment."""

    FORMAT = "<7L"
    SIZE = Header.SIZE + calcsize(FORMAT)

    @property
    def version(self) -> int:
        """The version of IVT and Image format."""
        return self._header.param

    @version.setter
    def version(self, value: int) -> None:
        """The version of IVT and Image format."""
        if value < 0x40 or value >= 0x4F:
            raise SPSDKError("Invalid version of IVT and image format")
        self._header.param = value

    @property
    def size(self) -> int:
        """Size of the binary data."""
        return self._header.length

    def __init__(self, version: int) -> None:
        """Initialize IVT2 segment.

        :param version: The version of IVT and Image format
        """
        super().__init__()
        self._header = Header(SegTag.IVT2, version)
        self._header.length = self.SIZE
        self.app_address = 0
        self.rs1 = 0
        self.dcd_address = 0
        self.bdt_address = 0
        self.ivt_address = 0
        self.csf_address = 0
        self.rs2 = 0

    def __repr__(self) -> str:
        return "IVT2 <IVT:0x{:X}, BDT:0x{:X}, DCD:0x{:X}, APP:0x{:X}, CSF:0x{:X}>".format(
            self.ivt_address,
            self.bdt_address,
            self.dcd_address,
            self.app_address,
            self.csf_address,
        )

    def info(self) -> str:
        """String representation of the SegIVT2."""
        msg = ""
        msg += f" Format version   : {_format_ivt_item(self.version, digit_count=2)}\n"
        msg += f" IVT start address: {_format_ivt_item(self.ivt_address)}\n"
        msg += f" BDT start address: {_format_ivt_item(self.bdt_address)}\n"
        msg += f" DCD start address: {_format_ivt_item(self.dcd_address)}\n"
        msg += f" APP entry point  : {_format_ivt_item(self.app_address)}\n"
        msg += f" CSF start address: {_format_ivt_item(self.csf_address)}\n"
        msg += "\n"
        return msg

    def validate(self) -> None:
        """Validate settings of the segment.

        :raises SPSDKError: If there is configuration problem
        """
        if self.ivt_address == 0 or self.bdt_address == 0 or self.bdt_address < self.ivt_address:
            raise SPSDKError("Not valid IVT/BDT address")
        if self.dcd_address and self.dcd_address < self.ivt_address:
            raise SPSDKError(
                "Not valid DCD address: 0x{:X} < 0x{:X}".format(self.dcd_address, self.ivt_address)
            )
        # TODO: resolve commented code: if self.app_address and self.app_address < self.ivt_address:
        #  raise SPSDKError("Not valid APP address: 0x{:X} < 0x{:X}".format(self.app_address, self.ivt_address))
        if self.csf_address and self.csf_address < self.ivt_address:
            raise SPSDKError(
                "Not valid CSF address: 0x{:X} < 0x{:X}".format(self.csf_address, self.ivt_address)
            )
        if self.padding > 0:
            raise SPSDKError("IVT padding should be zero: {}".format(self.padding))

    def export(self) -> bytes:
        """Export to binary representation (serialization).

        :return: segment exported as binary data
        """
        self.validate()

        data = self._header.export()
        data += pack(
            self.FORMAT,
            self.app_address,
            self.rs1,
            self.dcd_address,
            self.bdt_address,
            self.ivt_address,
            self.csf_address,
            self.rs2,
        )

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegIVT2":
        """Parse segment from bytes array.

        :param data: The bytes array of IVT2 segment
        :return: SegIVT2 object
        """
        header = Header.parse(data, 0, SegTag.IVT2)
        obj = cls(header.param)
        # Parse IVT items
        (
            obj.app_address,
            obj.rs1,
            obj.dcd_address,
            obj.bdt_address,
            obj.ivt_address,
            obj.csf_address,
            obj.rs2,
        ) = unpack_from(cls.FORMAT, data, header.size)
        # Calculate IVT padding (should be zero)
        obj.padding = obj.bdt_address - obj.ivt_address - obj.size
        # Validate parsed values
        obj.validate()
        return obj


class SegBDT(BaseSegment):
    """Boot Data Table segment."""

    FORMAT = "<3L"
    SIZE = calcsize(FORMAT)

    @property
    def plugin(self) -> int:
        """Plugin."""
        return self._plugin

    @plugin.setter
    def plugin(self, value: int) -> None:
        if value not in (0, 1, 2):
            raise SPSDKError("Plugin value must be 0 .. 2")
        self._plugin = value

    @property
    def size(self) -> int:
        """Size of the exported binary data (without padding)."""
        return self.SIZE

    def __init__(self, app_start: int = 0, app_length: int = 0, plugin: int = 0) -> None:
        """Initialize BDT segment.

        :param app_start: first address of the application
        :param app_length: length of the application
        :param plugin: 0 .. 2
        """
        super().__init__()
        self.app_start = app_start
        self.app_length = app_length
        self.plugin = plugin

    def __repr__(self) -> str:
        return "BDT <ADDR: 0x{:X}, LEN: {} Bytes, Plugin: {}>".format(
            self.app_start, self.app_length, self.plugin
        )

    def info(self) -> str:
        """String representation of the SegBDT."""
        msg = f" Start      : 0x{self.app_start:08X}\n"
        msg += f" App Length : {size_fmt(self.app_length)} ({self.app_length} Bytes)\n"
        msg += f" Plugin     : {'YES' if self.plugin else 'NO'}\n"
        msg += "\n"

        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(self.FORMAT, self.app_start, self.app_length, self.plugin)
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegBDT":
        """Parse segment from bytes array.

        :param data: The bytes array of BDT segment
        :return: SegBDT object
        """
        return cls(*unpack_from(cls.FORMAT, data))


class SegAPP(BaseSegment):
    """APP segment."""

    def __init__(self, data: Optional[bytes] = None) -> None:
        """Initialize APP segment.

        :param data: application binary data
        """
        super().__init__()
        self._data = data

    @property
    def data(self) -> Optional[bytes]:
        """Application binary data."""
        return self._data

    @data.setter
    def data(self, value: Union[bytearray, bytes]) -> None:
        """Application binary data."""
        assert isinstance(value, (bytes, bytearray))
        self._data = bytes(value)

    @property
    def size(self) -> int:
        """Size of APP segment."""
        return 0 if (self._data is None) else len(self._data)

    def __repr__(self) -> str:
        return "APP <LEN: {} Bytes>".format(self.size)

    def info(self) -> str:
        """String representation of the SegAPP."""
        msg = " Size: {0:d} Bytes\n".format(self.size)
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = b""
        if self._data:
            data += bytes(self._data)
        data += self._padding_export()
        return data


_SEG_DCD_COMMANDS = {
    "WriteValue": ("write", EnumWriteOps.WRITE_VALUE),
    "WriteClearBits": ("write", EnumWriteOps.WRITE_CLEAR_BITS),
    "ClearBitMask": ("write", EnumWriteOps.CLEAR_BITMASK),
    "SetBitMask": ("write", EnumWriteOps.SET_BITMASK),
    "CheckAllClear": ("check", EnumCheckOps.ALL_CLEAR),
    "CheckAllSet": ("check", EnumCheckOps.ALL_SET),
    "CheckAnyClear": ("check", EnumCheckOps.ANY_CLEAR),
    "CheckAnySet": ("check", EnumCheckOps.ANY_SET),
    "Unlock": None,
    "Nop": None,
}


class SegDCD(BaseSegment):
    """Device configuration data (DCD) segment.

    IC configuration data, usually is used to configure DDR/SDRAM memory. Typically this is optional
    """

    # list of supported DCD commands
    _COMMANDS: Tuple[CmdTag, ...] = (
        CmdTag.WRT_DAT,
        CmdTag.CHK_DAT,
        CmdTag.NOP,
        CmdTag.UNLK,
    )

    @property
    def header(self) -> Header:
        """Header of Device configuration data (DCD) segment."""
        return self._header

    @property
    def commands(self) -> List[CmdBase]:
        """Commands of Device configuration data (DCD) segment."""
        return self._commands

    @property
    def size(self) -> int:
        """Size of Device configuration data (DCD) segment."""
        return self._header.length if self.enabled else 0

    @property
    def space(self) -> int:
        """Add space."""
        return self.size + self.padding if self.enabled else 0

    def __init__(self, param: int = 0x41, enabled: bool = False) -> None:
        """Initialize DCD segment."""
        super().__init__()
        self.enabled = enabled
        self._header = Header(SegTag.DCD, param)
        self._header.length = self._header.size
        self._commands: List[CmdBase] = []

    def __repr__(self) -> str:
        return "DCD <Commands: {}>".format(len(self._commands))

    def __len__(self) -> int:
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBase:
        return self._commands[key]

    def __setitem__(self, key: int, value: CmdBase) -> None:
        if value.tag not in self._COMMANDS:
            raise SPSDKError("Invalid command")
        self._commands[key] = value

    def __iter__(self) -> Iterator:
        return self._commands.__iter__()

    def info(self) -> str:
        """String representation of the SegDCD."""
        msg = ""
        for cmd in self._commands:
            msg += cmd.info()
            msg += "\n"
        return msg

    def append(self, cmd: CmdBase) -> None:
        """Appending of Device configuration data (DCD) segment."""
        if not (isinstance(cmd, CmdBase) and (cmd.tag in self._COMMANDS)):
            raise SPSDKError("Invalid command")
        self._commands.append(cmd)
        self._header.length += cmd.size

    def pop(self, index: int) -> CmdBase:
        """Popping of Device configuration data (DCD) segment."""
        if index < 0 or index >= len(self._commands):
            raise SPSDKError("Can not pop item from dcd segment")
        cmd = self._commands.pop(index)
        self._header.length -= cmd.size
        return cmd

    def clear(self) -> None:
        """Clear of Device configuration data (DCD) segment."""
        self._commands.clear()
        self._header.length = self._header.size

    def export_txt(self, txt_data: str = None) -> str:
        """Export txt of Device configuration data (DCD) segment."""
        write_ops = ("WriteValue", "WriteClearBits", "ClearBitMask", "SetBitMask")
        check_ops = ("CheckAllClear", "CheckAllSet", "CheckAnyClear", "CheckAnySet")
        if txt_data is None:
            txt_data = ""

        for cmd in self._commands:
            if isinstance(cmd, CmdWriteData):
                for (address, value) in cmd:
                    txt_data += "{0:s} {1:d} 0x{2:08X} 0x{3:08X}\n".format(
                        write_ops[cmd.ops], cmd.num_bytes, address, value
                    )
            elif isinstance(cmd, CmdCheckData):
                txt_data += "{0:s} {1:d} 0x{2:08X} 0x{3:08X}".format(
                    check_ops[cmd.ops], cmd.num_bytes, cmd.address, cmd.mask
                )
                txt_data += " {0:d}\n".format(cmd.count) if cmd.count else "\n"

            elif isinstance(cmd, CmdUnlock):
                txt_data += "Unlock {0:s}".format(EnumEngine[cmd.engine])  # type: ignore
                cnt = 1
                for value in cmd:
                    if cnt > 6:
                        txt_data += " \\\n"
                        cnt = 0
                    txt_data += " 0x{0:08X}".format(value)
                    cnt += 1

                txt_data += "\n"

            else:
                txt_data += "Nop\n"

            # Split with new line every group of commands
            txt_data += "\n"

        return txt_data

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = b""
        if self.enabled:
            data = self._header.export()
            for command in self._commands:
                data += command.export()
            # padding
            data += self._padding_export()

        return data

    @classmethod
    def parse_txt(cls, text: str) -> "SegDCD":
        """Parse segment from text file.

        :param text: The string with DCD commands
        :return: SegDCD object
        """
        return SegDcdBuilder().build(text)

    @classmethod
    def parse(cls, data: bytes) -> "SegDCD":
        """Parse segment from bytes array.

        :param data: The bytes array of DCD segment
        :raises CorruptedException: Exception caused by corrupted data
        :return: SegDCD object
        """
        header = Header.parse(data, 0, SegTag.DCD)
        index = header.size
        obj = cls(header.param, True)
        while index < header.length:
            try:
                cmd_obj = parse_command(data, index)
            except ValueError:
                raise CorruptedException("Unknown command at position: " + hex(index))

            obj.append(cmd_obj)
            index += cmd_obj.size
        return obj


class SegDcdBuilder:
    """Builder to create SegDCD from text input."""

    def __init__(self) -> None:
        """Initialize SegDcdBuilder."""
        self.line_cnt = 0  # current line number to be displayed in the error message
        self.cmd_write: Optional[
            CmdWriteData
        ] = None  # this is cache to merge several write commands of same type

    def _parse_cmd(self, dcd_obj: SegDCD, cmd: List[str]) -> None:
        """Parse one command.

        :param dcd_obj: result of the builder
        :param cmd: command with arguments
        :raises SyntaxError: command is corrupted
        :raises SPSDKError: When command is unsupported
        """
        # ----------------------------
        # Parse command
        # ----------------------------
        cmd_tuple = _SEG_DCD_COMMANDS[cmd[0]]
        if cmd_tuple is None:
            if cmd[0] == "Nop":
                if self.cmd_write is not None:
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

                dcd_obj.append(CmdNop())

            elif cmd[0] == "Unlock":
                if self.cmd_write is not None:
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

                if cmd[1] not in EnumEngine:
                    raise SyntaxError(
                        "Unlock CMD: wrong engine parameter at line %d" % (self.line_cnt - 1)
                    )

                engine = EnumEngine.from_int(EnumEngine[cmd[1]])
                args = [int(value, 0) for value in cmd[2:]]
                dcd_obj.append(CmdUnlock(engine, *args))
            else:
                if True:
                    raise SPSDKError("unknown command")

        elif cmd_tuple[0] == "write":
            if len(cmd) < 4:
                raise SyntaxError(
                    "Write CMD: not enough arguments at line %d" % (self.line_cnt - 1)
                )

            ops = cmd_tuple[1]
            numbytes = int(cmd[1])
            addr = int(cmd[2], 0)
            value = int(cmd[3], 0)

            if self.cmd_write is not None:
                if (self.cmd_write.ops != ops) or (self.cmd_write.num_bytes != numbytes):
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

            if self.cmd_write is None:
                self.cmd_write = CmdWriteData(numbytes, ops)

            self.cmd_write.append(addr, value)

        else:
            if len(cmd) < 4:
                raise SyntaxError(
                    "Check CMD: not enough arguments at line %d" % (self.line_cnt - 1)
                )

            if self.cmd_write is not None:
                dcd_obj.append(self.cmd_write)
                self.cmd_write = None

            ops = cmd_tuple[1]
            numbytes = int(cmd[1])
            addr = int(cmd[2], 0)
            mask = int(cmd[3], 0)
            count = int(cmd[4], 0) if len(cmd) > 4 else None
            dcd_obj.append(CmdCheckData(numbytes, ops, addr, mask, count))

    def build(self, text: str) -> SegDCD:
        """Parse segment from text file and build SegDCD.

        :param text: input text to import
        :return: SegDCD object
        :raise SyntaxError: if input format is not valid
        """
        dcd_obj = SegDCD(enabled=True)
        cmd_mline = False
        cmd: List[str] = []
        for line in text.split("\n"):
            line = line.rstrip("\0")
            line = line.lstrip()
            # increment line counter
            self.line_cnt += 1
            # ignore comments
            if not line or line.startswith("#"):
                continue
            # check if multi-line command
            if cmd_mline:
                cmd += line.split()
                cmd_mline = False
            else:
                cmd = line.split()
                if cmd[0] not in _SEG_DCD_COMMANDS:
                    logger.error(f"Unknown DCD command ignored: {cmd}")
                    continue
            #
            if cmd[-1] == "\\":
                cmd = cmd[:-1]
                cmd_mline = True
                continue

            self._parse_cmd(dcd_obj, cmd)

        if self.cmd_write is not None:
            dcd_obj.append(self.cmd_write)

        return dcd_obj


class SegCSF(BaseSegment):
    """Command Sequence File (CSF), signature block for Secure Boot.

    A script of commands used to guide image authentication and device configuration operations.
    """

    # list of supported CSF commands
    _COMMANDS: Tuple[CmdTag, ...] = (
        CmdTag.WRT_DAT,
        CmdTag.CHK_DAT,
        CmdTag.NOP,
        CmdTag.SET,
        CmdTag.INIT,
        CmdTag.UNLK,
        CmdTag.INS_KEY,
        CmdTag.AUT_DAT,
    )

    @classmethod
    def _is_csf_command(cls, cmd: object) -> bool:
        """Test whether given class is instance of supported CSF command.

        :param cmd: instance to be tested
        :return: True if yes, False otherwise
        """
        return isinstance(cmd, CmdBase) and (cmd.tag in cls._COMMANDS)

    def __init__(self, version: int = 0x40, enabled: bool = False):
        """Initialize CSF segment."""
        super().__init__()
        self._header = Header(SegTag.CSF, version)
        self.enabled = enabled
        self._commands: List[CmdBase] = []
        # additional command data: keys and certificates; these data are stored after the commands
        #   - key is an offset of the data section in segment
        #   - value is an instance of the data section
        self._cmd_data: Dict[int, BaseClass] = dict()
        # this allows to export segment, that was parsered, but certificate and private keys are not available
        self.no_signature_updates = False

    @property
    def version(self) -> int:
        """Version of CSF segment."""
        return self._header.param

    @property
    def commands(self) -> List[CmdBase]:
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
        # noinspection PyTypeChecker
        return filter(lambda m: isinstance(m, MAC), self._cmd_data.values())  # type: ignore

    def __repr__(self) -> str:
        return "CSF <Commands: {}>".format(len(self.commands))

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

    def info(self) -> str:
        """String representation of the SegCSF."""
        msg = ""
        msg += f"CSF Version        : {hex(self.version)}\n"
        msg += f"Number of commands : {len(self.commands)}\n"
        for cmd in self.commands:
            msg += cmd.info()
            msg += "\n"

        # certificates and signatures
        msg += "[CMD-DATA]\n"
        for offset, cmd_data in self._cmd_data.items():
            msg += f"- OFFSET : {offset}\n"
            msg += cmd_data.info()

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
        new_cmd_data: Dict[int, BaseClass] = dict()
        for cmd in filter(lambda c: c.needs_cmd_data_reference, self.commands):
            key = cmd.cmd_data_reference
            if key is not None:
                cmd.cmd_data_offset = cur_ofs
                new_cmd_data[cur_ofs] = key
                cur_ofs += align(key.size, 4)
            elif reset_cmddata_offsets and (cmd.cmd_data_offset > 0):
                cmd.cmd_data_offset = 0

        self._cmd_data = new_cmd_data

    def _export_base(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export base part of the CSF section (header and commands) without keys and signatures.

        :param dbg_info: optional instance allowing to produce deung information about exported data
        :return: exported binary data
        """
        self.update(True)
        data = self._header.export()
        dbg_info.append_binary_section("header", data)
        for command in self.commands:
            dbg_info.append_section(f"COMMAND: {CmdTag.desc(command.tag)}")
            cmd_data = command.export(dbg_info)
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

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export segment as bytes array (serialization).

        :param dbg_info: optional list of strings to produce debug information about exported data
        :return: bytes
        """
        data = b""
        if self.enabled:
            data = self._export_base(dbg_info)
            dbg_info.append_section("CSF-DATA: CERTIFICATES and SIGNATURES")
            cmd_data_by_offset = sorted(self._cmd_data.items(), key=lambda t: str(t[0]).zfill(8))
            for offset, cmd_data in cmd_data_by_offset:
                data = extend_block(data, offset)
                dbg_info.append_section(f"CMD-DATA: {type(cmd_data).__name__}")
                data += cmd_data.export(dbg_info=dbg_info)
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
        result = cmd.parse_cmd_data(data, cmd.cmd_data_offset)
        self._cmd_data[cmd.cmd_data_offset] = result

        return result

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SegCSF":
        """Parse segment from bytes array.

        :param data: The bytes array of CSF segment
        :param offset: to start parsing the data
        :raises CorruptedException: When there is unknown command
        :raises CorruptedException: When command can not be parsed
        :return: SegCSF instance
        """
        header = Header.parse(data, offset, SegTag.CSF)
        index = header.size
        obj = cls(header.param, True)
        obj.no_signature_updates = True
        while index < header.length:
            try:
                cmd_obj = parse_command(data, offset + index)
                obj.append_command(cmd_obj)
            except ValueError:
                raise CorruptedException(
                    "Failed to parse command at position: " + hex(offset + index)
                )
            index += cmd_obj.size

        for cmd in obj.commands:
            if cmd.needs_cmd_data_reference:
                obj._parse_cmd_data(cmd, data)

        obj.update(True)
        return obj


########################################################################################################################
# Boot Image V3 Segments (i.MX8QM-Ax, i.MX8QXP-Ax)
########################################################################################################################


class SegIVT3a(BaseSegment):
    """IVT3a segment."""

    FORMAT = "<1L5Q"
    SIZE = Header.SIZE + calcsize(FORMAT)

    @property
    def header(self) -> Header:
        """Header of IVT3a segment."""
        return self._header

    @property
    def size(self) -> int:
        """Size of IVT3a segment."""
        return self.SIZE

    def __init__(self, param: int) -> None:
        """Initialize IVT segment.

        :param param: The version of IVT and Image format
        """
        super().__init__()
        self._header = Header(SegTag.IVT3, param)
        self._header.length = self.SIZE
        self.version = 0
        self.dcd_address = 0
        self.bdt_address = 0
        self.ivt_address = 0
        self.csf_address = 0
        self.next = 0

    def __repr__(self) -> str:
        return "IVT3a <IVT:0x{:X}, BDT:0x{:X}, DCD:0x{:X}, CSF:0x{:X}>".format(
            self.ivt_address, self.bdt_address, self.dcd_address, self.csf_address
        )

    def info(self) -> str:
        """String representation of the SegIVT3a."""
        msg = ""
        msg += f" Format version   : {_format_ivt_item(self.version, digit_count=2)}\n"
        msg += f" IVT start address: {_format_ivt_item(self.ivt_address)}\n"
        msg += f" BDT start address: {_format_ivt_item(self.bdt_address)}\n"
        msg += f" DCD start address: {_format_ivt_item(self.dcd_address)}\n"
        msg += f" CSF start address: {_format_ivt_item(self.csf_address)}\n"
        msg += f" NEXT address     : {_format_ivt_item(self.next)}\n"
        msg += "\n"
        return msg

    def validate(self) -> None:
        """Validation of IVT3a segment."""
        if self.ivt_address == 0 or self.bdt_address == 0 or self.bdt_address < self.ivt_address:
            raise SPSDKError("Not valid IVT/BDT address")
        if self.dcd_address and self.dcd_address < self.ivt_address:
            raise SPSDKError("Not valid DCD address: 0x{:X}".format(self.dcd_address))
        if self.csf_address and self.csf_address < self.ivt_address:
            raise SPSDKError("Not valid CSF address: 0x{:X}".format(self.csf_address))

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        self.validate()

        data = self.header.export()
        data += pack(
            self.FORMAT,
            self.version,
            self.dcd_address,
            self.bdt_address,
            self.ivt_address,
            self.csf_address,
            self.next,
        )
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegIVT3a":
        """Parse segment from bytes array.

        :param data: The bytes array of IVT3a segment
        :return: SegIVT3a object
        """
        header = Header.parse(data, 0, SegTag.IVT3)
        obj = cls(header.param)

        (
            obj.version,
            obj.dcd_address,
            obj.bdt_address,
            obj.ivt_address,
            obj.csf_address,
            obj.next,
        ) = unpack_from(cls.FORMAT, data, header.size)

        obj.validate()

        return obj


class SegIVT3b(BaseSegment):
    """IVT3b segment."""

    FORMAT = "<1L7Q"
    SIZE = Header.SIZE + calcsize(FORMAT)

    @property
    def header(self) -> Header:
        """Header of IVT3b segment."""
        return self._header

    @property
    def size(self) -> int:
        """Size of IVT3b segment.

        :return size
        """
        return self.SIZE

    def __init__(self, version: int) -> None:
        """Initialize IVT segment.

        :param version: The version of IVT and Image format
        """
        super().__init__()
        self._header = Header(SegTag.IVT2, version)
        self._header.length = self.SIZE
        self.rs1 = 0
        self.dcd_address = 0
        self.bdt_address = 0
        self.ivt_address = 0
        self.csf_address = 0
        self.scd_address = 0
        self.rs2h = 0
        self.rs2l = 0

    def __repr__(self) -> str:
        return "IVT3b <IVT:0x{:X}, BDT:0x{:X}, DCD:0x{:X}, CSF:0x{:X}, SCD:0x{:X}>".format(
            self.ivt_address,
            self.bdt_address,
            self.dcd_address,
            self.csf_address,
            self.scd_address,
        )

    def info(self) -> str:
        """String representation of the SegIVT3b."""
        msg = ""
        msg += f" IVT start address: {_format_ivt_item(self.ivt_address)}\n"
        msg += f" BDT start address: {_format_ivt_item(self.bdt_address)}\n"
        msg += f" DCD start address: {_format_ivt_item(self.dcd_address)}\n"
        msg += f" CSF start address: {_format_ivt_item(self.csf_address)}\n"
        msg += f" SCD start address: {_format_ivt_item(self.scd_address)}\n"
        msg += "\n"
        return msg

    def validate(self) -> None:
        """Validation of IVT3b segment."""
        if self.ivt_address == 0 or self.bdt_address == 0 or self.bdt_address < self.ivt_address:
            raise SPSDKError("Not valid IVT/BDT address")
        if self.dcd_address and self.dcd_address < self.ivt_address:
            raise SPSDKError("Not valid DCD address: 0x{:X}".format(self.dcd_address))
        if self.csf_address and self.csf_address < self.ivt_address:
            raise SPSDKError("Not valid CSF address: 0x{:X}".format(self.csf_address))
        if self.scd_address and self.scd_address < self.ivt_address:
            raise SPSDKError("Not valid SCD address: 0x{:X}".format(self.scd_address))

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        self.validate()

        data = self.header.export()
        data += pack(
            self.FORMAT,
            self.rs1,
            self.dcd_address,
            self.bdt_address,
            self.ivt_address,
            self.csf_address,
            self.scd_address,
            self.rs2h,
            self.rs2l,
        )
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegIVT3b":
        """Parse segment from bytes array.

        :param data: The bytes array of IVT3b segment
        :return: SegIVT3b object
        """
        header = Header.parse(data, 0, SegTag.IVT2)
        obj = cls(header.param)

        (
            obj.rs1,
            obj.dcd_address,
            obj.bdt_address,
            obj.ivt_address,
            obj.csf_address,
            obj.scd_address,
            obj.rs2h,
            obj.rs2l,
        ) = unpack_from(cls.FORMAT, data, header.size)

        obj.validate()

        return obj


class SegIDS3a(BaseSegment):
    """IDS3a segment."""

    FORMAT = "<3Q4L"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Size of IDS3a segment."""
        return self.SIZE

    def __init__(self) -> None:
        """Initialize IDS3a segment."""
        super().__init__()
        self.image_source = 0
        self.image_destination = 0
        self.image_entry = 0
        self.image_size = 0
        self.hab_flags = 0
        self.scfw_flags = 0
        self.rom_flags = 0

    def __repr__(self) -> str:
        return "IDS3a <IN:0x{:X}, OUT:0x{:X}, ENTRY:0x{:X}, SIZE:{}B, HAB:0x{:X}, SCFW:0x{:X}, ROM:0x{:X}>".format(
            self.image_source,
            self.image_destination,
            self.image_entry,
            self.image_size,
            self.hab_flags,
            self.scfw_flags,
            self.rom_flags,
        )

    def info(self) -> str:
        """String representation of the SegIDS3a."""
        msg = " Source: 0x{:08X}\n".format(self.image_source)
        msg += " Dest:   0x{:08X}\n".format(self.image_destination)
        msg += " Entry:  0x{:08X}\n".format(self.image_entry)
        msg += " Size:   {:s} ({} Bytes)\n".format(size_fmt(self.image_size), self.image_size)
        msg += " <Flags>\n"
        msg += " SCFW:   0x{:08X}\n".format(self.scfw_flags)
        msg += " HAB:    0x{:08X}\n".format(self.hab_flags)
        msg += " ROM:    0x{:08X}\n".format(self.rom_flags)
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(
            self.FORMAT,
            self.image_source,
            self.image_destination,
            self.image_entry,
            self.image_size,
            self.hab_flags,
            self.scfw_flags,
            self.rom_flags,
        )
        data += self._padding_export()

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegIDS3a":
        """Parse segment from bytes array.

        :param data: The bytes array of IDS3a segment
        :return: SegIDS3a object
        """
        obj = cls()
        (
            obj.image_source,
            obj.image_destination,
            obj.image_entry,
            obj.image_size,
            obj.hab_flags,
            obj.scfw_flags,
            obj.rom_flags,
        ) = unpack_from(obj.FORMAT, data)

        return obj


class SegBDS3a(BaseSegment):
    """BDS3a segment."""

    FORMAT = "<4L"
    HEADER_SIZE = calcsize(FORMAT)
    IMAGES_MAX_COUNT = 6
    SIZE = HEADER_SIZE + SegIDS3a.SIZE * IMAGES_MAX_COUNT

    @property
    def header_size(self) -> int:
        """Header's size of BDS3a segment."""
        return self.HEADER_SIZE

    @property
    def size(self) -> int:
        """Size of BDS3a segment."""
        return self.SIZE

    def __init__(self) -> None:
        """Initialize BDS3a segment."""
        super().__init__()
        self.images_count = 0
        self.boot_data_size = 0
        self.boot_data_flag = 0
        self.images = [SegIDS3a() for _ in range(self.IMAGES_MAX_COUNT)]
        self.reserved = 0

    def __repr__(self) -> str:
        return "BDS3a <IMAGES: {}, SIZE: {}B, FLAG: 0x{:X}>".format(
            self.images_count, self.boot_data_size, self.boot_data_flag
        )

    def info(self) -> str:
        """String representation of the SegBDS3a."""
        msg = " IMAGES: {}\n".format(self.images_count)
        # TODO: why the code commented-out?   msg += " Data size: {}\n".format(self.boot_data_size)
        msg += " DFLAGS: 0x{0:08X}\n".format(self.boot_data_flag)
        msg += "\n"
        for i in range(self.images_count):
            msg += " IMAGE[{}] \n".format(i)
            msg += self.images[i].info()
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(
            self.FORMAT,
            self.images_count,
            self.boot_data_size,
            self.boot_data_flag,
            self.reserved,
        )

        for i in range(self.IMAGES_MAX_COUNT):
            data += self.images[i].export()

        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegBDS3a":
        """Parse segment from bytes array.

        :param data: The bytes array of BDS3a segment
        :return: SegBDS3a object
        """
        obj = cls()
        (
            obj.images_count,
            obj.boot_data_size,
            obj.boot_data_flag,
            obj.reserved,
        ) = unpack_from(cls.FORMAT, data)

        for i in range(obj.images_count):
            obj.images[i] = SegIDS3a.parse(data[cls.HEADER_SIZE + i * SegIDS3a.SIZE :])

        return obj


class SegIDS3b(BaseSegment):
    """IDS3b segment."""

    FORMAT = "<3Q2L"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Size of IDS3b segment."""
        return calcsize(self.FORMAT)

    def __init__(self) -> None:
        """Initialize IDS3b segment."""
        super().__init__()
        self.image_source = 0
        self.image_destination = 0
        self.image_entry = 0
        self.image_size = 0
        self.flags = 0

    def __repr__(self) -> str:
        return "IDS3b <IN:0x{:X}, OUT:0x{:X}, ENTRY:0x{:X}, SIZE:{}B, FLAGS:0x{:X}>".format(
            self.image_source,
            self.image_destination,
            self.image_entry,
            self.image_size,
            self.flags,
        )

    def info(self) -> str:
        """String representation of the SegIDS3b."""
        msg = " Source: 0x{:08X}\n".format(self.image_source)
        msg += " Dest:   0x{:08X}\n".format(self.image_destination)
        msg += " Entry:  0x{:08X}\n".format(self.image_entry)
        msg += " Flags:  0x{:08X}\n".format(self.flags)
        msg += " Size:   {:s} ({} Bytes)\n".format(size_fmt(self.image_size), self.image_size)
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(
            self.FORMAT,
            self.image_source,
            self.image_destination,
            self.image_entry,
            self.image_size,
            self.flags,
        )
        data += self._padding_export()

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegIDS3b":
        """Parse segment from bytes array.

        :param data: The bytes array of IDS3b segment
        :return: SegIDS3b object
        """
        ids = cls()
        (
            ids.image_source,
            ids.image_destination,
            ids.image_entry,
            ids.image_size,
            ids.flags,
        ) = unpack_from(cls.FORMAT, data)

        return ids


class SegBDS3b(BaseSegment):
    """BDS3b segment."""

    FORMAT = "<4L"
    HEADER_SIZE = calcsize(FORMAT)
    IMAGES_MAX_COUNT = 4
    SIZE = calcsize(FORMAT) + SegIDS3b.SIZE * (IMAGES_MAX_COUNT + 3)

    @property
    def header_size(self) -> int:
        """Size of header of BDS3b segment."""
        return self.HEADER_SIZE

    @property
    def size(self) -> int:
        """Size of BDS3b segment."""
        return self.SIZE

    def __init__(self) -> None:
        """Initialize BDS3b segment."""
        super().__init__()
        self.images_count = 0
        self.boot_data_size = 0
        self.boot_data_flag = 0
        self.reserved = 0

        self.images = [SegIDS3b() for _ in range(self.IMAGES_MAX_COUNT)]

        self.scd = SegIDS3b()
        self.csf = SegIDS3b()
        self.rs_img = SegIDS3b()

    def __repr__(self) -> str:
        return "BDS3b <IMAGES: {}, SIZE: {}B, FLAG: 0x{:X}>".format(
            self.images_count, self.boot_data_size, self.boot_data_flag
        )

    def info(self) -> str:
        """String representation of the SegBDS3b."""
        msg = " IMAGES: {}\n".format(self.images_count)
        # TODO: why the code commented-out? msg += " Data size: {}\n".format(self.boot_data_size)
        msg += " DFLAGS: 0x{0:08X}\n".format(self.boot_data_flag)
        msg += "\n"
        for i in range(self.images_count):
            msg += " IMAGE[{}] \n".format(i)
            msg += self.images[i].info()
        if self.scd.image_source != 0:
            msg += " SCD:\n"
            msg += self.scd.info()
        if self.csf.image_source != 0:
            msg += " CSF:\n"
            msg += self.csf.info()

        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(
            self.FORMAT,
            self.images_count,
            self.boot_data_size,
            self.boot_data_flag,
            self.reserved,
        )

        for i in range(self.IMAGES_MAX_COUNT):
            data += self.images[i].export()

        data += self.scd.export()
        data += self.csf.export()
        data += self.rs_img.export()

        data += self._padding_export()

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegBDS3b":
        """Parse segment from bytes array.

        :param data: The bytes array of BDS3b segment
        :return: SegBDS3b object
        """
        obj = cls()
        (
            obj.images_count,
            obj.boot_data_size,
            obj.boot_data_flag,
            obj.reserved,
        ) = unpack_from(obj.FORMAT, data)

        offset = cls.HEADER_SIZE
        for i in range(obj.images_count):
            obj.images[i] = SegIDS3b.parse(data[offset:])
            offset += SegIDS3b.SIZE

        obj.scd = SegIDS3b.parse(data[offset:])
        offset += SegIDS3b.SIZE
        obj.csf = SegIDS3b.parse(data[offset:])
        offset += SegIDS3b.SIZE
        obj.rs_img = SegIDS3b.parse(data[offset:])

        return obj


########################################################################################################################
# Boot Image V4 Segments (i.MX8DM, i.MX8QM-Bx, i.MX8QXP-Bx)
########################################################################################################################


class SegBIM(BaseSegment):
    """BootImage segment."""

    FORMAT = "<2L2Q2L"
    SIZE = calcsize(FORMAT) + 64 + 32

    @property
    def size(self) -> int:
        """Size of BootImage segment."""
        return self.SIZE

    def __init__(self) -> None:
        """Initialize BootImage segment."""
        super().__init__()
        self.image_offset = 0
        self.image_size = 0
        self.load_address = 0
        self.entry_address = 0
        self.hab_flags = 0
        self.meta_data = 0
        self.image_hash: Optional[bytes] = None
        self.image_iv: Optional[bytes] = None

    def __repr__(self) -> str:
        return "BIM <OFFSET:{}, SIZE:{}B, LOAD:0x{:X}, ENTRY:0x{:X}, FLAGS:0x{:X}>".format(
            self.image_offset,
            self.image_size,
            self.load_address,
            self.entry_address,
            self.hab_flags,
        )

    def info(self) -> str:
        """String representation of the SegBIM."""
        msg = " Offset:     0x{:X}\n".format(self.image_offset)
        msg += " Size:       {} ({} Bytes)\n".format(size_fmt(self.image_size), self.image_size)
        msg += " Load:       0x{:X}\n".format(self.load_address)
        msg += " Entry:      0x{:X}\n".format(self.entry_address)
        if self.image_hash:
            msg += " HASH:       {}\n".format(
                "".join(["{:02X}".format(i) for i in self.image_hash])
            )
        if self.image_iv:
            msg += " IV:         {}\n".format("".join(["{:02X}".format(i) for i in self.image_iv]))
        msg += " Hash Flags: 0x{:08X}\n".format(self.hab_flags)
        msg += " Meta Data:  0x{:08X}\n".format(self.meta_data)
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = pack(
            self.FORMAT,
            self.image_offset,
            self.image_size,
            self.load_address,
            self.entry_address,
            self.hab_flags,
            self.meta_data,
        )

        data += self._padding_export()

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegBIM":
        """Parse segment from bytes array.

        :param data: The bytes array of BootImage segment
        :return: SegBootImage object
        """
        obj = cls()
        (
            obj.image_offset,
            obj.image_size,
            obj.load_address,
            obj.entry_address,
            obj.hab_flags,
            obj.meta_data,
        ) = unpack_from(obj.FORMAT, data)

        offset = calcsize(cls.FORMAT)
        obj.image_hash = data[offset : offset + 64]
        offset += 64
        obj.image_iv = data[offset : offset + 32]

        return obj


class SegSIGB(BaseSegment):
    """SignatureBlock segment."""

    FORMAT = "<4HL"
    SIZE = Header2.SIZE + calcsize(FORMAT)

    @property
    def version(self) -> int:
        """Version of Signature Block segment."""
        return self._header.param

    @version.setter
    def version(self, value: int) -> None:
        self._header.param = value

    @property
    def size(self) -> int:
        """Size of Signature Block segment."""
        return self.SIZE

    def __init__(self, version: int = 0) -> None:
        """Initialize SignatureBlock segment."""
        super().__init__()
        self._header = Header2(SegTag.SIGB, version)
        self._header.length = self.SIZE
        self.srk_table_offset = 0
        self.cert_offset = 0
        self.blob_offset = 0
        self.signature_offset = 0
        self.reserved = 0

    def __repr__(self) -> str:
        return "SIGB <SRK:0x{:X}, CERT:0x{:X}, BLOB:0x{:X}, SIG:0x{:X}>".format(
            self.srk_table_offset,
            self.cert_offset,
            self.blob_offset,
            self.signature_offset,
        )

    def info(self) -> str:
        """String representation of the SegSIGB."""
        msg = " SRK Table Offset:   0x{:X}\n".format(self.srk_table_offset)
        msg += " Certificate Offset: 0x{:X}\n".format(self.cert_offset)
        msg += " Signature Offset:   0x{:X}\n".format(self.signature_offset)
        msg += " Blob Offset:        0x{:X}\n".format(self.blob_offset)
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        data = self._header.export()
        data += pack(
            self.FORMAT,
            self.srk_table_offset,
            self.cert_offset,
            self.blob_offset,
            self.signature_offset,
            self.reserved,
        )
        data += self._padding_export()

        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegSIGB":
        """Parse segment from bytes array.

        :param data: The bytes array of SignatureBlock segment
        :return: SegSigBlk object
        """
        header = Header2.parse(data, 0, SegTag.SIGB)
        obj = cls(header.param)

        (
            obj.srk_table_offset,
            obj.cert_offset,
            obj.blob_offset,
            obj.signature_offset,
            obj.reserved,
        ) = unpack_from(obj.FORMAT, data)

        return obj


# pylint: disable=too-many-instance-attributes
class SegBIC1(BaseSegment):
    """Boot Images Container segment."""

    MAX_NUM_IMGS = 6

    FORMAT = "<LH2B2H"
    SIZE = Header.SIZE + calcsize(FORMAT) + MAX_NUM_IMGS * SegBIM.SIZE + SegSIGB.SIZE + 8

    @property
    def version(self) -> int:
        """Version of Boot Images Container segment."""
        return self._header.param

    @version.setter
    def version(self, value: int) -> None:
        """Version of Boot Images Container segment."""
        self._header.param = value

    @property
    def size(self) -> int:
        """Size."""
        return self.SIZE

    def __init__(self, version: int = 0) -> None:
        """Initialize Boot Images Container segment.

        :param version: The version of Header for Boot Images Container
        """
        super().__init__()
        self._header = Header2(SegTag.BIC1, version)
        self._header.length = self.SIZE
        self.flags = 0
        self.sw_version = 0
        self.fuse_version = 0
        self.images_count = 0
        self.sig_blk_offset = 0
        self.reserved = 0
        self.images = [SegBIM() for _ in range(self.MAX_NUM_IMGS)]
        self.sig_blk_hdr = SegSIGB()
        self.sig_blk_size = 0
        self.padding = 8

    def __repr__(self) -> str:
        return "BIC1 <FLAGS:0x{:X}, SWV:0x{:X}, FUSEV:0x{:X}, COUNT:{}, SBO:0x{:X}>".format(
            self.flags,
            self.sw_version,
            self.fuse_version,
            self.images_count,
            self.sig_blk_offset,
        )

    def info(self) -> str:
        """String representation of the SegBIC1."""
        msg = ""
        msg += " Flags:        0x{:08X}\n".format(self.flags)
        msg += " SW Version:   {}\n".format(self.sw_version)
        msg += " Fuse Version: {}\n".format(self.fuse_version)
        msg += " Images Count: {}\n".format(self.images_count)
        msg += " SigBlkOffset: 0x{:08X}\n".format(self.sig_blk_offset)
        msg += "\n"
        for i in range(self.images_count):
            msg += " IMAGE[{}] \n".format(i)
            msg += self.images[i].info()
        msg += " [ Signature Block Header ]\n"
        msg += self.sig_blk_hdr.info()
        msg += "\n"
        return msg

    def validate(self) -> None:
        """Validate segment."""
        return None

    def export(self) -> bytes:
        """Export segment as bytes array.

        :return: bytes
        """
        self.validate()

        data = self._header.export()
        data += pack(
            self.FORMAT,
            self.flags,
            self.sw_version,
            self.fuse_version,
            self.images_count,
            self.sig_blk_offset,
            self.reserved,
        )
        for image in self.images:
            data += image.export()
        data += self.sig_blk_hdr.export()
        data += pack("<L", self.sig_blk_size)
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> "SegBIC1":
        """Parse segment from bytes array.

        :param data: The bytes array of BIC1 segment
        :return: SegBIC1 object
        """
        header = Header2.parse(data, 0, SegTag.BIC1)
        offset = header.size
        obj = cls(header.param)

        (
            obj.flags,
            obj.sw_version,
            obj.fuse_version,
            obj.images_count,
            obj.sig_blk_offset,
            obj.reserved,
        ) = unpack_from(cls.FORMAT, data, offset)

        offset += calcsize(cls.FORMAT)
        for i in range(obj.images_count):
            obj.images[i] = SegBIM.parse(data[offset:])
            offset += SegBIM.SIZE

        obj.sig_blk_hdr = SegSIGB.parse(data[offset:])
        offset += SegSIGB.SIZE
        obj.sig_blk_size = unpack_from("<L", data, offset)[0]

        obj.validate()

        return obj


def _format_ivt_item(item_address: int, digit_count: int = 8) -> str:
    """Formats 'item_address' to hex or None if address is 0.

    If provided item address is not 0, the result will be in format
    '0x' + leading zeros + number in HEX format
    If provided number is 0, function returns 'None'

    :param item_address: Address if IVT item
    :param digit_count: Number of digits to , defaults to 8
    :return: Formated number
    """
    return f"{item_address:#0{digit_count + 2}x}" if item_address else "none"
