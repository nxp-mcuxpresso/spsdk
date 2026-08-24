#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IPED V2 register-image table creator.

The module serializes IPED XSPI register-image tables used by boot ROM/ELE handoff
on devices with XSPI IPED hardware. The binary format is a direct dump of XSPI IPED hardware
registers (16 contexts with IV, START, END, AAD fields plus IPEDCTRL/IPEDCTXCTRL).
IPED/PRINCE data encryption uses a built-in pure-Python PRINCE cipher implementation.
When the optional C++ ``iped-offline-tool`` package is installed, it is preferred
for ~100-150x better performance on large data sets.
"""

import logging
import os
from copy import deepcopy
from struct import pack, unpack_from
from typing import Any

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness, align_block, file_extension, value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class IpedMode(SpsdkEnum):
    """IPED context mode."""

    CTR = (0, "ctr", "CTR mode")
    GCM = (1, "gcm", "GCM mode")
    XEX = (2, "xex", "XEX mode")
    BYPASS = (3, "bypass", "Bypass mode")


def _check_u32(value: int, name: str) -> None:
    """Check that value fits into an unsigned 32-bit register field.

    :param value: Value to check.
    :param name: Value name for error reporting.
    :raises SPSDKValueError: If value is outside of unsigned 32-bit range.
    """
    if value < 0 or value > 0xFFFFFFFF:
        raise SPSDKValueError(f"{name} must fit into 32 bits.")


def _words_from_config(config: Config, key: str, default: list[int] | None = None) -> list[int]:
    """Load two 32-bit words from configuration.

    :param config: Source configuration.
    :param key: Configuration key.
    :param default: Default two words if the key is missing.
    :raises SPSDKValueError: If the value does not represent exactly two words.
    :return: List of two 32-bit words.
    """
    value = config.get(key)
    if value is None:
        return default[:] if default is not None else [0, 0]
    if isinstance(value, list):
        if len(value) != 2:
            raise SPSDKValueError(f"IPED {key} must contain exactly two 32-bit words.")
        words = [value_to_int(word) for word in value]
    else:
        data = config.load_symmetric_key(key, expected_size=8, name=f"IPED {key}")
        words = [
            int.from_bytes(data[0:4], byteorder=Endianness.BIG.value),
            int.from_bytes(data[4:8], byteorder=Endianness.BIG.value),
        ]
    for index, word in enumerate(words):
        _check_u32(word, f"{key}[{index}]")
    return words


def _words_to_hex(words: list[int]) -> str:
    """Convert two 32-bit words into one 8-byte hexadecimal value.

    :param words: Two 32-bit words.
    :return: Hexadecimal string.
    """
    if len(words) != 2:
        raise SPSDKValueError("IPED value must contain exactly two 32-bit words.")
    return f"0x{value_to_int(words[0]):08x}{value_to_int(words[1]):08x}"


def _words_to_int(words: list[int]) -> int:
    """Convert two 32-bit words into one 64-bit integer.

    :param words: Two 32-bit words.
    :return: 64-bit integer.
    """
    if len(words) != 2:
        raise SPSDKValueError("IPED value must contain exactly two 32-bit words.")
    return (value_to_int(words[0]) << 32) | value_to_int(words[1])


def _load_iped_key(config: Config) -> bytes | None:
    """Load optional 128-bit effective IPED encryption key from configuration.

    :param config: Context configuration.
    :return: Effective IPED key or None if the key is not configured.
    """
    if config.get("key") is None:
        return None
    return config.load_symmetric_key("key", expected_size=16, name="IPED encryption key")


def _load_iped_backend() -> tuple[type[Any], type[Exception]]:
    """Load IPED encryption backend.

    Uses the built-in pure-Python PRINCE implementation as the primary backend.
    If the optional C++ ``iped-offline-tool`` package is installed, it is preferred
    for significantly better performance (~100-150x faster).

    :return: Tuple with backend class and backend exception type.
    """
    try:
        from iped.iped import IPED as OfflineIped
        from iped.iped import IPEDError as OfflineIpedError

        logger.debug("Using C++ iped-offline-tool backend (high performance)")
        return OfflineIped, OfflineIpedError
    except ImportError:
        from spsdk.image.iped.prince import PrinceCipher, PrinceError

        logger.debug("Using built-in Python PRINCE backend (C++ backend not available)")
        return PrinceCipher, PrinceError


class IpedContext:
    """One IPED context register record."""

    FORMAT = "<8I"
    SIZE = 0x20
    ADDRESS_ALIGNMENT = 0x100
    FREEZE_MASK = 0x3
    KEY_SIZE = 16
    ENCRYPTION_BLOCK_SIZE = 8

    def __init__(
        self,
        start_address: int,
        end_address: int,
        mode: IpedMode = IpedMode.CTR,
        iv: list[int] | None = None,
        aad: list[int] | None = None,
        freeze: int = 0,
        address_alignment: int = ADDRESS_ALIGNMENT,
        key: bytes | None = None,
    ) -> None:
        """Initialize IPED context.

        :param start_address: Start address of the IPED region.
        :param end_address: End address of the IPED region.
        :param mode: IPED context mode.
        :param iv: Two 32-bit IV words.
        :param aad: Two 32-bit AAD words.
        :param freeze: Two-bit context freeze value.
        :param address_alignment: Required region address alignment.
        :param key: Optional 128-bit effective IPED encryption key for data blobs.
        :raises SPSDKValueError: If the context parameters are invalid.
        """
        self.start_address = value_to_int(start_address)
        self.end_address = value_to_int(end_address)
        self.mode = mode
        self.iv = iv[:] if iv else [0, 0]
        self.aad = aad[:] if aad else [0, 0]
        self.freeze = value_to_int(freeze)
        self.address_alignment = value_to_int(address_alignment)
        self.key = key
        self.validate()

    def validate(self) -> None:
        """Validate IPED context fields.

        :raises SPSDKValueError: If the context fields are invalid.
        """
        _check_u32(self.start_address, "start_address")
        _check_u32(self.end_address, "end_address")
        if self.end_address < self.start_address:
            raise SPSDKValueError("IPED context end_address must be greater than start_address.")
        if self.address_alignment <= 0:
            raise SPSDKValueError("IPED address alignment must be positive.")
        if self.start_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED context start_address must be aligned to {hex(self.address_alignment)}."
            )
        if self.end_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED context end_address must be aligned to {hex(self.address_alignment)}."
            )
        if self.freeze & ~self.FREEZE_MASK:
            raise SPSDKValueError(
                f"IPED context freeze value exceeds mask {hex(self.FREEZE_MASK)}."
            )
        for field_name, words in (("iv", self.iv), ("aad", self.aad)):
            if len(words) != 2:
                raise SPSDKValueError(f"IPED context {field_name} must contain two words.")
            for index, word in enumerate(words):
                _check_u32(value_to_int(word), f"{field_name}[{index}]")
        if self.key is not None and len(self.key) != self.KEY_SIZE:
            raise SPSDKValueError(f"IPED context key must be {self.KEY_SIZE} bytes long.")

    @property
    def start_register(self) -> int:
        """Get serialized START register value.

        :return: START register value with mode bits.
        """
        return self.start_address | self.mode.tag

    def export(self) -> bytes:
        """Export context into the XSPI IPED register-image layout.

        :return: Serialized context bytes.
        """
        return pack(
            self.FORMAT,
            self.iv[0],
            self.iv[1],
            self.start_register,
            self.end_address,
            self.aad[0],
            self.aad[1],
            0,
            0,
        )

    def matches_range(self, start_address: int, end_address: int) -> bool:
        """Check if the context fully contains an address range.

        :param start_address: Start address of the range.
        :param end_address: Exclusive end address of the range.
        :return: True if the range fits into the context.
        """
        return self.start_address <= start_address and end_address <= self.end_address

    def encrypt_data(self, data: bytes, address: int, double_encryption: bool) -> bytes:
        """Encrypt data using this IPED context.

        :param data: Plain data to encrypt.
        :param address: Absolute address where data will be stored.
        :param double_encryption: Enable double encryption in the IPED backend.
        :raises SPSDKError: If encryption cannot be performed.
        :return: Encrypted data aligned to IPED block size.
        """
        data = align_block(data, self.ENCRYPTION_BLOCK_SIZE)
        if self.mode == IpedMode.BYPASS:
            return data
        if self.mode == IpedMode.XEX:
            raise SPSDKError("IPED XEX data encryption is not supported by iped-offline-tool.")
        if self.key is None:
            raise SPSDKError(
                f"IPED context {hex(self.start_address)}-{hex(self.end_address)} has no key "
                "configured for data encryption."
            )

        backend_cls, backend_error = _load_iped_backend()
        try:
            backend = backend_cls(
                key=self.key,
                address=address,
                iv=_words_to_int(self.iv),
                double_encrypt=double_encryption,
                use_gcm=self.mode == IpedMode.GCM,
                aad=_words_to_int(self.aad),
            )
            encrypted = backend.encrypt(data=data)
        except backend_error as exc:
            raise SPSDKError(f"IPED data encryption failed: {exc}") from exc
        return bytes(encrypted)

    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        address_alignment: int = ADDRESS_ALIGNMENT,
        freeze: int = 0,
    ) -> Self:
        """Parse IPED context from the XSPI IPED register-image layout.

        :param data: Binary data containing the context record.
        :param offset: Offset of the context record in the binary data.
        :param address_alignment: Required region address alignment.
        :param freeze: Two-bit context freeze value from IPEDCTXCTRL.
        :raises SPSDKValueError: If the context record is invalid.
        :return: Parsed IPED context object.
        """
        if len(data) < offset + cls.SIZE:
            raise SPSDKValueError("IPED context data is too short.")
        iv0, iv1, start_register, end_address, aad0, aad1, reserved0, reserved1 = unpack_from(
            cls.FORMAT, data, offset
        )
        if reserved0 or reserved1:
            raise SPSDKValueError("IPED context reserved words must be zero.")
        return cls(
            start_address=start_register & ~0x3,
            end_address=end_address,
            mode=IpedMode.from_tag(start_register & 0x3),
            iv=[iv0, iv1],
            aad=[aad0, aad1],
            freeze=freeze,
            address_alignment=address_alignment,
        )

    @classmethod
    def load_from_config(cls, config: Config, address_alignment: int) -> Self:
        """Load IPED context from configuration.

        :param config: Context configuration.
        :param address_alignment: Required region address alignment.
        :return: IPED context object.
        """
        return cls(
            start_address=config.get_int("start_address"),
            end_address=config.get_int("end_address"),
            mode=IpedMode.from_label(config.get_str("mode", IpedMode.CTR.label)),
            iv=_words_from_config(config, "iv"),
            aad=_words_from_config(config, "aad"),
            freeze=config.get_int("freeze", 0),
            address_alignment=address_alignment,
            key=_load_iped_key(config),
        )

    def get_config(self) -> dict[str, str | int]:
        """Get context configuration.

        :return: Configuration dictionary.
        """
        return {
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "mode": self.mode.label,
            "iv": _words_to_hex(self.iv),
            "aad": _words_to_hex(self.aad),
            "freeze": self.freeze,
        }


class IpedV2(FeatureBaseClass):
    """IPED V2 register-image table creator.

    The binary format is a direct dump of XSPI IPED hardware registers: 16 context
    slots (IV, START|mode, END, AAD, reserved) followed by IPEDCTRL, a reserved word,
    and two IPEDCTXCTRL words.

    The boolean control flags map to IPEDCTRL bits. The IP path is the memory controller
    command interface, while the AHB path is the memory-mapped XIP bus. Enable only the
    read/write flags that match the configured context modes and intended access path.
    """

    FEATURE = DatabaseManager.IPED

    CONTEXT_COUNT = 16
    RAW_TABLE_SIZE = CONTEXT_COUNT * IpedContext.SIZE + 0x10

    IPEDCTRL_CONFIG = 1 << 0
    IPEDCTRL_IPED_EN = 1 << 1
    IPEDCTRL_IPWR_EN = 1 << 2
    IPEDCTRL_AHBWR_EN = 1 << 3
    IPEDCTRL_AHBRD_EN = 1 << 4
    IPEDCTRL_IPGCMWR = 1 << 6
    IPEDCTRL_AHGCMWR = 1 << 7
    IPEDCTRL_AHBGCMRD = 1 << 8
    IPEDCTRL_IPED_PROTECT = 1 << 9
    IPEDCTRL_IPED_XEX_EN = 1 << 11
    IPEDCTRL_IPSXEXWE = 1 << 12
    IPEDCTRL_AHBXEXWE = 1 << 13
    IPEDCTRL_AHBXEXRE = 1 << 14

    def __init__(
        self,
        family: FamilyRevision,
        contexts: list[IpedContext] | None = None,
        table_size: int | None = None,
        control_word: int | None = None,
        context_control: list[int] | None = None,
        double_encryption: bool = False,
        enable: bool = True,
        ip_write_enable: bool = False,
        ahb_write_enable: bool = False,
        ahb_read_enable: bool = True,
        ip_gcm_write_enable: bool = False,
        ahb_gcm_write_enable: bool = False,
        ahb_gcm_read_enable: bool = False,
        protection: bool = False,
        xex_enable: bool = False,
        ip_xex_write_enable: bool = False,
        ahb_xex_write_enable: bool = False,
        ahb_xex_read_enable: bool = False,
        output_name: str = "iped_table",
        encrypted_name: str = "encrypted_blob",
        image_name: str = "iped_image",
        output_format: str = "bin",
        keyblob_address: int = 0,
        binaries: BinaryImage | None = None,
        data_alignment: int = IpedContext.ENCRYPTION_BLOCK_SIZE,
    ) -> None:
        """Initialize IPED table.

        :param family: Target family.
        :param contexts: List of configured IPED contexts.
        :param table_size: Exported table size including padding.
        :param control_word: Raw IPEDCTRL word; if set, boolean control flags are ignored.
        :param context_control: Two raw IPEDCTXCTRL words.
        :param double_encryption: Enable the IPED double encryption/decryption path.
        :param enable: Enable the IPED CTR/GCM engine.
        :param ip_write_enable: Enable CTR encryption for IP-command writes.
        :param ahb_write_enable: Enable CTR encryption for memory-mapped AHB/XIP writes.
        :param ahb_read_enable: Enable CTR decryption for memory-mapped AHB/XIP reads.
        :param ip_gcm_write_enable: Enable GCM encryption for IP-command writes.
        :param ahb_gcm_write_enable: Enable GCM encryption for memory-mapped AHB/XIP writes.
        :param ahb_gcm_read_enable: Enable GCM decryption for memory-mapped AHB/XIP reads.
        :param protection: Enable hardware protection of the loaded IPED configuration.
        :param xex_enable: Enable the IPED XEX engine.
        :param ip_xex_write_enable: Enable XEX encryption for IP-command writes.
        :param ahb_xex_write_enable: Enable XEX encryption for memory-mapped AHB/XIP writes.
        :param ahb_xex_read_enable: Enable XEX decryption for memory-mapped AHB/XIP reads.
        :param output_name: Output file name without extension for CLI export.
        :param encrypted_name: Output file name without extension for encrypted data blobs.
        :param image_name: Output file name without extension for table and encrypted data image.
        :param output_format: Output file format.
        :param keyblob_address: Absolute address where the IPED table/keyblob is placed.
        :param binaries: Optional plain data blobs to encrypt.
        :param data_alignment: Alignment of encrypted data blobs in the output image.
        :raises SPSDKValueError: If the table configuration is invalid.
        """
        self.family = family
        if family.name not in [device.name for device in self.get_supported_families()]:
            raise SPSDKValueError(f"IPED is not supported for family {family}.")
        self.db = get_db(family)
        self.contexts = contexts[:] if contexts else []
        self.max_contexts = self.db.get_int(self.FEATURE, "max_contexts")
        self.min_contexts = self.db.get_int(self.FEATURE, "min_contexts")
        self.address_alignment = self.db.get_int(self.FEATURE, "address_alignment")
        self.table_size = value_to_int(
            table_size if table_size is not None else self.db.get_int(self.FEATURE, "table_size")
        )
        self.control_word = (
            value_to_int(control_word)
            if control_word is not None
            else self.compose_control_word(
                double_encryption=double_encryption,
                enable=enable,
                ip_write_enable=ip_write_enable,
                ahb_write_enable=ahb_write_enable,
                ahb_read_enable=ahb_read_enable,
                ip_gcm_write_enable=ip_gcm_write_enable,
                ahb_gcm_write_enable=ahb_gcm_write_enable,
                ahb_gcm_read_enable=ahb_gcm_read_enable,
                protection=protection,
                xex_enable=xex_enable,
                ip_xex_write_enable=ip_xex_write_enable,
                ahb_xex_write_enable=ahb_xex_write_enable,
                ahb_xex_read_enable=ahb_xex_read_enable,
            )
        )
        self.context_control = context_control[:] if context_control else [0, 0]
        self.output_name = output_name
        self.encrypted_name = encrypted_name
        self.image_name = image_name
        self.output_format = output_format
        self.keyblob_address = value_to_int(keyblob_address)
        self.binaries = binaries
        self.data_alignment = value_to_int(data_alignment)
        self.validate()

    def __repr__(self) -> str:
        """Get text representation of IPED table.

        :return: Text representation.
        """
        return f"IPED table for {self.family}"

    def __str__(self) -> str:
        """Get text representation of IPED table.

        :return: Text representation.
        """
        return self.__repr__()

    @classmethod
    def compose_control_word(
        cls,
        double_encryption: bool,
        enable: bool,
        ip_write_enable: bool,
        ahb_write_enable: bool,
        ahb_read_enable: bool,
        ip_gcm_write_enable: bool,
        ahb_gcm_write_enable: bool,
        ahb_gcm_read_enable: bool,
        protection: bool,
        xex_enable: bool,
        ip_xex_write_enable: bool,
        ahb_xex_write_enable: bool,
        ahb_xex_read_enable: bool,
    ) -> int:
        """Compose IPEDCTRL register value from boolean flags.

        The caller is responsible for enabling flags consistent with the context mode.
        A decrypted-XIP CTR boot flow typically uses ``enable`` and ``ahb_read_enable``.

        :param double_encryption: Enable the IPED double encryption/decryption path.
        :param enable: Enable the IPED CTR/GCM engine.
        :param ip_write_enable: Enable CTR encryption for IP-command writes.
        :param ahb_write_enable: Enable CTR encryption for memory-mapped AHB/XIP writes.
        :param ahb_read_enable: Enable CTR decryption for memory-mapped AHB/XIP reads.
        :param ip_gcm_write_enable: Enable GCM encryption for IP-command writes.
        :param ahb_gcm_write_enable: Enable GCM encryption for memory-mapped AHB/XIP writes.
        :param ahb_gcm_read_enable: Enable GCM decryption for memory-mapped AHB/XIP reads.
        :param protection: Enable hardware protection of the loaded IPED configuration.
        :param xex_enable: Enable the IPED XEX engine.
        :param ip_xex_write_enable: Enable XEX encryption for IP-command writes.
        :param ahb_xex_write_enable: Enable XEX encryption for memory-mapped AHB/XIP writes.
        :param ahb_xex_read_enable: Enable XEX decryption for memory-mapped AHB/XIP reads.
        :return: IPEDCTRL register value.
        """
        flags = (
            (double_encryption, cls.IPEDCTRL_CONFIG),
            (enable, cls.IPEDCTRL_IPED_EN),
            (ip_write_enable, cls.IPEDCTRL_IPWR_EN),
            (ahb_write_enable, cls.IPEDCTRL_AHBWR_EN),
            (ahb_read_enable, cls.IPEDCTRL_AHBRD_EN),
            (ip_gcm_write_enable, cls.IPEDCTRL_IPGCMWR),
            (ahb_gcm_write_enable, cls.IPEDCTRL_AHGCMWR),
            (ahb_gcm_read_enable, cls.IPEDCTRL_AHBGCMRD),
            (protection, cls.IPEDCTRL_IPED_PROTECT),
            (xex_enable, cls.IPEDCTRL_IPED_XEX_EN),
            (ip_xex_write_enable, cls.IPEDCTRL_IPSXEXWE),
            (ahb_xex_write_enable, cls.IPEDCTRL_AHBXEXWE),
            (ahb_xex_read_enable, cls.IPEDCTRL_AHBXEXRE),
        )
        control_word = 0
        for enabled, bit in flags:
            if enabled:
                control_word |= bit
        return control_word

    def validate(self) -> None:
        """Validate IPED table configuration.

        :raises SPSDKValueError: If the table configuration is invalid.
        """
        if len(self.contexts) < self.min_contexts:
            raise SPSDKValueError(
                f"At least {self.min_contexts} IPED context(s) must be configured."
            )
        if len(self.contexts) > self.max_contexts or len(self.contexts) > self.CONTEXT_COUNT:
            raise SPSDKValueError(
                f"IPED supports at most {min(self.max_contexts, self.CONTEXT_COUNT)} contexts."
            )
        if len(self.context_control) != 2:
            raise SPSDKValueError("IPED context_control must contain exactly two words.")
        if self.table_size < self.RAW_TABLE_SIZE:
            raise SPSDKValueError(
                f"IPED table_size must be at least {hex(self.RAW_TABLE_SIZE)} bytes."
            )
        _check_u32(self.control_word, "control_word")
        for index, word in enumerate(self.context_control):
            _check_u32(value_to_int(word), f"context_control[{index}]")
        for context in self.contexts:
            context.validate()
        _check_u32(self.keyblob_address, "keyblob_address")
        if self.data_alignment <= 0:
            raise SPSDKValueError("IPED data_alignment must be positive.")
        if self.binaries is not None:
            self.binaries.validate()

    def _context_control_words(self) -> list[int]:
        """Get IPEDCTXCTRL words with freeze fields applied.

        :return: Two IPEDCTXCTRL words.
        """
        words = self.context_control[:]
        for index, context in enumerate(self.contexts):
            words[0] |= context.freeze << (index * 2)
        return words

    def export(self) -> bytes:
        """Export IPED table into binary form.

        :return: IPED table padded to configured table size.
        """
        data = b""
        for context in self.contexts:
            data += context.export()
        data += bytes(IpedContext.SIZE * (self.CONTEXT_COUNT - len(self.contexts)))
        data += pack("<IIII", self.control_word, 0, *self._context_control_words())
        return align_block(data, self.table_size, padding=0)

    @property
    def double_encryption(self) -> bool:
        """Return whether double encryption is enabled in IPEDCTRL.

        :return: True if double encryption is enabled.
        """
        return bool(self.control_word & self.IPEDCTRL_CONFIG)

    def _get_context_for_range(self, start_address: int, data_size: int) -> IpedContext:
        """Find IPED context that fully contains data range.

        :param start_address: Start address of the data.
        :param data_size: Data size in bytes.
        :raises SPSDKError: If no context fully contains the data range.
        :return: Matching IPED context.
        """
        aligned_size = (
            (data_size + IpedContext.ENCRYPTION_BLOCK_SIZE - 1)
            // IpedContext.ENCRYPTION_BLOCK_SIZE
            * IpedContext.ENCRYPTION_BLOCK_SIZE
        )
        end_address = start_address + aligned_size
        for context in self.contexts:
            if context.matches_range(start_address, end_address):
                return context
        raise SPSDKError(
            f"No IPED context covers data range {hex(start_address)}-{hex(end_address)}."
        )

    def encrypt_image(self, image: bytes, base_addr: int) -> bytes:
        """Encrypt one data blob with the matching IPED context.

        :param image: Plain data blob.
        :param base_addr: Absolute address where the blob will be stored.
        :raises SPSDKError: If no context matches the blob range or backend encryption fails.
        :return: Encrypted data blob.
        """
        context = self._get_context_for_range(base_addr, len(image))
        logger.debug(
            f"Encrypting IPED data range {hex(base_addr)}:"
            f"{hex(base_addr + len(image))} using {context.mode.label} context."
        )
        return context.encrypt_data(image, base_addr, self.double_encryption)

    def export_image(self) -> BinaryImage | None:
        """Export encrypted data blobs.

        :return: Encrypted binary image, or None if no data blobs are configured.
        """
        if self.binaries is None:
            return None
        binaries: BinaryImage = deepcopy(self.binaries)
        binaries.validate()
        for binary in binaries.sub_images:
            binary.alignment = IpedContext.ENCRYPTION_BLOCK_SIZE
            binary.binary = self.encrypt_image(
                binary.export(), binary.absolute_address + self.keyblob_address
            )
            binary.sub_images = []
        binaries.alignment = self.data_alignment
        binaries.validate()
        return binaries

    def binary_image(self, encrypted_image: BinaryImage | None = None) -> BinaryImage:
        """Get IPED table and encrypted blobs as a binary image.

        :param encrypted_image: Precomputed encrypted data blobs.
        :return: Complete IPED image.
        """
        iped_image = BinaryImage(self.image_name, offset=self.keyblob_address)
        keyblob = BinaryImage(
            name=self.output_name,
            size=self.table_size,
            offset=0,
            description=f"IPED table/keyblob for {self.family}",
            binary=self.export(),
            alignment=self.table_size,
        )
        iped_image.add_image(keyblob)
        if encrypted_image:
            iped_image.add_image(encrypted_image)
        return iped_image

    def post_export(self, output_path: str) -> list[str]:
        """Export IPED table and optional encrypted data files.

        :param output_path: Output directory.
        :return: List of generated files.
        """
        os.makedirs(output_path, exist_ok=True)
        extension = file_extension(self.output_format)
        output_file = os.path.join(output_path, f"{self.output_name}{extension}")
        image = BinaryImage(name=self.output_name, binary=self.export(), size=self.table_size)
        image.save_binary_image(output_file, file_format=self.output_format)
        generated_files = [output_file]

        encrypted_image = self.export_image()
        if encrypted_image is None:
            return generated_files

        encrypted_file = os.path.join(output_path, f"{self.encrypted_name}{extension}")
        encrypted_export = deepcopy(encrypted_image)
        encrypted_export.offset = 0
        encrypted_export.save_binary_image(encrypted_file, file_format=self.output_format)
        generated_files.append(encrypted_file)

        full_image = self.binary_image(encrypted_image=encrypted_image)
        full_image.offset -= self.keyblob_address
        image_file = os.path.join(output_path, f"{self.image_name}{extension}")
        full_image.save_binary_image(image_file, file_format=self.output_format)
        generated_files.append(image_file)
        return generated_files

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision | None = None) -> Self:
        """Parse IPED table from bytes.

        :param data: Input binary data.
        :param family: Target family used for family-specific validation.
        :raises SPSDKValueError: If the table is invalid or family is not provided.
        :return: Parsed IPED table.
        """
        if family is None:
            raise SPSDKValueError("Family must be specified to parse IPED table.")
        if len(data) < cls.RAW_TABLE_SIZE:
            raise SPSDKValueError(
                f"IPED table must be at least {hex(cls.RAW_TABLE_SIZE)} bytes long."
            )
        if any(data[cls.RAW_TABLE_SIZE :]):
            raise SPSDKValueError("IPED table padding must contain only zeros.")

        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")
        control_word, reserved, context_control0, context_control1 = unpack_from(
            "<IIII", data, IpedContext.SIZE * cls.CONTEXT_COUNT
        )
        if reserved:
            raise SPSDKValueError("IPED table reserved word must be zero.")

        last_used_context = -1
        for index in range(cls.CONTEXT_COUNT):
            offset = index * IpedContext.SIZE
            context_data = data[offset : offset + IpedContext.SIZE]
            if context_data != bytes(IpedContext.SIZE):
                last_used_context = index

        contexts = []
        for index in range(last_used_context + 1):
            offset = index * IpedContext.SIZE
            contexts.append(
                IpedContext.parse(
                    data=data,
                    offset=offset,
                    address_alignment=address_alignment,
                    freeze=(context_control0 >> (index * 2)) & IpedContext.FREEZE_MASK,
                )
            )

        return cls(
            family=family,
            contexts=contexts,
            table_size=len(data),
            control_word=control_word,
            context_control=[context_control0, context_control1],
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for IPED configuration.

        :param family: Target family.
        :return: List of validation schemas.
        """
        database = get_db(family)
        schemas = get_schema_file(cls.FEATURE)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        sch_family["main_title"] = f"IPED table Configuration for {family}."
        try:
            mem_block = database.device.info.memory_map.get_memory(block_name="flexspi1_ns")
            base_address = mem_block.base_address
            schemas["iped"]["properties"]["contexts"]["items"]["properties"]["start_address"][
                "template_value"
            ] = hex(base_address + 0x1000)
            schemas["iped"]["properties"]["contexts"]["items"]["properties"]["end_address"][
                "template_value"
            ] = hex(base_address + 0x2000)
        except SPSDKError:
            pass
        schemas["iped"]["properties"]["table_size"]["template_value"] = hex(
            database.get_int(cls.FEATURE, "table_size")
        )
        schemas["iped"]["properties"]["keyblob_address"]["template_value"] = hex(
            cls.get_default_keyblob_address(family)
        )
        return [sch_family, schemas["iped_output"], schemas["iped"]]

    @staticmethod
    def get_default_keyblob_address(family: FamilyRevision) -> int:
        """Get default absolute IPED table/keyblob address for a family.

        :param family: Target family.
        :return: Default absolute address.
        """
        try:
            return (
                get_db(family)
                .device.info.memory_map.get_memory(block_name="flexspi1_ns")
                .base_address
            )
        except SPSDKError:
            return 0

    def get_config(self, data_path: str = "./") -> Config:
        """Create IPED configuration.

        :param data_path: Path to store data files.
        :return: IPED configuration.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["output_folder"] = data_path
        config["output_name"] = self.output_name
        config["encrypted_name"] = self.encrypted_name
        config["image_name"] = self.image_name
        config["output_format"] = self.output_format
        config["keyblob_address"] = hex(self.keyblob_address)
        config["data_alignment"] = self.data_alignment
        config["table_size"] = hex(self.table_size)
        config["control_word"] = hex(self.control_word)
        config["context_control"] = [hex(word) for word in self.context_control]
        config["contexts"] = [context.get_config() for context in self.contexts]
        return config

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load IPED table from configuration.

        :param config: IPED configuration.
        :return: IPED table object.
        """
        family = FamilyRevision.load_from_config(config)
        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")
        contexts = [
            IpedContext.load_from_config(context_config, address_alignment)
            for context_config in config.get_list_of_configs("contexts")
        ]
        context_control = None
        if config.get("context_control") is not None:
            context_control = [value_to_int(word) for word in config.get_list("context_control")]

        keyblob_address = config.get_int("keyblob_address", cls.get_default_keyblob_address(family))
        binaries = None
        if "data_blobs" in config:
            data_blobs = config.get_list_of_configs("data_blobs")
            if data_blobs:
                start_address = min([data_blob.get_int("address") for data_blob in data_blobs])
                binaries = BinaryImage(
                    config.get_str("encrypted_name", "encrypted_blob"),
                    offset=start_address - keyblob_address,
                    alignment=IpedContext.ENCRYPTION_BLOCK_SIZE,
                )
                for data_blob in data_blobs:
                    data_file_name = data_blob.get_input_file_name("data")
                    binary = BinaryImage.load_binary_image(
                        path=data_file_name,
                        name=os.path.basename(data_file_name),
                        alignment=IpedContext.ENCRYPTION_BLOCK_SIZE,
                        size=0,
                    )
                    address = data_blob.get_int("address", binary.absolute_address)
                    expected_offset = address - keyblob_address - binaries.offset
                    if binary.offset != expected_offset:
                        logger.warning(
                            f"The data blob {data_file_name} has different offset {binary.offset}, "
                            f"than expected {expected_offset}."
                        )
                        binary.offset = expected_offset
                    binaries.add_image(binary)

        return cls(
            family=family,
            contexts=contexts,
            table_size=config.get_int("table_size", database.get_int(cls.FEATURE, "table_size")),
            control_word=(
                config.get_int("control_word") if config.get("control_word") is not None else None
            ),
            context_control=context_control,
            double_encryption=config.get_bool("double_encryption", False),
            enable=config.get_bool("enable", True),
            ip_write_enable=config.get_bool("ip_write_enable", False),
            ahb_write_enable=config.get_bool("ahb_write_enable", False),
            ahb_read_enable=config.get_bool("ahb_read_enable", True),
            ip_gcm_write_enable=config.get_bool("ip_gcm_write_enable", False),
            ahb_gcm_write_enable=config.get_bool("ahb_gcm_write_enable", False),
            ahb_gcm_read_enable=config.get_bool("ahb_gcm_read_enable", False),
            protection=config.get_bool("protection", False),
            xex_enable=config.get_bool("xex_enable", False),
            ip_xex_write_enable=config.get_bool("ip_xex_write_enable", False),
            ahb_xex_write_enable=config.get_bool("ahb_xex_write_enable", False),
            ahb_xex_read_enable=config.get_bool("ahb_xex_read_enable", False),
            output_name=config.get_str("output_name", "iped_table"),
            encrypted_name=config.get_str("encrypted_name", "encrypted_blob"),
            image_name=config.get_str("image_name", "iped_image"),
            output_format=config.get_str("output_format", "bin"),
            keyblob_address=keyblob_address,
            binaries=binaries,
            data_alignment=config.get_int("data_alignment", IpedContext.ENCRYPTION_BLOCK_SIZE),
        )

    def verify(self) -> Verifier:
        """Verify IPED table.

        :return: Verification result.
        """
        ret = Verifier(f"IPED table for {self.family}")
        try:
            self.validate()
            ret.add_record("Configuration", VerifierResult.SUCCEEDED, "Valid")
        except SPSDKError as exc:
            ret.add_record("Configuration", VerifierResult.ERROR, str(exc))
        ret.add_record_range("Contexts", len(self.contexts), min_val=self.min_contexts)
        ret.add_record_range("Table size", self.table_size, min_val=self.RAW_TABLE_SIZE)
        ret.add_record(
            "Data blobs", VerifierResult.SUCCEEDED, "Configured" if self.binaries else "None"
        )
        return ret
