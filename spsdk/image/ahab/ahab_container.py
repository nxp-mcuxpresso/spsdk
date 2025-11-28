#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK AHAB container implementation for Advanced High-Assurance Boot.

This module provides classes for creating, parsing, and manipulating AHAB containers
used in NXP's Advanced High-Assurance Boot architecture. It supports multiple container
versions, signature verification, encrypted firmware images, and SRK management for
secure boot chains.
Main classes include AHABContainerBase, AHABContainer, AHABContainerV1forV2, and
AHABContainerV2 for different container versions and configurations.
"""

import logging
from struct import pack, unpack
from typing import Optional, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.fuses.fuses import FuseScript
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import (
    CONTAINER_ALIGNMENT,
    LITTLE_ENDIAN,
    RESERVED,
    UINT8,
    UINT16,
    UINT32,
    AhabChipConfig,
    AhabChipContainerConfig,
    AHABTags,
    FlagsSrkSet,
)
from spsdk.image.ahab.ahab_iae import ImageArrayEntry, ImageArrayEntryTemplates, ImageArrayEntryV2
from spsdk.image.ahab.ahab_sign_block import SignatureBlock, SignatureBlockV2
from spsdk.image.ahab.ahab_srk import SRKTableArray
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import align, extend_block, get_abs_path, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class AHABContainerBase(HeaderContainer):
    """AHAB Container base class for secure boot operations.

    This class provides the foundation for all AHAB (Advanced High Assurance Boot)
    container implementations, handling common header format, signature verification,
    and security configuration. AHAB containers are used for both signed messages
    and bootable images in NXP secure boot process.
    Container header structure::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +--------------------------------+---------------------------------+
        |             Payload (Signed Message or Image Array)              |
        +------------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+

    :cvar SIGNATURE_BLOCK: Default signature block class for containers.
    :cvar TAG: Container tag identifier (must be overridden by subclasses).
    :cvar VERSION: Container format version.
    :cvar CONTAINER_SIZE: Default container size in bytes.
    """

    SIGNATURE_BLOCK = SignatureBlock

    TAG = 0x00  # Need to be updated by child class
    VERSION = 0x00
    NAME = "Container"
    CONTAINER_SIZE = 0x400
    FLAGS_SRK_SET_OFFSET = 0
    FLAGS_SRK_SET_SIZE = 2

    FLAGS_USED_SRK_ID_OFFSET = 4
    FLAGS_USED_SRK_ID_SIZE = 2
    FLAGS_SRK_REVOKE_MASK_OFFSET = 8
    FLAGS_SRK_REVOKE_MASK_SIZE = 4

    DIFF_ATTRIBUTES_VALUES = ["flags", "fuse_version", "sw_version"]
    DIFF_ATTRIBUTES_OBJECTS = ["signature_block"]

    def __init__(
        self,
        chip_config: AhabChipConfig,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        signature_block: Optional[Union[SignatureBlock, SignatureBlockV2]] = None,
    ):
        """Initialize AHAB container with configuration and security parameters.

        :param chip_config: Chip-specific configuration for AHAB container.
        :param flags: Container flags controlling behavior and security settings.
        :param fuse_version: Minimum fuse version required, must be equal to or greater than the
            version stored in fuses to allow loading this container.
        :param sw_version: Software version used by PHBC (Privileged Host Boot Companion) to
            select between multiple images with same fuse version.
        :param signature_block: Optional signature block for container authentication.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self.flags = flags
        self.fuse_version = fuse_version
        self.sw_version = sw_version
        self.signature_block = signature_block
        self.chip_config = AhabChipContainerConfig(
            base=chip_config,
            used_srk_id=self.flag_used_srk_id,
            srk_set=self.flag_srk_set,
            srk_revoke_keys=self.flag_srk_revoke_keys,
            locked=False,
        )

    def __eq__(self, other: object) -> bool:
        """Check equality of AHAB container objects.

        Compares this AHAB container instance with another object to determine if they are equal.
        The comparison includes the parent class equality check and specific AHAB container
        attributes: flags, fuse_version, and sw_version.

        :param other: Object to compare with this AHAB container instance.
        :return: True if objects are equal, False otherwise.
        """
        if isinstance(other, type(self)):
            if (
                super().__eq__(other)
                and self.flags == other.flags
                and self.fuse_version == other.fuse_version
                and self.sw_version == other.sw_version
            ):
                return True

        return False

    def set_flags(
        self, srk_set: str = "none", used_srk_id: int = 0, srk_revoke_mask: int = 0
    ) -> None:
        """Set the flags value for AHAB container.

        Updates the container flags based on SRK configuration and also synchronizes
        the chip configuration with the provided values.

        :param srk_set: Super Root Key (SRK) set identifier
        :param used_srk_id: Index of the key from SRK set being used
        :param srk_revoke_mask: Bitmask indicating which SRK keys are revoked
        """
        flags = FlagsSrkSet.from_attr(srk_set.lower()).tag
        flags |= used_srk_id << 4
        flags |= srk_revoke_mask << 8
        self.flags = flags

        # Update also chip configuration accordingly
        self.chip_config.srk_set = FlagsSrkSet.from_attr(srk_set.lower())
        self.chip_config.srk_revoke_keys = srk_revoke_mask
        self.chip_config.used_srk_id = used_srk_id

    @property
    def flag_srk_set(self) -> FlagsSrkSet:
        """Get SRK set flag in string representation.

        Extract and return the SRK (Super Root Key) set flag from the container flags field.
        The flag indicates which SRK set is being used for authentication.

        :return: SRK Set flag enumeration value.
        """
        srk_set = (self.flags >> self.FLAGS_SRK_SET_OFFSET) & ((1 << self.FLAGS_SRK_SET_SIZE) - 1)
        return FlagsSrkSet.from_tag(srk_set)

    @property
    def flag_used_srk_id(self) -> int:
        """Get the used SRK ID flag from container flags.

        This method extracts the SRK (Super Root Key) ID that is currently being used
        from the container flags field using bit manipulation.

        :return: Index of the used SRK ID extracted from flags.
        """
        return (self.flags >> self.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << self.FLAGS_USED_SRK_ID_SIZE) - 1
        )

    @property
    def flag_srk_revoke_keys(self) -> int:
        """Get SRK revoke mask flag from container flags.

        Extracts the SRK (Super Root Key) revoke mask from the container flags field
        by applying bit shifting and masking operations.

        :return: SRK revoke mask value indicating which keys are revoked.
        """
        srk_revoke_mask = (self.flags >> self.FLAGS_SRK_REVOKE_MASK_OFFSET) & (
            (1 << self.FLAGS_SRK_REVOKE_MASK_SIZE) - 1
        )
        return srk_revoke_mask

    @property
    def flag_srk_revoke_mask(self) -> str:
        """Get SRK revoke mask flag in hexadecimal format.

        :return: SRK revoke mask represented as hexadecimal string.
        """
        return hex(self.flag_srk_revoke_keys)

    @property
    def srk_count(self) -> int:
        """Get count of used SRK (Super Root Key) signatures in container.

        :return: Number of SRK signatures used in the container, 0 if no signature block exists.
        """
        if self.signature_block and self.signature_block.srk_assets:
            return self.signature_block.srk_assets.srk_count

        return 0

    def get_srk_hash(self, srk_id: int = 0) -> bytes:
        """Get SRK hash.

        Retrieves the SHA256 hash of the Super Root Key (SRK) table for the specified
        SRK ID. Returns empty bytes if signature block is not available or SRK ID is
        out of range.

        :param srk_id: ID of SRK table in case of using multiple signatures, defaults to 0.
        :return: SHA256 hash of SRK table, or empty bytes if not available.
        """
        if (
            self.signature_block
            and self.signature_block.srk_assets
            and 0 <= srk_id < self.srk_count
        ):
            return self.signature_block.srk_assets.compute_srk_hash(srk_id)
        return b""

    @property
    def _signature_block_offset(self) -> int:
        """Calculate the signature block offset within the container.

        The offset is calculated by aligning the container header and image array entry
        table size to the required container alignment boundary.

        :return: Offset in bytes where the signature block begins.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().__len__(),
            CONTAINER_ALIGNMENT,
        )

    @property
    def image_array_len(self) -> int:
        """Get image array length if available.

        :return: Length of image array.
        """
        return 0

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of AHAB Container.
        """
        # If there are no images just return length of header
        return self.header_length()

    def header_length(self) -> int:
        """Calculate the total length of AHAB Container header.

        The method calculates the base header length and adds the signature block
        length if present.

        :return: Total length in bytes of AHAB Container header including signature block.
        """
        ret = super().__len__()
        if self.signature_block is not None:
            ret += len(self.signature_block)
        return ret  # This returns the fixed length of the container header

    @classmethod
    def format(cls) -> str:
        """Get format string for binary representation of the container.

        Returns the format string that describes the binary layout including flags,
        software version, fuse version, number of images, signature block offset,
        and reserved fields.

        :return: Format string describing the binary structure layout.
        """
        return (
            super().format()
            + UINT32  # Flags
            + UINT16  # SW version
            + UINT8  # Fuse version
            + UINT8  # Number of Images
            + UINT16  # Signature Block Offset
            + UINT16  # Reserved
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        This method refreshes the signature block, updates the container header length,
        and signs the image header to ensure all fields are current and consistent.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # Update the signature block to get overall size of it
        if self.signature_block is not None:
            self.signature_block.update_fields()
        # Update the Container header length
        self.length = self.header_length()
        # # Sign the image header
        self.sign_itself()

    def get_signature_data(self) -> bytes:
        """Get binary data to be signed from the container.

        The container must be properly initialized, so the data are valid for signing, i.e. the
        offsets, lengths etc. must be set prior invoking this method, otherwise improper data will
        be signed.
        The whole container gets serialized first. Afterwards the binary data is sliced so only
        data for signing gets returned. The signature data length is evaluated based on offsets,
        namely the signature block offset, the container signature offset and the container
        signature fixed data length.

        Signature data structure::
            +---------------------------------------------------+----------------+
            |                  Container header                 |                |
            +---+---+-----------+---------+--------+------------+     Data       |
            | S |   |    tag    | length  | length | version    |                |
            | i |   +-----------+---------+--------+------------+                |
            | g |   |                  flags                    |      to        |
            | n |   +---------------------+---------------------+                |
            | a |   |  srk table offset   | certificate offset  |                |
            | t |   +---------------------+---------------------+     Sign       |
            | u |   |     blob offset     | signature offset    |                |
            | r |   +---------------------+---------------------+                |
            | e |   |       SRK Table / SRK Table Array         |                |
            |   +---+-----------+---------+--------+------------+----------------+
            | B | S |   tag     | length  | length | version    | Signature data |
            | l | i +-----------+---------+--------+------------+ fixed length   |
            | o | g |               Reserved                    |                |
            | c | n +-------------------------------------------+----------------+
            | k | a |               Signature data                               |
            |   | t |                                                            |
            |   | u |                                                            |
            |   | r |                                                            |
            |   | e |                                                            |
            +---+---+------------------------------------------------------------+

        :return: Binary data to be signed, empty bytes if signature block is not available.
        """
        if not self.signature_block or not self.signature_block.signature:
            return bytes()  # Its OK to return just empty data - the verifier catch this issue

        signature_offset = self._signature_block_offset + self.signature_block._signature_offset
        return self._export()[:signature_offset]

    def sign_itself(self) -> None:
        """Sign the container using its signature block if signing is required.

        This method performs self-signing of the container when the SRK (Super Root Key) flag
        is set to a value other than NONE. It validates that a signature block exists before
        attempting to sign the container with the signature data.

        :raises SPSDKError: When signing is required but signature block is missing.
        """
        if self.flag_srk_set != FlagsSrkSet.NONE:
            if not self.signature_block:
                raise SPSDKError("Cannot sign because the Signature block is missing.")
            self.signature_block.sign_itself(self.get_signature_data())

    def _export(self) -> bytes:
        """Export container header into bytes.

        The method serializes the container header fields into a binary format using
        the struct.pack function with the container's format specification.

        :return: Bytes representing container header content including the signature block.
        """
        return pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self.flags,
            self.sw_version,
            self.fuse_version,
            self.image_array_len,
            self._signature_block_offset,
            RESERVED,  # Reserved field
        )

    def _verify(self, name: Optional[str] = None, description: Optional[str] = None) -> Verifier:
        """Validate object data.

        Performs comprehensive validation of the AHAB container object including header verification,
        flags validation, and signature block checks.

        :param name: Optional overloaded name for the verifier instance.
        :param description: Optional description for the verifier instance.
        :return: Verifier object containing validation results and child verifications.
        """
        ret = Verifier(name or self.NAME, description=description)
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_bit_range("Flags", self.flags, 32)
        ret.add_record_enum("Flags: SRK Set", self.flag_srk_set, FlagsSrkSet)
        ret.add_record_range("Flags: SRK Selection", self.flag_used_srk_id, min_val=0, max_val=3)
        ret.add_record_bit_range("Flags: SRK Revoke mask", self.flag_srk_revoke_keys, bit_range=4)
        ret.add_record_bit_range("SW version", self.sw_version, bit_range=16)
        ret.add_record_bit_range("Fuse version", self.fuse_version, bit_range=8)
        ret.add_record_range("Signature Block offset", self._signature_block_offset, max_val=65535)

        if self.signature_block:
            ret.add_child(self.signature_block.verify())

        return ret

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-parse and verify AHAB container structure.

        This method performs initial validation of the AHAB container header and
        signature block without full parsing of the container data.

        :param data: Binary data containing the AHAB container block to pre-parse.
        :return: Verifier object containing validation results of the pre-parsed data.
        """
        ret = cls.check_container_head(data)
        if ret.has_errors:
            return ret
        (signature_block_offset, _) = unpack(LITTLE_ENDIAN + UINT16 + UINT16, data[0x0C:0x10])

        ret.add_child(cls.SIGNATURE_BLOCK.pre_parse_verify(data[signature_block_offset:]))
        return ret

    @classmethod
    def _parse(cls, binary: bytes) -> tuple[int, int, int, int, int, int]:
        """Parse input binary chunk to the container object.

        The method extracts and validates AHAB container header fields from binary data,
        returning the essential container configuration parameters.

        :param binary: Binary data with Container block to parse.
        :raises SPSDKError: Invalid container header format or validation failure.
        :return: Tuple of following AHAB container fields:
            - container length
            - flags
            - software version
            - fuse version
            - number of images
            - signature block offset
        """
        cls.check_container_head(binary).validate()
        image_format = cls.format()
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
            _,  # reserved
        ) = unpack(image_format, binary[: cls.fixed_length()])

        return (
            container_length,
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
        )

    def _create_flags_config(self) -> Config:
        """Create configuration of the AHAB container flags.

        The method creates a Config object containing the current flag settings including SRK set,
        used SRK ID, and SRK revoke mask values.

        :return: Configuration dictionary with AHAB container flags.
        """
        cfg = Config()

        cfg["srk_set"] = self.flag_srk_set.label
        cfg["used_srk_id"] = self.flag_used_srk_id
        cfg["srk_revoke_mask"] = self.flag_srk_revoke_mask
        return cfg

    def _create_config(self, index: int, data_path: str) -> Config:
        """Create configuration of the AHAB Image.

        The method generates a configuration dictionary containing fuse version, software version,
        and signature block configuration if present.

        :param index: Container index used for configuration generation.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with AHAB image settings.
        """
        cfg = self._create_flags_config()

        cfg["fuse_version"] = self.fuse_version
        cfg["sw_version"] = self.sw_version

        if self.signature_block:
            cfg.update(self.signature_block.get_config(data_path=data_path, index=index))

        return cfg

    def _load_from_config_flags(self, config: Config) -> None:
        """Load AHAB container flags from configuration.

        The method extracts and sets the SRK (Super Root Key) related flags including
        SRK set identifier, used SRK ID, and SRK revoke mask from the provided
        configuration object.

        :param config: Configuration object containing AHAB container settings.
        """
        self.set_flags(
            srk_set=config.get_str("srk_set", "none"),
            used_srk_id=config.get_int("used_srk_id", 0),
            srk_revoke_mask=config.get_int("srk_revoke_mask", 0),
        )

    def load_from_config_generic(self, config: Config) -> None:
        """Load container configuration into AHAB image object.

        Converts the configuration options into an AHAB image object by setting
        fuse version, software version, chip configuration parameters, and
        signature block from the provided configuration.

        :param config: Configuration object containing AHAB container settings.
        """
        self._load_from_config_flags(config)
        self.fuse_version = config.get_int("fuse_version", 0)
        self.sw_version = config.get_int("sw_version", 0)
        self.chip_config.used_srk_id = self.flag_used_srk_id
        self.chip_config.srk_set = self.flag_srk_set
        self.chip_config.srk_revoke_keys = self.flag_srk_revoke_keys

        self.signature_block = self.SIGNATURE_BLOCK.load_from_config(config, self.chip_config)

    def post_export(self, data_path: str, cnt_ix: Optional[int] = None) -> list[str]:
        """Post export actions for AHAB container.

        :param data_path: Path to store exported data files.
        :param cnt_ix: Container index.
        :raises SPSDKNotImplementedError: Post export action is not implemented.
        """
        raise SPSDKNotImplementedError("Post export action is not implemented")


class AHABContainer(AHABContainerBase):
    """AHAB Container implementation for secure boot image management.

    This class represents an AHAB (Advanced High Assurance Boot) container that manages
    secure boot images and their associated metadata. It handles container structure,
    image array entries, signature blocks, and provides functionality for encryption,
    decryption, and validation of boot images.
    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +----+---------------------------+---------------------------------+
        | I  |image0: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + m  |-------------------------------------------------------------+
        | g  |image1: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + .  |-------------------------------------------------------------+
        | A  |...                                                          |
        | r  |...                                                          |
        | r  |                                                             |
        + a  |-------------------------------------------------------------+
        | y  |imageN: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        +----+-------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_0                                |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_n                                |
        +------------------------------------------------------------------+

    :cvar START_IMAGE_ADDRESS: Default start address for images (0x2000).
    :cvar START_IMAGE_ADDRESS_NAND: Start address for NAND flash images (0x1C00).
    """

    TAG = AHABTags.CONTAINER_HEADER.tag
    IAE_TYPE = ImageArrayEntry

    SIGNATURE_BLOCK = SignatureBlock

    START_IMAGE_ADDRESS = 0x2000
    START_IMAGE_ADDRESS_NAND = 0x1C00

    # Container special flags:
    FLAGS_GDET_ENABLE_OFFSET = 20
    FLAGS_GDET_ENABLE_SIZE = 2

    class FlagsGdetBehavior(SpsdkEnum):
        """SPSDK Glitch Detector behavior flags enumeration.

        This enumeration defines the runtime behavior options for the Glitch Detector
        in AHAB containers, controlling when and how the detector operates during
        authentication and ELE API operations.
        """

        Disabled = (
            0x00,
            "disabled",
            "Glitch Detector is disabled after the first OEM container"
            " has been authenticated (default behavior)",
        )
        EnabledEleApi = (
            0x01,
            "enabled_eleapi",
            "Automatically enable Glitch Detector during all ELE API calls",
        )
        Enabled = (0x02, "enabled", "Leave Glitch Detector enabled")

    def __init__(
        self,
        chip_config: AhabChipConfig,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        image_array: Optional[Union[list[ImageArrayEntry], list[ImageArrayEntryV2]]] = None,
        signature_block: Optional[Union[SignatureBlock, SignatureBlockV2]] = None,
        container_offset: int = 0,
    ):
        """Initialize AHAB container with configuration and optional components.

        :param chip_config: Chip configuration for AHAB container.
        :param flags: Container flags for AHAB processing.
        :param fuse_version: Minimum fuse version required, must be equal to or greater than the
            version stored in the fuses to allow loading this container.
        :param sw_version: Software version used by PHBC (Privileged Host Boot Companion) to
            select between multiple images with same fuse version field.
        :param image_array: Array of image entries, must be `number of images` long.
        :param signature_block: Signature block for container authentication.
        :param container_offset: Offset of the container in memory.
        """
        super().__init__(
            chip_config=chip_config,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.chip_config.container_offset = container_offset
        self.image_array = image_array or []

    def __eq__(self, other: object) -> bool:
        """Check equality of two AHAB containers.

        Compares this AHAB container with another object for equality. Two AHAB containers
        are considered equal if they are both instances of AHABContainer, their parent
        classes are equal, and their image arrays are identical.

        :param other: Object to compare with this AHAB container.
        :return: True if containers are equal, False otherwise.
        """
        return (
            isinstance(other, AHABContainer)
            and super().__eq__(other)
            and self.image_array == other.image_array
        )

    def __repr__(self) -> str:
        """Return string representation of AHAB Container.

        Provides a human-readable string showing the container's offset position
        in hexadecimal format for debugging and logging purposes.

        :return: String representation containing container offset in hex format.
        """
        return f"AHAB Container at offset {hex(self.chip_config.container_offset)} "

    def __str__(self) -> str:
        """Return string representation of AHAB Container.

        Provides a formatted string containing key information about the AHAB container
        including SRK set configuration, offset, flags, version information, and image count.

        :return: Formatted string with AHAB container details.
        """
        return (
            "AHAB Container:\n"
            f"  SRK Set:            {self.flag_srk_set.label}. {self.flag_srk_set.description}\n"
            f"  Offset:             {hex(self.chip_config.container_offset)}\n"
            f"  Flags:              {hex(self.flags)}\n"
            f"  Fuse version:       {hex(self.fuse_version)}\n"
            f"  SW version:         {hex(self.sw_version)}\n"
            f"  Images count:       {self.image_array_len}"
        )

    @property
    def image_array_len(self) -> int:
        """Get image array length.

        :return: Length of image array.
        """
        return len(self.image_array)

    @property
    def _signature_block_offset(self) -> int:
        """Calculate the current signature block offset in the container.

        The offset is calculated by aligning the sum of the container header size
        and image array entry table size to the container alignment boundary.

        :return: Offset in bytes of the signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().fixed_length() + len(self.image_array) * self.IAE_TYPE.fixed_length(),
            CONTAINER_ALIGNMENT,
        )

    @property
    def srk_hash(self) -> bytes:
        """Get SRK hash if available.

        :return: SHA256 hash of SRK table.
        """
        return self.get_srk_hash(0)

    def header_length(self) -> int:
        """Calculate the total length of AHAB Container header.

        The header length includes the fixed container header, all image array entries,
        and the signature block if present.

        :return: Total length in bytes of AHAB Container header.
        """
        return (
            super().fixed_length()  # This returns the fixed length of the container header
            # This returns the total length of all image array entries
            + len(self.image_array) * self.IAE_TYPE.fixed_length()
            # This returns the length of signature block (including SRK table,
            # blob etc. if present)
            + len(self.signature_block)
            if self.signature_block
            else 0
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        This method performs a complete update of the container by:
        1. Encrypting all flagged images that aren't already encrypted
        2. Updating the signature block fields
        3. Updating all image entries in the array
        4. Recalculating the container header length

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 1. Encrypt all images if applicable
        for image_entry in self.image_array:
            if (
                image_entry.flags_is_encrypted
                and not image_entry.already_encrypted_image
                and self.signature_block
                and self.signature_block.blob
            ):
                image_entry.encrypted_image = self.signature_block.blob.encrypt_data(
                    image_entry.image_iv[16:],
                    extend_block(
                        image_entry.plain_image,
                        image_entry._get_valid_size(image_entry.plain_image),
                    ),
                )
                image_entry.already_encrypted_image = True

        # 2. Update the signature block to get overall size of it
        if self.signature_block:
            self.signature_block.update_fields()
        # 3. Updates Image Entries
        for image_entry in self.image_array:
            image_entry.update_fields()
        # 4. Update the Container header length
        self.length = self.header_length()

    def decrypt_data(self) -> None:
        """Decrypt all encrypted images in the container.

        Iterates through all images in the image array and attempts to decrypt those
        that are marked as encrypted. Uses the signature block's blob for decryption
        and validates the decrypted data against the stored hash. Logs success or
        failure for each decryption attempt.

        :raises SPSDKError: If attempting to decrypt without a signature block or blob.
        """
        for i, image_entry in enumerate(self.image_array):
            if image_entry.flags_is_encrypted:
                if self.signature_block is None or self.signature_block.blob is None:
                    raise SPSDKError("Cannot decrypt image without Blob!")

                decrypted_data = self.signature_block.blob.decrypt_data(
                    image_entry.image_iv[16:], image_entry.encrypted_image
                )
                if image_entry.image_iv == get_hash(
                    decrypted_data, algorithm=EnumHashAlgorithm.SHA256
                ):
                    image_entry.plain_image = decrypted_data
                    logger.info(
                        f" Image{i} from AHAB container at offset "
                        f"{hex(self.chip_config.container_offset)} has been decrypted."
                    )
                else:
                    logger.warning(
                        f" Image{i} from AHAB container at offset "
                        f"{hex(self.chip_config.container_offset)} decryption failed."
                    )

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: Bytes representing container header content including the signature block.
        """
        return self.export()

    def export(self) -> bytes:
        """Export container header into bytes.

        The method creates a properly aligned container header that includes all image array
        entries and an optional signature block. The container is aligned according to
        CONTAINER_ALIGNMENT requirements.

        :return: Bytes representing the complete container header content including signature block.
        """
        container_header = bytearray(align(self.header_length(), CONTAINER_ALIGNMENT))
        container_header_only = super()._export()

        for image_array_entry in self.image_array:
            container_header_only += image_array_entry.export()

        container_header[: self._signature_block_offset] = container_header_only
        # Add Signature Block
        if self.signature_block:
            signature_block = self.signature_block.export()
            container_header[
                self._signature_block_offset : self._signature_block_offset
                + align(len(signature_block), CONTAINER_ALIGNMENT)
            ] = signature_block

        return container_header

    def post_export(self, output_path: str, cnt_ix: Optional[int] = None) -> list[str]:
        """Post-export processing and optional file writing.

        Performs post-export operations including SRK hash generation and fuse script creation.
        Skips processing for NXP containers, DEVHSM containers, and v2x-1 containers.

        :param output_path: Base path for output files
        :param cnt_ix: Container index for file naming, optional
        :return: List of generated file paths
        :raises SPSDKError: When fuse script generation fails
        """
        generated_files: list[str] = []
        if self.flag_srk_set in (FlagsSrkSet.NXP, FlagsSrkSet.DEVHSM):
            logger.debug("Skipping generating hashes for NXP container")
            return generated_files
        if self.image_array_len > 0 and self.image_array[0].flags_core_id_name == "v2x-1":
            logger.debug("Skipping generating hashes for v2x-1 container")
            return generated_files

        if self.signature_block:
            for srk_id in range(self.signature_block.SUPPORTED_SIGNATURES_CNT):
                srk_hash = self.get_srk_hash(srk_id)
                if srk_hash:
                    file_name = f"ahab_{self.flag_srk_set.label}{cnt_ix if cnt_ix is not None else ''}_srk{srk_id}_hash"
                    srk_hash_file = get_abs_path(f"{file_name}.txt", output_path)
                    write_file(srk_hash.hex().upper(), srk_hash_file, overwrite=False)
                    logger.info(f"Generated file containing SRK hash: {srk_hash_file}")
                    generated_files.append(srk_hash_file)
                    try:
                        fuse_script = FuseScript(self.chip_config.base.family, DatabaseManager.AHAB)
                        logger.info(
                            f"\nFuses info:\n{fuse_script.generate_script(self, info_only=True)}"
                        )
                        output_path = fuse_script.write_script(
                            file_name, output_path, self, overwrite=False
                        )
                        generated_files.append(output_path)
                        logger.info(
                            "Generated script for writing fuses for container "
                            f"{cnt_ix}: {output_path}"
                        )
                    except SPSDKError:
                        logger.info(
                            f"Failed to generate script for writing fuses for container {cnt_ix}"
                        )
        return generated_files

    def verify(self) -> Verifier:
        """Verify AHAB container data integrity and authenticity.

        Performs comprehensive verification of the container including image array
        validation, encryption verification, and signature authenticity checks.
        The verification process validates image count consistency, decrypts and
        verifies encrypted images when DEK is available, and checks container
        signatures against the configured SRK set.

        :return: Verifier object containing detailed verification results and status.
        """

        def verify_images() -> None:
            """Verify all images in the container array.

            Validates the image array existence, length consistency, and individual image integrity.
            For encrypted images, performs additional decryption verification using the signature
            block's blob container and validates the decrypted data hash against the IV vector.

            :raises SPSDKError: When image array validation fails or decryption verification errors
                occur.
            """
            if self.image_array is None:
                ret.add_record("Image array", VerifierResult.ERROR, "Not Exists")
            elif len(self.image_array) == 0:
                ret.add_record("Image array", VerifierResult.ERROR, "Has zero length")
            else:
                ver_img_arr = Verifier("Image array")
                if self.image_array_len != len(self.image_array):
                    ver_img_arr.add_record(
                        "Image count",
                        VerifierResult.ERROR,
                        f"Invalid: {self.image_array_len} != {len(self.image_array)}",
                    )
                else:
                    ver_img_arr.add_record(
                        "Image count", VerifierResult.SUCCEEDED, self.image_array_len
                    )

                for image_entry in self.image_array:
                    ver_img = image_entry.verify()
                    # Verify encryption if used
                    if image_entry.flags_is_encrypted:
                        ver_enc = Verifier("Image Encryption", description="")
                        if (
                            self.signature_block and self.signature_block.blob
                        ):  # The error in case that the blob doesn't exist is
                            # already printed in image array entry verifier

                            blob = self.signature_block.blob
                            if blob.dek is None:
                                ver_enc.add_record(
                                    "DEK",
                                    VerifierResult.WARNING,
                                    "The DEK key to encrypt has not been provided",
                                )
                            else:
                                decrypted_data = self.signature_block.blob.decrypt_data(
                                    image_entry.image_iv[16:], image_entry.encrypted_image
                                )
                                if image_entry.image_iv == get_hash(
                                    decrypted_data, algorithm=EnumHashAlgorithm.SHA256
                                ):
                                    ver_enc.add_record_bytes("Decrypted data", decrypted_data)
                                else:
                                    ver_enc.add_record(
                                        "Decrypted data",
                                        VerifierResult.ERROR,
                                        "Decrypted data HASH doesn't match IV vector.",
                                    )
                        else:
                            if self.flag_srk_set in (FlagsSrkSet.NXP, FlagsSrkSet.DEVHSM):
                                ver_enc.add_record(
                                    "Decrypted data",
                                    VerifierResult.WARNING,
                                    "The NXP image can't be verified",
                                )
                            elif self.flag_srk_set not in FlagsSrkSet:
                                ver_enc.add_record(
                                    "Decrypted data",
                                    VerifierResult.WARNING,
                                    "The unknown SRK Set image without blob container is not possible to verify",
                                )
                            else:
                                ver_enc.add_record(
                                    "Decrypted data", VerifierResult.ERROR, "Missing Blob container"
                                )
                        ver_img.add_child(ver_enc)
                    ver_img_arr.add_child(ver_img)
                ret.add_child(ver_img_arr)

        def verify_authenticity() -> None:
            """Verify the authenticity of the AHAB container.

            This method checks the container's authenticity by examining the SRK (Super Root Key)
            flags and validating the signature block if present. It adds verification records
            to track the authentication status and any errors encountered.

            :raises SPSDKError: If signature verification fails or container data is invalid.
            """
            ret.add_record_enum("Container authenticity", self.flag_srk_set, FlagsSrkSet)
            if self.flag_srk_set != FlagsSrkSet.NONE:
                if self.signature_block is None:
                    ret.add_record("Signature block", VerifierResult.ERROR, "Missing")
                else:
                    ret.add_child(
                        self.signature_block.verify_container_authenticity(
                            self.get_signature_data()
                        )
                    )

        description = str(self)
        if self.flag_srk_set == FlagsSrkSet.OEM:
            description += "\n\nThis is signed container, check that the SRK hash fuses has following values:\n"
            description += self.create_srk_hash_fuses_script()
        ret = self._verify(
            name=f"Container {self.chip_config.container_offset // self.CONTAINER_SIZE}",
            description=description,
        )
        ret.add_record_enum(
            "Glitch detector runtime behavior",
            self.flag_gdet_runtime_behavior,
            self.FlagsGdetBehavior,
        )
        verify_images()
        verify_authenticity()

        return ret

    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipConfig, offset: int) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse input binary chunk to the container object.

        This method reconstructs an AHAB container from binary data by parsing the container
        header, signature block, and all image array entries with their associated binary images.

        :param data: Binary data with Container block to parse.
        :param chip_config: Ahab image chip configuration.
        :param offset: AHAB container offset in the binary data.
        :return: Object recreated from the binary data.
        """
        (
            container_length,
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
        ) = cls._parse(data[offset:])

        parsed_container = cls(
            chip_config=chip_config,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            container_offset=offset,
        )
        # Lock the parsed container to any updates of offsets
        parsed_container.length = container_length
        parsed_container.chip_config.locked = True

        parsed_container.signature_block = cls.SIGNATURE_BLOCK.parse(
            data[offset + signature_block_offset :], parsed_container.chip_config
        )

        for i in range(number_of_images):
            image_array_entry_binary_start = (
                offset + cls.fixed_length() + i * cls.IAE_TYPE.fixed_length()
            )
            image_array_entry = cls.IAE_TYPE.parse(
                data[image_array_entry_binary_start:], parsed_container.chip_config
            )
            binary_image_start = offset + image_array_entry._image_offset

            image_size = int.from_bytes(
                data[image_array_entry_binary_start + 4 : image_array_entry_binary_start + 8],
                "little",
            )
            binary_image_end = min(binary_image_start + image_size, len(data))
            image_array_entry.image = data[binary_image_start:binary_image_end]

            parsed_container.image_array.append(image_array_entry)  # type: ignore
        parsed_container._parsed_header = HeaderContainerData.parse(binary=data[offset:])
        return parsed_container

    @property
    def flag_gdet_runtime_behavior(self) -> FlagsGdetBehavior:
        """Get glitch detector runtime behavior flag as enumeration.

        Extracts and decodes the glitch detector enable bits from the container flags
        to determine the runtime behavior configuration.

        :return: Glitch detector behavior enumeration value.
        """
        gdet_enable = (self.flags >> self.FLAGS_GDET_ENABLE_OFFSET) & (
            (1 << self.FLAGS_GDET_ENABLE_SIZE) - 1
        )
        return self.FlagsGdetBehavior.from_tag(gdet_enable)

    def _create_flags_config(self) -> Config:
        """Create configuration of the AHAB container flags.

        This method extends the base class flags configuration by adding the GDET
        runtime behavior flag specific to AHAB containers.

        :return: Configuration dictionary containing all container flags.
        """
        cfg = super()._create_flags_config()
        cfg["gdet_runtime_behavior"] = self.flag_gdet_runtime_behavior.label

        return cfg

    def get_config(self, data_path: str = "./", index: int = 0) -> Config:
        """Create configuration of the AHAB Image.

        Generates a complete configuration dictionary for the AHAB container including all images
        and runtime behavior settings.

        :param data_path: Path to store the data files of configuration.
        :param index: Container index.
        :return: Configuration dictionary containing container and images configuration.
        """
        ret_cfg = Config()
        cfg = self._create_config(index, data_path)
        cfg["gdet_runtime_behavior"] = self.flag_gdet_runtime_behavior.label
        images_cfg = []

        for img_ix, image in enumerate(self.image_array):
            images_cfg.append(image.get_config(index, img_ix, data_path))
        cfg["images"] = images_cfg

        ret_cfg["container"] = cfg
        return ret_cfg

    def _load_from_config_flags(self, config: Config) -> None:
        """Load AHAB container flags from configuration.

        This method processes the configuration to extract and set container flags,
        including the GDET (Global Device Error Trap) runtime behavior setting.

        :param config: Configuration dictionary containing AHAB container settings.
        """
        super()._load_from_config_flags(config)
        self.flags |= (
            self.FlagsGdetBehavior.from_attr(config.get("gdet_runtime_behavior", "disabled")).tag
            << self.FLAGS_GDET_ENABLE_OFFSET
        )

    @classmethod
    def load_from_config(
        cls, chip_config: AhabChipConfig, config: Config, container_ix: int
    ) -> Self:
        """Create AHAB container from configuration data.

        Converts the configuration dictionary into an AHAB container object with proper
        chip configuration and image array entries.

        :param chip_config: AHAB chip configuration settings.
        :param config: Configuration dictionary containing container settings.
        :param container_ix: Index of the container being loaded.
        :return: Configured AHAB Container object.
        """
        ahab_container = cls(chip_config=chip_config)
        ahab_container.chip_config.container_offset = cls.CONTAINER_SIZE * container_ix
        ahab_container.load_from_config_generic(config)

        images = config.get_list_of_configs("images", [])
        ahab_container.image_array = ImageArrayEntryTemplates.create_image_array_entries(
            iae_cls=cls.IAE_TYPE, chip_config=ahab_container.chip_config, config=images
        )

        return ahab_container

    def image_info(self) -> BinaryImage:
        """Get AHAB Container binary image information.

        Creates a BinaryImage object containing metadata and binary data for the AHAB container,
        including container size, description with SRK set flag and software version.

        :return: Binary image object with AHAB container metadata and exported binary data.
        """
        ret = BinaryImage(
            name="AHAB Container",
            size=self.header_length(),
            offset=0,
            binary=self.export(),
            description=(
                f"AHAB Container for {self.flag_srk_set.label}" f"_SWver:{self.sw_version}"
            ),
            alignment=CONTAINER_ALIGNMENT,
        )
        return ret

    def create_srk_hash_fuses_script(self) -> str:
        """Create fuses script for Super Root Keys (SRK) hash.

        This method generates a fuse script that can be used to program the SRK hash
        into the device fuses for secure boot verification.

        :return: Fuse script as text string, or error message if SRK hash fuses
                 are not available for the target chip family.
        """
        try:
            fuse_script = FuseScript(self.chip_config.base.family, DatabaseManager.AHAB)
        except SPSDKError as exc:
            return f"The Super Root Keys Hash fuses are not available, yet: {exc.description}"
        return fuse_script.generate_script(self, True)

    @classmethod
    def get_container_offset(cls, ix: int) -> int:
        """Get container offset by index.

        Calculate the byte offset for a container based on its index position.
        Each container has a fixed size, and containers are placed sequentially.

        :param ix: Container index (0-3).
        :raises SPSDKValueError: Invalid container index (negative or greater than 3).
        :return: Container offset in bytes.
        """
        if ix < 0:
            raise SPSDKValueError(f"Invalid container offset: {ix}")
        if ix > 3:
            raise SPSDKValueError("There is no option to have more that 4 containers")
        return cls.CONTAINER_SIZE * ix

    @property
    def start_of_images(self) -> int:
        """Get real start of container images.

        Finds the minimum image offset among all images in the container's image array
        to determine where the actual image data begins.

        :raises ValueError: If the image array is empty.
        :return: The smallest image offset value from all container images.
        """
        return min(x.image_offset for x in self.image_array)


class AHABContainerV1forV2(AHABContainer):
    """AHAB Container Version 1 for V2 Images.

    This class represents an AHAB container using version 1 format that is specifically
    designed for use within AHAB images containing V2 containers, providing compatibility
    between different container versions.

    :cvar CONTAINER_SIZE: Fixed size of the container (0x4000 bytes).
    :cvar TAG: Container header tag for V1 containers in V2 images.
    """

    CONTAINER_SIZE = 0x4000
    TAG = AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag


class AHABContainerV2(AHABContainer):
    """AHAB Container Version 2 implementation for secure boot image management.

    This class implements the Advanced High Assurance Boot (AHAB) container format
    version 2, providing secure boot capabilities for NXP MCUs. It manages container
    structure, image array entries, signature blocks, and cryptographic operations
    for authenticated boot sequences.
    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +----+---------------------------+---------------------------------+
        | I  |image0: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + m  |-------------------------------------------------------------+
        | g  |image1: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + .  |-------------------------------------------------------------+
        | A  |...                                                          |
        | r  |...                                                          |
        | r  |                                                             |
        + a  |-------------------------------------------------------------+
        | y  |imageN: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        +----+-------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_0                                |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_n                                |
        +------------------------------------------------------------------+

    :cvar VERSION: Container format version identifier (0x02).
    :cvar CONTAINER_SIZE: Standard container size in bytes (0x4000).
    :cvar START_IMAGE_ADDRESS: Default start address for images (0xC000).
    :cvar START_IMAGE_ADDRESS_NAND: Start address for NAND flash images (0xBC00).
    """

    IAE_TYPE = ImageArrayEntryV2

    SIGNATURE_BLOCK = SignatureBlockV2  # type:ignore
    CONTAINER_SIZE = 0x4000
    VERSION = 0x02

    START_IMAGE_ADDRESS = 0xC000
    START_IMAGE_ADDRESS_NAND = 0xBC00

    # Container special flags:
    FLAGS_CHECK_ALL_SIGNATURES_OFFSET = 15
    FLAGS_CHECK_ALL_SIGNATURES_SIZE = 1

    # Container special flags for FastBoot:
    FLAGS_FAST_BOOT_OFFSET = 16
    FLAGS_FAST_BOOT_SIZE = 3

    class FlagsCheckAllSignatures(SpsdkEnum):
        """AHAB container signature verification flags enumeration.

        This enumeration defines the available flags for controlling signature verification
        behavior in AHAB (Advanced High Assurance Boot) containers, allowing configuration
        of whether all signatures must be verified or default fuse policy should be applied.
        """

        Default = (0x00, "default", "Apply default fuse policy")
        CheckAllSignatures = (
            0x01,
            "check_all_signatures",
            "Force verification of all present signatures",
        )

    @property
    def flag_check_all_signatures(self) -> FlagsCheckAllSignatures:
        """Get check all signatures flag as enumeration.

        Extracts and returns the check all signatures flag from the container flags
        by applying bit masking and offset operations.

        :return: Check all signatures flag as FlagsCheckAllSignatures enumeration.
        """
        check_all = (self.flags >> self.FLAGS_CHECK_ALL_SIGNATURES_OFFSET) & (
            (1 << self.FLAGS_CHECK_ALL_SIGNATURES_SIZE) - 1
        )
        return self.FlagsCheckAllSignatures.from_tag(check_all)

    class FlagsFastBoot(SpsdkEnum):
        """Fast Boot configuration flags enumeration.

        This enumeration defines the available flags for configuring Fast Boot behavior
        in AHAB containers, controlling hash operations, copy operations, and external
        accelerator usage for authentication.
        """

        Disabled = (0x00, "disabled", "Fast Boot is disabled")
        HashAndCopy = (
            0x01,
            "hash_and_copy",
            "ELE will do the hash and copy (when disabled, BootROM will do the copy)",
        )
        ExternalAccelerator = (
            0x02,
            "external_accelerator",
            "Use external accelerator for authentication (e.g. V2X on i.MX95B0, i.MX943 and i.MX952)",
        )
        HashAndCopyWithExternalAccelerator = (
            0x03,
            "hash_and_copy_with_external_accelerator",
            "ELE will do hash and copy, and use external accelerator for authentication",
        )

    @property
    def flag_fast_boot(self) -> FlagsFastBoot:
        """Get Fast Boot flags as enumeration.

        Extracts and returns the Fast Boot flags from the container flags field
        by applying bit masking and offset operations.

        :return: Fast Boot flags as FlagsFastBoot enumeration value.
        """
        fast_boot = (self.flags >> self.FLAGS_FAST_BOOT_OFFSET) & (
            (1 << self.FLAGS_FAST_BOOT_SIZE) - 1
        )
        return self.FlagsFastBoot.from_tag(fast_boot)

    def _create_flags_config(self) -> Config:
        """Create configuration of the AHAB container flags.

        The method extends the base class flags configuration by adding AHAB-specific
        flags including signature checking and fast boot options.

        :return: Configuration dictionary with AHAB container flags.
        """
        cfg = super()._create_flags_config()
        cfg["check_all_signatures"] = self.flag_check_all_signatures.label
        cfg["fast_boot"] = self.flag_fast_boot.label

        return cfg

    def _load_from_config_flags(self, config: Config) -> None:
        """Load AHAB container flags from configuration.

        This method processes the configuration to set container-specific flags including
        check_all_signatures and fast_boot options, combining them with flags from the parent class.

        :param config: Configuration dictionary containing AHAB container settings.
        :raises SPSDKValueError: Invalid flag attribute values in configuration.
        """
        super()._load_from_config_flags(config)
        self.flags |= (
            self.FlagsCheckAllSignatures.from_attr(
                config.get("check_all_signatures", "default")
            ).tag
            << self.FLAGS_CHECK_ALL_SIGNATURES_OFFSET
        )
        self.flags |= (
            self.FlagsFastBoot.from_attr(config.get("fast_boot", "disabled")).tag
            << self.FLAGS_FAST_BOOT_OFFSET
        )

    def create_srk_hash_fuses_script(self) -> str:
        """Create fuses script for Super Root Key (SRK) hash.

        Generates a script containing fuse programming commands for the SRK hash values.
        The script is created for each SRK table in the signature block's SRK assets.
        If SRK hash fuses are not available for the target chip family, an error
        message is returned instead.

        :return: Fuse programming script as text, or error message if fuses not available.
        """
        ret = ""
        if self.signature_block and self.signature_block.srk_assets:
            assert isinstance(self.signature_block.srk_assets, SRKTableArray)
            for ix in range(len(self.signature_block.srk_assets._srk_tables)):
                try:
                    fuse_script = FuseScript(
                        self.chip_config.base.family,
                        DatabaseManager.AHAB,
                        index=ix,
                    )
                except SPSDKError as exc:
                    return (
                        f"The Super Root Keys Hash fuses are not available, yet: {exc.description}"
                    )
                ret += fuse_script.generate_script(self, True) + "\n"
        return ret

    def post_export(self, output_path: str, cnt_ix: Optional[int] = None) -> list[str]:
        """Post-export processing and optional file writing.

        Generates SRK hash files and fuse scripts for AHAB containers. Skips processing for NXP
        containers and v2x-1 containers. Creates hash files and corresponding fuse scripts for
        each SRK table in the signature block.

        :param output_path: Base path for output files
        :param cnt_ix: Container index for file naming, optional
        :return: List of generated file paths including hash files and fuse scripts
        """
        generated_files: list[str] = []
        if self.flag_srk_set == FlagsSrkSet.NXP:
            logger.debug("Skipping generating hashes for NXP container")
            return generated_files
        if self.image_array_len > 0 and self.image_array[0].flags_core_id_name == "v2x-1":
            logger.debug("Skipping generating hashes for v2x-1 container")
            return generated_files

        if self.signature_block:
            if not isinstance(self.signature_block.srk_assets, SRKTableArray):
                return generated_files
            for srk_id in range(len(self.signature_block.srk_assets._srk_tables)):
                srk_hash = self.get_srk_hash(srk_id)
                if srk_hash:
                    file_name = f"ahab_{self.flag_srk_set.label}{cnt_ix if cnt_ix is not None else ''}_srk{srk_id}_hash"
                    srk_hash_file = get_abs_path(f"{file_name}.txt", output_path)
                    write_file(srk_hash.hex().upper(), srk_hash_file, overwrite=False)
                    logger.info(f"Generated file containing SRK hash: {srk_hash_file}")
                    generated_files.append(srk_hash_file)
                    try:
                        fuse_script = FuseScript(
                            self.chip_config.base.family, DatabaseManager.AHAB, srk_id
                        )
                        logger.info(
                            f"\nFuses info:\n{fuse_script.generate_script(self, info_only=True)}"
                        )
                        fuse_script_path = fuse_script.write_script(
                            file_name, output_path, self, overwrite=False
                        )
                        generated_files.append(fuse_script_path)
                        logger.info(
                            "Generated script for writing fuses for container "
                            f"{cnt_ix}: {fuse_script_path}"
                        )
                    except SPSDKError:
                        logger.info(
                            f"Failed to generate script for writing fuses for container {cnt_ix}"
                        )
        return generated_files

    @property
    def srk_hash0(self) -> bytes:
        """Get SRK hash if available.

        :return: SHA256 hash of SRK table.
        """
        return self.get_srk_hash(0)

    @property
    def srk_hash1(self) -> bytes:
        """Get SRK hash from index 1 if available.

        The method retrieves the SHA256 hash of the Super Root Key (SRK) table from index 1.

        :return: SHA256 hash of SRK table from index 1.
        """
        return self.get_srk_hash(1)
