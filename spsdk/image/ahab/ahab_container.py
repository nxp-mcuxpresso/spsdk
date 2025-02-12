#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of raw AHAB container support.

This module represents a generic AHAB container implementation. You can set the
containers values at will. From this perspective, consult with your reference
manual of your device for allowed values.
"""


import logging
from struct import pack, unpack
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
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
from spsdk.utils.database import DatabaseManager
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import align, value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class AHABContainerBase(HeaderContainer):
    """Class representing AHAB container base class (common for Signed messages and AHAB Image).

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
        +--------------------------------+---------------------------------+
        |             Payload (Signed Message or Image Array)              |
        +------------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+

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

    def __init__(
        self,
        chip_config: AhabChipConfig,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        signature_block: Optional[Union[SignatureBlock, SignatureBlockV2]] = None,
    ):
        """Class object initializer.

        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param signature_block: signature block.
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
        """Set the flags value.

        :param srk_set: Super Root Key (SRK) set, defaults to "none"
        :param used_srk_id: Which key from SRK set is being used, defaults to 0
        :param srk_revoke_mask: SRK revoke mask, defaults to 0
        """
        flags = FlagsSrkSet.from_attr(srk_set.lower()).tag
        flags |= used_srk_id << 4
        flags |= srk_revoke_mask << 8
        self.flags = flags

    @property
    def flag_srk_set(self) -> FlagsSrkSet:
        """SRK set flag in string representation.

        :return: Name of SRK Set flag.
        """
        srk_set = (self.flags >> self.FLAGS_SRK_SET_OFFSET) & ((1 << self.FLAGS_SRK_SET_SIZE) - 1)
        return FlagsSrkSet.from_tag(srk_set)

    @property
    def flag_used_srk_id(self) -> int:
        """Used SRK ID flag.

        :return: Index of Used SRK ID.
        """
        return (self.flags >> self.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << self.FLAGS_USED_SRK_ID_SIZE) - 1
        )

    @property
    def flag_srk_revoke_keys(self) -> int:
        """SRK Revoke mask flag.

        :return: SRK revoke mask.
        """
        srk_revoke_mask = (self.flags >> self.FLAGS_SRK_REVOKE_MASK_OFFSET) & (
            (1 << self.FLAGS_SRK_REVOKE_MASK_SIZE) - 1
        )
        return srk_revoke_mask

    @property
    def flag_srk_revoke_mask(self) -> str:
        """SRK Revoke mask flag.

        :return: SRK revoke mask in HEX.
        """
        return hex(self.flag_srk_revoke_keys)

    @property
    def srk_count(self) -> int:
        """Get count of used signatures in container."""
        if self.signature_block and self.signature_block.srk_assets:
            return self.signature_block.srk_assets.srk_count

        return 0

    def get_srk_hash(self, srk_id: int = 0) -> bytes:
        """Get SRK hash.

        :param srk_id: ID of SRK table in case of using multiple Signatures, default is 0.
        :return: SHA256 hash of SRK table.
        """
        if self.signature_block and self.signature_block.srk_assets:
            return self.signature_block.srk_assets.compute_srk_hash(srk_id)
        return b""

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
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
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
        """
        ret = super().__len__()
        if self.signature_block is not None:
            ret += len(self.signature_block)
        return ret  # This returns the fixed length of the container header

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
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
        """Returns binary data to be signed.

        The container must be properly initialized, so the data are valid for
        signing, i.e. the offsets, lengths etc. must be set prior invoking this
        method, otherwise improper data will be signed.

        The whole container gets serialized first. Afterwards the binary data
        is sliced so only data for signing get's returned. The signature data
        length is evaluated based on offsets, namely the signature block offset,
        the container signature offset and the container signature fixed data length.

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
            | k | a |               Signature data              |
            |   | t |                                           |
            |   | u |                                           |
            |   | r |                                           |
            |   | e |                                           |
            +---+---+-------------------------------------------+

        :return: bytes representing data to be signed.
        """
        if (
            not self.signature_block
            or not self.signature_block.signature
            or not self.signature_block.srk_assets
        ):
            return bytes()  # Its OK to return just empty data - the verifier catch this issue

        signature_offset = self._signature_block_offset + self.signature_block.signature_offset
        return self._export()[:signature_offset]

    def sign_itself(self) -> None:
        """Sign itself if needed."""
        if self.flag_srk_set != FlagsSrkSet.NONE:
            if not self.signature_block:
                raise SPSDKError("Cannot sign because the Signature block is missing.")
            self.signature_block.sign_itself(self.get_signature_data())

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
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

        :param name: Optional overloaded name
        :param name: Optional description
        """
        ret = Verifier(name or self.NAME, description=description)
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_bit_range("Flags", self.flags, 32)
        ret.add_record_enum("Flags: SRK Set", self.flag_srk_set, FlagsSrkSet)
        ret.add_record_range("Flags: SRK Selection", self.flag_used_srk_id, min_val=0, max_val=3)
        ret.add_record_bit_range("Flags: SRK Revoke mask", self.flag_srk_revoke_keys, bit_range=4)
        ret.add_record_bit_range("SW version", self.flags, 16)
        ret.add_record_bit_range("Fuse version", self.flags, 8)
        ret.add_record_range("Signature Block offset", self._signature_block_offset, max_val=65535)

        if self.signature_block:
            ret.add_child(self.signature_block.verify())

        return ret

    @classmethod
    def pre_parse_verify(cls, data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB container.

        :param data: Binary data with Container block to pre-parse.
        :return: Verifier of pre-parsed binary data.
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

        :param binary: Binary data with Container block to parse.
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

    def _create_flags_config(self) -> dict[str, Any]:
        """Create configuration of the AHAB container flags.

        :return: Configuration dictionary.
        """
        cfg: dict[str, Any] = {}

        cfg["srk_set"] = self.flag_srk_set.label
        cfg["used_srk_id"] = self.flag_used_srk_id
        cfg["srk_revoke_mask"] = self.flag_srk_revoke_mask
        return cfg

    def _create_config(self, index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg = self._create_flags_config()

        cfg["fuse_version"] = self.fuse_version
        cfg["sw_version"] = self.sw_version

        if self.signature_block:
            cfg.update(self.signature_block.create_config(index=index, data_path=data_path))

        return cfg

    def _load_from_config_flags(self, config: dict[str, Any]) -> None:
        """Loads from config AHAB container flags.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        self.set_flags(
            srk_set=config.get("srk_set", "none"),
            used_srk_id=value_to_int(config.get("used_srk_id", 0)),
            srk_revoke_mask=value_to_int(config.get("srk_revoke_mask", 0)),
        )

    def load_from_config_generic(self, config: dict[str, Any]) -> None:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        self._load_from_config_flags(config)
        self.fuse_version = value_to_int(config.get("fuse_version", 0))
        self.sw_version = value_to_int(config.get("sw_version", 0))
        self.chip_config.used_srk_id = value_to_int(config.get("used_srk_id", 0))
        self.signature_block = self.SIGNATURE_BLOCK.load_from_config(
            config, self.chip_config, search_paths=self.chip_config.base.search_paths
        )


class AHABContainer(AHABContainerBase):
    """Class representing AHAB container.

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
        """Flags Glitch Detector runtime behavior flags."""

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
        """Class object initializer.

        :chip_config: Chip configuration for AHAB.
        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param image_array: array of image entries, must be `number of images` long.
        :param signature_block: signature block.
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
        return (
            isinstance(other, AHABContainer)
            and super().__eq__(other)
            and self.image_array == other.image_array
        )

    def __repr__(self) -> str:
        return f"AHAB Container at offset {hex(self.chip_config.container_offset)} "

    def __str__(self) -> str:
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
        """Get image array length if available.

        :return: Length of image array.
        """
        return len(self.image_array)

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().fixed_length() + len(self.image_array) * self.IAE_TYPE.fixed_length(),
            CONTAINER_ALIGNMENT,
        )

    @property
    def srk_hash(self) -> bytes:
        """SRK hash if available.

        :return: SHA256 hash of SRK table.
        """
        return self.get_srk_hash(0)

    def header_length(self) -> int:
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
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
                    image_entry.image_iv[16:], image_entry.plain_image
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
        """Decrypt all images if possible."""
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

        :return: bytes representing container header content including the signature block.
        """
        return self.export()

    def export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        container_header = bytearray(align(self.header_length(), CONTAINER_ALIGNMENT))
        container_header_only = super()._export()

        for image_array_entry in self.image_array:
            container_header_only += image_array_entry.export()

        container_header[: self._signature_block_offset] = container_header_only
        # Add Signature Block
        if self.signature_block:
            container_header[
                self._signature_block_offset : self._signature_block_offset
                + align(len(self.signature_block), CONTAINER_ALIGNMENT)
            ] = self.signature_block.export()

        return container_header

    def verify(self) -> Verifier:
        """Verify container data."""

        def verify_images() -> None:
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
                            if self.flag_srk_set == FlagsSrkSet.NXP:
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
            ret.add_record_enum("Container authenticity", self.flag_srk_set, FlagsSrkSet)
            if self.flag_srk_set != "none":
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
            name=f"Container {self.chip_config.container_offset // 0x400}", description=description
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
    def parse(cls, data: bytes, chip_config: AhabChipConfig, container_id: int) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse input binary chunk to the container object.

        :param data: Binary data with Container block to parse.
        :param chip_config: Ahab image chip configuration.
        :param container_id: AHAB container ID.
        :return: Object recreated from the binary data.
        """
        (
            container_length,
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
        ) = cls._parse(data)

        parsed_container = cls(
            chip_config=chip_config,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            container_offset=cls.CONTAINER_SIZE * container_id,
        )
        # Lock the parsed container to any updates of offsets
        parsed_container.length = container_length
        parsed_container.chip_config.locked = True

        parsed_container.signature_block = cls.SIGNATURE_BLOCK.parse(
            data[signature_block_offset:], parsed_container.chip_config
        )

        for i in range(number_of_images):
            image_array_entry_binary_start = cls.fixed_length() + i * cls.IAE_TYPE.fixed_length()
            image_array_entry = cls.IAE_TYPE.parse(
                data[image_array_entry_binary_start:], parsed_container.chip_config
            )
            binary_image_start = image_array_entry._image_offset

            image_size = int.from_bytes(
                data[image_array_entry_binary_start + 4 : image_array_entry_binary_start + 8],
                "little",
            )
            binary_image_end = min(binary_image_start + image_size, len(data))
            image_array_entry.image = data[binary_image_start:binary_image_end]

            parsed_container.image_array.append(image_array_entry)  # type: ignore
        parsed_container._parsed_header = HeaderContainerData.parse(binary=data)
        return parsed_container

    @property
    def flag_gdet_runtime_behavior(self) -> FlagsGdetBehavior:
        """Glitch detector flag as enumeration."""
        gdet_enable = (self.flags >> self.FLAGS_GDET_ENABLE_OFFSET) & (
            (1 << self.FLAGS_GDET_ENABLE_SIZE) - 1
        )
        return self.FlagsGdetBehavior.from_tag(gdet_enable)

    def _create_flags_config(self) -> dict[str, Any]:
        """Create configuration of the AHAB container flags.

        :return: Configuration dictionary.
        """
        cfg = super()._create_flags_config()
        cfg["gdet_runtime_behavior"] = self.flag_gdet_runtime_behavior.label

        return cfg

    def create_config(self, index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = {}
        cfg = self._create_config(index, data_path)
        cfg["gdet_runtime_behavior"] = self.flag_gdet_runtime_behavior.label
        images_cfg = []

        for img_ix, image in enumerate(self.image_array):
            images_cfg.append(image.create_config(index, img_ix, data_path))
        cfg["images"] = images_cfg

        ret_cfg["container"] = cfg
        return ret_cfg

    def _load_from_config_flags(self, config: dict[str, Any]) -> None:
        """Loads from config AHAB container flags.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        super()._load_from_config_flags(config)
        self.flags |= (
            self.FlagsGdetBehavior.from_attr(config.get("gdet_runtime_behavior", "disabled")).tag
            << self.FLAGS_GDET_ENABLE_OFFSET
        )

    @classmethod
    def load_from_config(
        cls, chip_config: AhabChipConfig, config: dict[str, Any], container_ix: int
    ) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param chip_config: Ahab chip configuration.
        :param config: array of AHAB containers configuration dictionaries.
        :param container_ix: Container index that is loaded.
        :return: AHAB Container object.
        """
        ahab_container = cls(chip_config=chip_config)
        ahab_container.chip_config.container_offset = cls.CONTAINER_SIZE * container_ix
        ahab_container.load_from_config_generic(config)

        images: list[dict[str, Any]] = config.get("images", [])
        ahab_container.image_array = ImageArrayEntryTemplates.create_image_array_entries(
            iae_cls=cls.IAE_TYPE, chip_config=ahab_container.chip_config, config=images
        )

        return ahab_container

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: AHAB Container Info object.
        """
        ret = BinaryImage(
            name="AHAB Container",
            size=self.header_length(),
            offset=0,
            binary=self.export(),
            description=(
                f"AHAB Container for {self.flag_srk_set.label}" f"_SWver:{self.sw_version}"
            ),
        )
        return ret

    def create_srk_hash_fuses_script(self) -> str:
        """Create fuses script of SRK hash.

        :return: Text description of SRK hash.
        """
        try:
            fuse_script = FuseScript(
                self.chip_config.base.family, self.chip_config.base.revision, DatabaseManager.AHAB
            )
        except SPSDKError as exc:
            return f"The Super Root Keys Hash fuses are not available, yet: {exc.description}"
        return fuse_script.generate_script(self, True)

    @classmethod
    def get_container_offset(cls, ix: int) -> int:
        """Get container offset by index.

        :param ix: Container index
        :return: Container offset
        """
        if ix < 0:
            raise SPSDKValueError(f"Invalid container offset: {ix}")
        if ix > 3:
            raise SPSDKValueError("There is no option to have more that 4 containers")
        return cls.CONTAINER_SIZE * ix

    @property
    def start_of_images(self) -> int:
        """Get real start of container images."""
        return min(x.image_offset for x in self.image_array)


class AHABContainerV2(AHABContainer):
    """Class representing AHAB container.

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

    class FlagsCheckAllSignatures(SpsdkEnum):
        """Flags Check all signatures."""

        Default = (0x00, "default", "Apply default fuse policy")
        CheckAllSignatures = (
            0x01,
            "check_all_signatures",
            "Force verification of all present signatures",
        )

    @property
    def flag_check_all_signatures(self) -> FlagsCheckAllSignatures:
        """Check all signatures flag as enumeration."""
        check_all = (self.flags >> self.FLAGS_CHECK_ALL_SIGNATURES_OFFSET) & (
            (1 << self.FLAGS_CHECK_ALL_SIGNATURES_SIZE) - 1
        )
        return self.FlagsCheckAllSignatures.from_tag(check_all)

    def _create_flags_config(self) -> dict[str, Any]:
        """Create configuration of the AHAB container flags.

        :return: Configuration dictionary.
        """
        cfg = super()._create_flags_config()
        cfg["check_all_signatures"] = self.flag_check_all_signatures.label

        return cfg

    def _load_from_config_flags(self, config: dict[str, Any]) -> None:
        """Loads from config AHAB container flags.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        super()._load_from_config_flags(config)
        self.flags |= (
            self.FlagsCheckAllSignatures.from_attr(
                config.get("check_all_signatures", "default")
            ).tag
            << self.FLAGS_GDET_ENABLE_OFFSET
        )

    def create_srk_hash_fuses_script(self) -> str:
        """Create fuses script of SRK hash.

        :return: Text description of SRK hash.
        """
        ret = ""
        if self.signature_block and self.signature_block.srk_assets:
            assert isinstance(self.signature_block.srk_assets, SRKTableArray)
            for ix in range(len(self.signature_block.srk_assets._srk_tables)):
                try:
                    fuse_script = FuseScript(
                        self.chip_config.base.family,
                        self.chip_config.base.revision,
                        DatabaseManager.AHAB,
                        index=ix,
                    )
                except SPSDKError as exc:
                    return (
                        f"The Super Root Keys Hash fuses are not available, yet: {exc.description}"
                    )
                ret += fuse_script.generate_script(self, True) + "\n"
        return ret

    @property
    def srk_hash0(self) -> bytes:
        """SRK hash if available.

        :return: SHA256 hash of SRK table.
        """
        return self.get_srk_hash(0)

    @property
    def srk_hash1(self) -> bytes:
        """SRK hash if available.

        :return: SHA256 hash of SRK table.
        """
        return self.get_srk_hash(1)
