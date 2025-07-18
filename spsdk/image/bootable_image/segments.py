#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""


import logging
import os
from inspect import isclass
from struct import unpack
from typing import Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.hab.hab_image import HabImage
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mem_type import MemoryType
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.abstract import BaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import BinaryPattern, Endianness, align, load_binary, value_to_int, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class SPSDKSegmentNotPresent(SPSDKError):
    """The segment is not present in the configuration."""


class BootableImageSegment(SpsdkEnum):
    """Bootable image segment."""

    UNKNOWN = (0, "unknown", "Unknown segment")
    KEYBLOB = (1, "keyblob", "Keyblob segment")
    FCB = (2, "fcb", "Fcb segment")
    IMAGE_VERSION = (3, "image_version", "Image version segment")
    IMAGE_VERSION_AP = (4, "image_version_ap", "Image version antipole segment")
    KEYSTORE = (5, "keystore", "Keystore segment")
    BEE_HEADER_0 = (6, "bee_header_0", "BEE header 0 segment")
    BEE_HEADER_1 = (7, "bee_header_1", "BEE header 1 segment")
    XMCD = (8, "xmcd", "XMCD segment")
    MBI = (9, "mbi", "Masterboot image segment")
    HAB_CONTAINER = (10, "hab_container", "HAB container segment")
    AHAB_CONTAINER = (11, "ahab_container", "AHAB container segment")
    PRIMARY_IMAGE_CONTAINER_SET = (
        12,
        "primary_image_container_set",
        "Primary Image Container Set segment",
    )
    SECONDARY_IMAGE_CONTAINER_SET = (
        13,
        "secondary_image_container_set",
        "Secondary Image Container Set segment",
    )
    SB21 = (14, "sb21", "Secure binary 2.1 segment")
    SB31 = (15, "sb31", "Secure binary 3.1 segment")


class Segment(BaseClass):
    """Base Bootable Image Segment class."""

    NAME = BootableImageSegment.UNKNOWN
    BOOT_HEADER = True
    INIT_SEGMENT = False
    CFG_NAME: Optional[str] = None
    IMAGE_PATTERNS = ["zeros", "ones"]
    OFFSET_ALIGNMENT = 1

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in the full bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        """
        self._offset = offset
        self.family = family
        self.mem_type = mem_type
        self.raw_block = raw_block
        self.excluded = False
        self.not_parsed = True

    @property
    def size(self) -> int:
        """Segment size."""
        return -1

    @property
    def is_present(self) -> bool:
        """Returns true if the segment is present in the image."""
        return not (self.excluded) and bool(self.export())

    def clear(self) -> None:
        """Clear the segment to init state."""
        self.raw_block = None

    def __repr__(self) -> str:
        """Object representation in string format."""
        return f"Bootable image segment: {self.NAME.description}"

    def __str__(self) -> str:
        """Object description in string format."""
        return self.__repr__()

    def __len__(self) -> int:
        """Segment length."""
        return len(self.export())

    @property
    def full_image_offset(self) -> int:
        """Offset of the segment within the full bootable image."""
        if self._offset is None:
            raise SPSDKValueError("Segment offset is not defined.")
        if self._offset < 0:
            return self._offset
        return align(self._offset, self.OFFSET_ALIGNMENT)

    @full_image_offset.setter
    def full_image_offset(self, offset: int) -> None:
        self._offset = offset

    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Raw binary block of segment
        """
        if self.raw_block:
            return self.raw_block
        return b""

    def post_export(self, output_path: str) -> list[str]:
        """Post export artifacts like fuse scripts.

        :param output_path: Path to export artifacts
        :return: List of post export artifacts (usually fuse scripts)
        """
        return []

    def image_info(self) -> BinaryImage:
        """Get Image info format.

        :return: The segment content in Binary Image format.
        """
        export_binary = self.export()
        return BinaryImage(
            name=self.NAME.label,
            size=len(export_binary),
            offset=self.full_image_offset,
            binary=export_binary,
        )

    @staticmethod
    def find_segment_offset(binary: bytes) -> int:
        """Try to find the start of the Segment in data blob.

        :param binary: Data  to be used to find Segment.
        :return: Offset in data to new data container.
        """
        return 0

    @classmethod
    def cfg_key(cls) -> str:
        """Configuration key name."""
        return cls.CFG_NAME or cls.NAME.label

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Input data to parse
        :return: Parsed object
        """
        raise NotImplementedError

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: Binary image.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes
        """
        self.not_parsed = True
        if self.size > 0 and len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than parsed segment.")
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent(f"The segment {self.NAME.label} is not present")
        self.not_parsed = False
        self.raw_block = binary[: self.size] if self.size > 0 else binary

    def _is_padding(self, binary: bytes) -> bool:
        """Check is given binary is padding only."""
        if self.size > 0 and binary[: self.size] in [
            BinaryPattern(pattern).get_block(self.size) for pattern in self.IMAGE_PATTERNS
        ]:
            return True
        return False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        if not self.is_present:
            return ""
        ret = f"segment_{self.NAME.label}.bin"
        write_file(self.export(), os.path.join(output_dir, ret), mode="wb")
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent(
                f"The segment '{self.NAME.label}' is not present in the config file"
            )

        try:
            self.raw_block = load_binary(path=config.get_input_file_name(self.cfg_key()))
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"The binary file path to load {self.NAME.label} segment expected."
            ) from exc

    def pre_parse_verify(self, data: bytes) -> Verifier:
        """Pre-Parse binary to see main issue before parsing.

        :param data: Bootable image binary.
        :return: Verifier object of preparsed data.
        """
        ret = Verifier(f"Segment({self.NAME}) pre-parse")
        if self.size > 0 and len(data) < self.size:
            ret.add_record(
                "Data",
                VerifierResult.ERROR,
                f"Invalid length: Current-{len(data)} < Expected-{self.size}.",
            )
        else:
            ret.add_record("Data", VerifierResult.SUCCEEDED, "Fits")

        return ret

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        :return: Verifier of current object.
        """
        ret = Verifier(f"Segment({self.NAME}) details")
        ret.add_record_range("Offset", self._offset, min_val=-1)
        bin_size = len(self.raw_block) if (self.raw_block is not None) else 0
        ret.add_record_range("Size", bin_size)
        if self.not_parsed:
            ret.add_record("Raw data", VerifierResult.WARNING, "Not used")
        elif self.raw_block is None:
            ret.add_record("Raw data", VerifierResult.ERROR, "Is missing")
        elif self.size > 0 and bin_size > self.size:
            ret.add_record(
                "Raw data",
                VerifierResult.ERROR,
                f"Invalid length: Current-{len(self.raw_block)} != Expected-{self.size}.",
            )
        else:
            ret.add_record_bytes("Raw data", self.raw_block)

        return ret


class SegmentKeyBlob(Segment):
    """Bootable Image KeyBlob Segment class."""

    NAME = BootableImageSegment.KEYBLOB

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 256


class SegmentFcb(Segment):
    """Bootable Image FCB Segment class."""

    NAME = BootableImageSegment.FCB
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        fcb: Optional[FCB] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param fcb: FCB class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.fcb = fcb
        if fcb and raw_block and raw_block != fcb.export():
            raise SPSDKParsingError("The FCB block doesn't match the raw data.")
        self._size: Optional[int] = None

    @property
    def is_fcb_supported(self) -> bool:
        """Check if FCB is supported for the current family.

        This property determines whether Flash Configuration Block (FCB) functionality
        is available for the chip family assigned to this segment.

        :return: True if FCB is supported for the current family, False otherwise.
        """
        return self.family in FCB.get_supported_families(True)

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.fcb = None

    @property
    def size(self) -> int:
        """Size of the segment in bytes.

        :return: The segment size in bytes.
        """
        if self._size is None:
            if self.is_fcb_supported:
                # Use existing FCB if available, otherwise create a new one to get size
                self._size = (
                    self.fcb.size
                    if self.fcb
                    else FCB(family=self.family, mem_type=self.mem_type).size
                )
            else:
                self._size = -1
        return self._size

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than FCB.")
        if binary[:4] in [FCB.TAG, FCB.TAG_SWAPPED]:
            if self.is_fcb_supported:
                self.raw_block = binary[: self.size]
                self.fcb = FCB.parse(
                    binary[: self.size], family=self.family, mem_type=self.mem_type
                )
                self.not_parsed = False
                return

            logger.warning("Get the FCB binary from device where FCB is not yet supported.")
            super().parse_binary(binary=binary)
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent("The FCB segment is not present.")
        raise SPSDKParsingError("Parsing of FCB segment failed.")

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(output_dir)
        if self.fcb:
            write_file(
                self.fcb.get_config_yaml(),
                os.path.join(output_dir, f"segment_{self.NAME.label}.yaml"),
            )
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load FCB from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent("The FCB segment is not present in the config file")
        try:
            fcb = FCB.load_from_config(config.load_sub_config(self.cfg_key()))
            self.raw_block = fcb.export()
            self.fcb = fcb
            return
        except SPSDKError:
            pass

        try:
            FCB.parse(
                load_binary(config.get_input_file_name(self.cfg_key())),
                family=self.family,
                mem_type=self.mem_type,
            )
        except SPSDKError as exc:
            logger.warning(f"The given binary form of FCB block looks corrupted: {str(exc)}")
        super().load_config(config=config)


class SegmentImageVersion(Segment):
    """Bootable Image Image version Segment class."""

    NAME = BootableImageSegment.IMAGE_VERSION

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 4

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header
        """
        self.not_parsed = False
        self.raw_block = binary[: self.size] if self.size > 0 else binary

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        if not self.is_present:
            return 0
        assert isinstance(self.raw_block, bytes)
        return int.from_bytes(self.raw_block[:4], Endianness.LITTLE.value)

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        cfg_value = config.get(self.cfg_key(), 0)
        if not isinstance(cfg_value, int):
            raise SPSDKValueError(
                f"Invalid value of image version. It should be integer, and is: {cfg_value}"
            )
        self.raw_block = cfg_value.to_bytes(length=self.size, byteorder=Endianness.LITTLE.value)

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        :return: Verifier of current object.
        """
        ret = super().verify()
        if self.raw_block:
            ret.add_record_range(
                "Image Version", int.from_bytes(self.raw_block[:4], Endianness.LITTLE.value)
            )
        return ret


class SegmentImageVersionAntiPole(Segment):
    """Bootable Image Image version with antipole value Segment class."""

    NAME = BootableImageSegment.IMAGE_VERSION_AP
    CFG_NAME = "image_version"
    UNPROGRAMMED_VALUE = 0xFFFF

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 4

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        if not self.is_present:
            return 0
        assert isinstance(self.raw_block, bytes)
        return int.from_bytes(self.raw_block[:2], Endianness.LITTLE.value)

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        cfg_value = config.get(self.cfg_key())
        if cfg_value is None:
            image_version = self.UNPROGRAMMED_VALUE << 16 | self.UNPROGRAMMED_VALUE
        else:
            if not isinstance(cfg_value, int):
                raise SPSDKValueError(
                    f"Invalid value for image version. It should be integer, and is: {cfg_value}"
                )
            image_version = cfg_value & 0xFFFF
            image_version |= (image_version ^ 0xFFFF) << 16
        self.raw_block = image_version.to_bytes(length=self.size, byteorder=Endianness.LITTLE.value)

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than Image version needs.")
        self.not_parsed = False
        self.raw_block = binary[:4]

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        :return: Verifier of current object.
        """
        ret = super().verify()
        if not ret.has_errors and self.raw_block:
            image_version, image_version_anti = unpack("<HH", self.raw_block)
            if image_version == (image_version_anti ^ 0xFFFF):
                ret.add_record(
                    "Image version",
                    VerifierResult.SUCCEEDED,
                    f"{str(image_version)}, 0x{hex(image_version)}",
                )
            # unprogrammed value 0xFFFFFFFF is also considered as a valid value.
            elif image_version == image_version_anti == self.UNPROGRAMMED_VALUE:
                ret.add_record("Image version", VerifierResult.WARNING, "Has default value: 0xffff")
            else:
                ret.add_record(
                    "Image version",
                    VerifierResult.ERROR,
                    f" Image version doesn't match antipole part"
                    f"{hex(image_version)} != ^{hex(image_version_anti)}",
                )
        return ret


class SegmentKeyStore(Segment):
    """Bootable Image KeyStore Segment class."""

    NAME = BootableImageSegment.KEYSTORE

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 2048


class SegmentBeeHeader0(Segment):
    """Bootable Image BEE encryption header 0 Segment class."""

    NAME = BootableImageSegment.BEE_HEADER_0

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 512


class SegmentBeeHeader1(Segment):
    """Bootable Image BEE encryption header 1 Segment class."""

    NAME = BootableImageSegment.BEE_HEADER_1

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 512


class SegmentXmcd(Segment):
    """Bootable Image XMCD Segment class."""

    NAME = BootableImageSegment.XMCD

    @property
    def size(self) -> int:
        """Keyblob segment size."""
        return 512

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        xmcd: Optional[XMCD] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param raw_block: Raw data of segment.
        :param xmcd: XMCD class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.xmcd = xmcd
        if xmcd and raw_block and raw_block != xmcd.export():
            raise SPSDKParsingError("The XMCD block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.xmcd = None

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than XMCD.")
        # Check if the header of XMCD exists
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent("The XMCD segment is not present.")

        xmcd = XMCD.parse(binary, family=self.family)
        self.raw_block = xmcd.export()
        self.xmcd = xmcd
        self.not_parsed = False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(output_dir)
        if self.xmcd:
            write_file(self.xmcd.get_config_yaml(), os.path.join(output_dir, "segment_xmcd.yaml"))
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load XMCD from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent("The XMCD segment is not present in the config file")
        try:
            xmcd = XMCD.load_from_config(config.load_sub_config(self.cfg_key()))
            self.raw_block = xmcd.export()
            self.xmcd = xmcd
        except SPSDKError:
            super().load_config(config=config)

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        :return: Verifier of current object.
        """
        ret = super().verify()
        if not ret.has_errors and self.xmcd:
            ret.add_child(self.xmcd.verify())
        return ret


class SegmentMbi(Segment):
    """Bootable Image Master Boot Image(MBI) Segment class."""

    NAME = BootableImageSegment.MBI
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        mbi: Optional[MasterBootImage] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param mbi: Master boot image class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        if mbi and raw_block and raw_block != mbi.export():
            logger.info("The MBI block doesn't match the raw data.")
        self.mbi = mbi

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.mbi = None

    def image_info(self) -> BinaryImage:
        """Get Image info format.

        :return: The segment content in Binary Image format.
        """
        if not self.mbi:
            return super().image_info()

        image = self.mbi.export_image()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def __len__(self) -> int:
        """MBI segment length."""
        if self.mbi:
            return self.mbi.total_len
        return super().__len__()

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")
        mbi = MasterBootImage.parse(data=binary, family=self.family)
        mbi.validate()
        self.raw_block = binary
        self.mbi = mbi
        self.not_parsed = False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(output_dir)
        if self.mbi:
            write_file(
                self.mbi.get_config_yaml(output_dir), os.path.join(output_dir, "mbi_config.yaml")
            )
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load MBI from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "application"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config=config)
            return
        try:
            mbi = MasterBootImage.load_from_config(config_data)
            self.raw_block = mbi.export()
            self.mbi = mbi
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export MBI container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentHab(Segment):
    """Bootable Image High Assurance Boot(HAB) Segment class."""

    NAME = BootableImageSegment.HAB_CONTAINER
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        hab: Optional[HabImage] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param hab: High Assurance Boot class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.hab = hab
        if self.hab and raw_block:
            for pattern in self.IMAGE_PATTERNS:
                self.hab.image_pattern = pattern
                if raw_block == self.hab.export():
                    return
            logger.info("The HAB block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.hab = None

    def __len__(self) -> int:
        """Hab segment length."""
        if self.hab:
            return len(self.hab)
        return super().__len__()

    def image_info(self) -> BinaryImage:
        """Get Image info format.

        :return: The segment content in Binary Image format.
        """
        if not self.hab:
            return super().image_info()

        image = self.hab.image_info()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")
        hab = HabImage.parse(data=binary, family=self.family)
        self.raw_block = binary
        self.hab = hab
        self.not_parsed = False

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load HAB from configuration as a first attempt
        try:
            parsed_conf = config.load_sub_config(self.cfg_key())
        except (SPSDKError, UnicodeDecodeError):
            super().load_config(config=config)
            return
        try:

            schemas = HabImage.get_validation_schemas(self.family)
            parsed_conf.check(schemas, check_unknown_props=True)
            hab = HabImage.load_from_config(parsed_conf)
            self.raw_block = hab.export()
            self.hab = hab
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export HAB container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentAhab(Segment):
    """Bootable Image Advanced High Assurance Boot(HAB) Segment class."""

    NAME = BootableImageSegment.AHAB_CONTAINER
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        ahab: Optional[AHABImage] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param ahab: Advanced High Assurance Boot class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.ahab = ahab
        if ahab and raw_block and len(raw_block) != len(ahab.export()):
            logger.info("The AHAB block doesn't match the raw data.")

    def __len__(self) -> int:
        """Ahab segment length."""
        if self.ahab:
            return len(self.ahab)
        return super().__len__()

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.ahab = None

    def image_info(self) -> BinaryImage:
        """Get Image info format.

        :return: The segment content in Binary Image format.
        """
        if not self.ahab:
            return super().image_info()

        image = self.ahab.image_info()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")

        try:
            AHABImage._parse_container_type(binary).check_container_head(binary).validate()
        except SPSDKError as exc:
            raise SPSDKSegmentNotPresent("AHAB container header not available") from exc

        ahab = AHABImage.parse(binary, family=self.family)
        self.raw_block = binary[: len(ahab)]
        self.ahab = ahab
        self.not_parsed = False

    def post_export(self, output_path: str) -> list[str]:
        """Post export step.

        :param output_path: _description_
        :return: _description_
        """
        if self.ahab:
            return self.ahab.post_export(output_path)
        return []

    @staticmethod
    def find_segment_offset(binary: bytes) -> int:
        """Try to find the start of the AHAB Image in data blob.

        :param binary: Data  to be used to find AHAB container.
        :return: Offset in data to new data container.
        """
        return AHABImage.find_offset_of_ahab(binary)

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(output_dir)
        if self.ahab:
            ahab_parse_path = os.path.join(output_dir, self.NAME.label)
            cfg_path = os.path.join(ahab_parse_path, f"segment_{self.NAME.label}.yaml")
            write_file(self.ahab.get_config_yaml(ahab_parse_path), cfg_path)
            ret = os.path.join(f"{self.NAME.label}", f"segment_{self.NAME.label}.yaml")
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load AHAB from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent(
                f"The segment '{self.NAME.label}' is not present in the config file"
            )
        try:
            config_data = config.load_sub_config(self.cfg_key())
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            AHABImage.pre_check_config(config_data)
            ahab = AHABImage.load_from_config(config_data)
            ahab.update_fields()
            self.raw_block = ahab.export()
            self.ahab = ahab
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export AHAB container from the configuration:\n{str(exc)}"
            ) from exc

    def pre_parse_verify(self, data: bytes) -> Verifier:
        """Pre-Parse binary T osee main issue before parsing.

        :param data: Bootable image binary.
        :return: Verifier object of preparsed data.
        """
        ret = super().pre_parse_verify(data)
        ret.add_child(AHABImage.pre_parse_verify(data))
        return ret

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        :return: Verifier of current object.
        """
        ret = super().verify()
        if not ret.has_errors and self.ahab:
            ret.add_child(self.ahab.verify())
        return ret


class SegmentPrimaryAhab(SegmentAhab):
    """Primary Bootable Image Advanced High Assurance Boot(HAB) Segment class."""

    NAME = BootableImageSegment.PRIMARY_IMAGE_CONTAINER_SET


class SegmentSecondaryAhab(SegmentAhab):
    """Primary Bootable Image Advanced High Assurance Boot(HAB) Segment class."""

    NAME = BootableImageSegment.SECONDARY_IMAGE_CONTAINER_SET
    OFFSET_ALIGNMENT = 1024
    INIT_SEGMENT = False

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        cfg_value = config.get(self.cfg_key())
        if cfg_value and isinstance(cfg_value, dict):
            if "offset" in cfg_value:
                self._offset = value_to_int(cfg_value["offset"])
            # Update config with just the path for parent class processing
            config[self.cfg_key()] = cfg_value["path"]
        super().load_config(config)

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration including store the data to specified path.

        :param output_dir: Path where the information should be stored
        :returns: Value of segment to configuration file
        """
        ret = super().create_config(output_dir)
        # if offset is not < 0, the segment isn't right behind the previous segment
        if self.full_image_offset < 0:
            return ret
        return {"path": ret, "offset": self.full_image_offset}


class SegmentSB21(Segment):
    """Bootable Image Secure Binary 2.1 Segment class."""

    NAME = BootableImageSegment.SB21
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        sb21: Optional[BootImageV21] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param sb21: Secure Binary v2.1 class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.sb21 = sb21
        if sb21 and raw_block and raw_block != sb21.export():
            logger.info("The SB21 block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.sb21 = None

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load SB2.1 from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "sb21"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            config_data.check(
                BootImageV21.get_validation_schemas(self.family), check_unknown_props=True
            )
            sb21 = BootImageV21.load_from_config(config_data)
            self.raw_block = sb21.export()
            self.sb21 = sb21
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export SB2.1 from the configuration:\n{str(exc)}"
            ) from exc

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        """
        self.not_parsed = True
        BootImageV21.validate_header(binary)
        super().parse_binary(binary=binary)


class SegmentSB31(Segment):
    """Bootable Image Secure Binary 3.1 Segment class."""

    NAME = BootableImageSegment.SB31
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        sb31: Optional[SecureBinary31] = None,
    ) -> None:
        """Segment initialization, at least raw data are stored.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param sb31: Secure Binary v3.1 class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.sb31 = sb31

    def clear(self) -> None:
        """Clear the segment to init state."""
        super().clear()
        self.sb31 = None

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        :param config: Configuration of Segment.
        """
        # Try to load SB3.1 from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "sb31"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            SecureBinary31.pre_check_config(config_data)
            sb31 = SecureBinary31.load_from_config(config_data)
            self.raw_block = sb31.export()
            self.sb31 = sb31
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export SB3.1 from the configuration:\n{str(exc)}"
            ) from exc

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        :param binary: binary image.
        """
        self.not_parsed = True
        SecureBinary31.validate_header(binary)
        super().parse_binary(binary=binary)


def get_segments() -> dict[BootableImageSegment, Type[Segment]]:
    """Get list of all supported segments."""
    ret = {}
    for var in globals():
        obj = globals()[var]
        if isclass(obj) and issubclass(obj, Segment) and obj is not Segment:
            assert issubclass(obj, Segment)  # pylint: disable=assert-instance
            ret[obj.NAME] = obj
    return ret


def get_segment_class(name: BootableImageSegment) -> Type["Segment"]:
    """Get the segment class type.

    :return: Segment class type.
    """
    segments = get_segments()
    if name not in segments:
        raise SPSDKValueError(f"Unsupported Bootable image segment with name: {name.label}")
    return segments[name]
