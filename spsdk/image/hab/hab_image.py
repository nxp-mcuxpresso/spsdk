#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB (High Assurance Boot) image container management.

This module provides functionality for creating, manipulating, and managing
HAB image containers used in NXP's secure boot process. It includes support
for boot device configuration and HAB image operations.
"""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.commands.commands import ImageBlock
from spsdk.image.hab.segments.seg_app import HabSegmentApp
from spsdk.image.hab.segments.seg_bdt import HabSegmentBDT
from spsdk.image.hab.segments.seg_csf import HabSegmentCSF
from spsdk.image.hab.segments.seg_dcd import HabSegmentDcd
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt
from spsdk.image.hab.segments.seg_xmcd import HabSegmentXMCD
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum
from spsdk.image.hab.utils import get_ivt_offset_from_cfg
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import BinaryPattern
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class BootDevice(SpsdkEnum):
    """HAB boot device enumeration.

    Enumeration of supported boot devices for High Assurance Boot (HAB) image
    configuration, defining the storage medium from which the bootloader loads
    the application image.
    """

    FLEXSPI_NOR = (0, "flexspi_nor")
    FLEXSPI_NAND = (1, "flexspi_nand")
    SEMC_NAND = (2, "semc_nand")
    SD = (3, "sd")
    MMC = (4, "mmc")
    SERIAL_DOWNLOADER = (5, "serial_downloader")


class HabImage(FeatureBaseClass):
    """HAB (High Assurance Boot) image representation for NXP MCUs.

    This class manages HAB-enabled bootable images including IVT (Image Vector Table)
    configuration, segments management, and security features like authentication
    and encryption for secure boot operations.

    :cvar FEATURE: Database feature identifier for HAB functionality.
    """

    FEATURE = DatabaseManager.HAB

    def __init__(
        self,
        family: FamilyRevision,
        flags: int,
        start_address: int,
        segments: list[HabSegmentBase],
        boot_device: Optional[BootDevice] = None,
        ivt_offset: Optional[int] = None,
        image_pattern: str = "zeros",
    ) -> None:
        """Initialize HAB (High Assurance Boot) image.

        Creates a new HAB image instance with specified configuration parameters including
        family revision, boot flags, memory addresses, and image segments.

        :param family: Target MCU family and revision information.
        :param flags: Boot flags controlling image behavior.
        :param start_address: Start address of bootable image in memory.
        :param segments: List of HAB segments to include in the image.
        :param boot_device: Optional boot device specification.
        :param ivt_offset: Optional IVT offset value which is actually the HAB image offset.
        :param image_pattern: Image pattern used to fill empty spaces, defaults to "zeros".
        """
        self.db = get_db(family)
        self._ivt_offset = ivt_offset
        self.boot_device = boot_device
        self.family = family
        self.flags = flags
        self.start_address = start_address
        self.segments = segments
        self.image_pattern = image_pattern

    def __str__(self) -> str:
        """Get string representation of HAB image.

        Provides a formatted string containing key information about the HAB image
        including family, authentication status, encryption status, IVT offset,
        and start address.

        :return: Formatted string representation of the HAB image.
        """
        return (
            "HAB Image:\n"
            f"  Family:             {self.family}\n"
            f"  Is Authenticated:   {self.is_authenticated}\n"
            f"  Is Encrypted:       {self.is_encrypted}\n"
            f"  IVT Offset:         {hex(self.ivt_offset)}\n"
            f"  Start Address:      {hex(self.start_address)}\n"
        )

    def __repr__(self) -> str:
        """Get string representation of HAB Image object.

        :return: String representation containing the target family name.
        """
        return f"HAB Image for {self.family}"

    def verify(self) -> Verifier:
        """Verify HAB image data and return verification results.

        This method performs comprehensive verification of the High Assurance Boot (HAB) image,
        including validation of flags, IVT offset, and all image segments. It checks for
        custom IVT offsets and validates flag values against expected ranges.

        :return: Verifier object containing detailed verification results and any warnings or errors.
        """
        ret = Verifier("High Assurance Boot")
        ret.add_record_bit_range("Flags", self.flags, 32)

        if self.boot_device and self.ivt_offset != self.db.get_int(
            DatabaseManager.BOOTABLE_IMAGE,
            ["mem_types", self.boot_device.label, "segments", "hab_container"],
        ):
            ret.add_record("IVT Offset", VerifierResult.WARNING, "Custom IVT offset defined.")
        if self.flags not in [0x0, 0x8, 0xC]:
            ret.add_record("Flags", VerifierResult.ERROR, "Invalid flags value.")
        for segment in self.segments:
            ret.add_child(segment.verify())
        return ret

    @property
    def ivt_offset(self) -> int:
        """Get the IVT (Image Vector Table) offset for the HAB image.

        The method retrieves the IVT offset from either a cached value or from the database
        based on the boot device configuration. The IVT offset is required for proper HAB
        image formatting and boot sequence.

        :raises SPSDKError: When IVT offset cannot be determined (no cached value and no boot device).
        :return: The IVT offset value in bytes.
        """
        if self._ivt_offset is not None:
            return self._ivt_offset
        if self.boot_device:
            return self.db.get_int(
                DatabaseManager.BOOTABLE_IMAGE,
                ["mem_types", self.boot_device.label, "segments", "hab_container"],
            )
        raise SPSDKError("IVT offset could not be found.")

    def get_supported_boot_devices(self) -> list[BootDevice]:
        """Get supported boot devices for this HAB image.

        This method retrieves the list of boot devices (target memories) that are
        supported for the current family configuration.

        :return: List of supported boot devices for the current family.
        """
        return self.get_boot_devices(self.family)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the HAB image feature.

        The method generates a configuration object containing options like flags, family information,
        revision, and optional file paths for XMCD and DCD segments based on the current state.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with HAB image settings.
        """
        config = Config()
        config["options"] = {
            "flags": self.flags,
            "family": self.family.name,
            "revision": self.family.revision,
            "bootDevice": None,  # TODO
        }
        if self.xmcd_segment:
            config["options"]["XMCDFilePath"] = "xmcd.bin"
        if self.dcd_segment:
            config["options"]["DCDFilePath"] = "dcd.bin"  # TODO
        return config

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method extracts options from the configuration, validates them against basic schemas,
        loads the family revision information, and returns the appropriate validation schemas
        for the specified family.

        :param config: Valid configuration object containing options and family information.
        :return: List of validation schema dictionaries for the specified family.
        """
        options = config.get_config("options")
        options.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(options)
        return cls.get_validation_schemas(family)

    def get_segment(self, segment: HabSegmentEnum) -> Optional[HabSegmentBase]:
        """Get image's segment by segment type.

        Searches through all segments in the image to find the one matching
        the specified segment identifier.

        :param segment: Segment enum specifying which segment type to retrieve.
        :return: The matching segment if found, None otherwise.
        """
        for seg in self.segments:
            if seg.SEGMENT_IDENTIFIER == segment:
                return seg
        return None

    @property
    def is_encrypted(self) -> bool:
        """Check if the HAB image is encrypted.

        :return: True if image is encrypted, False otherwise.
        """
        return bool(((self.flags << 1) & 0xF) >> 3)

    @property
    def is_authenticated(self) -> bool:
        """Check if the image is authenticated.

        The method examines the authentication flag in the image flags field by
        extracting bits 3-0 and checking bit 3 specifically.

        :return: True if image is authenticated, False otherwise.
        """
        return bool((self.flags & 0xF) >> 3)

    @property
    def ivt_segment(self) -> HabSegmentIvt:
        """Get IVT segment object from the HAB image.

        Retrieves the Image Vector Table (IVT) segment from the current HAB image segments.
        The IVT segment contains essential boot information and must be present in valid HAB images.

        :raises SPSDKSegmentNotPresent: When the IVT segment is not found in the image.
        :return: The IVT segment object containing boot vector information.
        """
        seg = self.get_segment(HabSegmentEnum.IVT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.IVT.label} is missing")
        assert isinstance(seg, HabSegmentIvt)
        return seg

    @property
    def bdt_segment(self) -> HabSegmentBDT:
        """Get BDT segment object from the HAB image.

        Retrieves the Boot Data Table (BDT) segment from the current HAB image segments.

        :raises SPSDKSegmentNotPresent: When BDT segment is not present in the image.
        :return: BDT segment object containing boot data table information.
        """
        seg = self.get_segment(HabSegmentEnum.BDT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.BDT.label} is missing")
        assert isinstance(seg, HabSegmentBDT)
        return seg

    @property
    def dcd_segment(self) -> Optional[HabSegmentDcd]:
        """Get DCD segment object if it exists.

        :return: DCD segment object if exists, None otherwise.
        """
        seg = self.get_segment(HabSegmentEnum.DCD)
        return seg  # type: ignore

    @property
    def xmcd_segment(self) -> Optional[HabSegmentXMCD]:
        """Get XMCD segment object from the HAB image.

        Retrieves the XMCD (External Memory Configuration Data) segment if it exists
        in the current HAB image.

        :return: XMCD segment object if present, None otherwise.
        """
        seg = self.get_segment(HabSegmentEnum.XMCD)
        return seg  # type: ignore

    @property
    def app_segment(self) -> HabSegmentApp:
        """Get APP segment object from the HAB image.

        Retrieves the application segment from the HAB image segments collection.
        The APP segment contains the main application code and data.

        :raises SPSDKSegmentNotPresent: When APP segment is not present in the image.
        :return: The application segment object.
        """
        seg = self.get_segment(HabSegmentEnum.APP)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.APP.label} is missing")
        assert isinstance(seg, HabSegmentApp)
        return seg

    @property
    def csf_segment(self) -> Optional[HabSegmentCSF]:
        """Get CSF segment object if it exists.

        :return: CSF segment object if exists, None otherwise.
        """
        seg = self.get_segment(HabSegmentEnum.CSF)
        return seg  # type: ignore

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the HAB image object from parsed configuration.

        Creates a HAB image by loading all available segments and configuring the image with the
        specified options including family, flags, IVT offset, and start address.

        :param config: Image configuration containing segments and options data.
        :return: Configured HAB image object with loaded segments.
        """
        segments = []
        for segment_cls in HabSegmentBase.__subclasses__():
            try:
                segment = segment_cls.load_from_config(config)
                segments.append(segment)
            except SPSDKSegmentNotPresent:
                pass
        options = config.get_config("options")
        hab = cls(
            family=FamilyRevision.load_from_config(options),
            flags=options["flags"],
            ivt_offset=get_ivt_offset_from_cfg(config),
            start_address=options["startAddress"],
            segments=segments,
        )
        hab.update_csf()
        if hab.is_encrypted:
            assert hab.csf_segment, "CSF segment is required for encrypted images"
            hab.csf_segment.save_dek()
        return hab

    def _get_signed_blocks(self) -> list[ImageBlock]:
        """Get list of signed blocks for HAB image authentication.

        Creates ImageBlock objects representing memory regions that need to be signed
        for HAB (High Assurance Boot) authentication. The method groups related segments
        (IVT/BDT, DCD, XMCD) into blocks and includes the application segment if the
        image is not encrypted.

        :return: List of ImageBlock objects representing signed memory regions.
        """
        blocks = []

        def add_block(offset: int, block_size: int) -> None:
            """Add image block to the blocks list.

            Creates a new ImageBlock with calculated base address and start position
            relative to the IVT offset, then appends it to the blocks collection.

            :param offset: Offset from IVT position where the block starts.
            :param block_size: Size of the block in bytes.
            """
            blocks.append(
                ImageBlock(
                    base_address=self.start_address + self.ivt_offset + offset,
                    start=self.ivt_offset + offset,
                    size=block_size,
                )
            )

        segment_blocks = [
            [HabSegmentEnum.IVT, HabSegmentEnum.BDT],
            [HabSegmentEnum.DCD],
            [HabSegmentEnum.XMCD],
        ]
        for segments_names in segment_blocks:
            all_defined = all([self.get_segment(seg_name) for seg_name in segments_names])
            if all_defined:
                block_size = sum(
                    [
                        self.get_segment(seg_name).size  # type: ignore
                        for seg_name in segments_names
                        if self.get_segment(seg_name) is not None
                    ]
                )
                segment = self.get_segment(segments_names[0])
                assert isinstance(segment, HabSegmentBase)
                add_block(segment.offset, block_size)
        if not self.is_encrypted:
            add_block(self.app_segment.offset, self.app_segment.size)
        return blocks

    def _get_encrypted_blocks(self) -> list[ImageBlock]:
        """Get list of encrypted blocks for HAB image.

        Creates image blocks that represent the encrypted portions of the HAB image,
        specifically the application segment that needs to be encrypted.

        :return: List of ImageBlock objects representing encrypted segments.
        """
        blocks = []
        blocks.append(
            ImageBlock(
                base_address=self.start_address + self.ivt_offset + self.app_segment.offset,
                start=self.ivt_offset + self.app_segment.offset,
                size=self.app_segment.size,
            )
        )
        return blocks

    def update_csf(self) -> None:
        """Update the CSF segment including signing and encryption.

        This method handles the complete CSF (Command Sequence File) segment update process,
        including encryption of application data when encryption is enabled and signature
        updates when authentication is enabled. It modifies the BDT segment length for
        encrypted images and processes the image data accordingly.

        :raises SPSDKError: When CSF segment is missing but encryption is enabled.
        """
        if self.is_encrypted:
            if not self.csf_segment:
                raise SPSDKError("CSF segment is missing")
            self.bdt_segment.bdt.app_length += HabSegmentCSF.KEYBLOB_SIZE
        if self.csf_segment:
            image = self.export_padding()
            image = image[: self.ivt_offset + self.csf_segment.offset]
            if self.is_encrypted:
                blocks = self._get_encrypted_blocks()
                encrypted_app = self.csf_segment.encrypt(image, blocks)

                self.app_segment.binary = encrypted_app
            if self.is_authenticated:
                blocks = self._get_signed_blocks()
                self.csf_segment.update_signature(
                    image, blocks, base_data_address=self.start_address
                )

    def image_info(self, padding: bool = False) -> BinaryImage:
        """Create Binary image of HAB image.

        The method creates a BinaryImage object containing all segments of the HAB image
        with proper offsets and binary data.

        :param padding: If True, adds IVT offset to segment offsets for proper alignment.
        :return: BinaryImage object containing the complete HAB image structure.
        """
        bin_image = BinaryImage(
            name="HAB image",
            size=0,
            pattern=BinaryPattern(self.image_pattern),
        )
        for segment in self.segments:
            binary = segment.export()
            offset = segment.offset + self.ivt_offset if padding else segment.offset
            bin_image.add_image(
                BinaryImage(
                    name=segment.__class__.__name__,
                    size=len(binary),
                    offset=offset,
                    binary=binary,
                )
            )
        return bin_image

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse existing binary into HAB image object.

        The method analyzes binary data to extract HAB segments and constructs a HAB image
        object with proper IVT offset, start address, and segment configuration.

        :param data: Binary data to be parsed into HAB image segments.
        :param family: Target chip family revision for parsing context.
        :return: HAB image object constructed from parsed binary data.
        :raises AssertionError: When required IVT or BDT segments are not found.
        """
        segments: list[HabSegmentBase] = []
        for seg_class in HabSegmentBase.__subclasses__():
            try:
                segment = seg_class.parse(data, family)
                segments.append(segment)
            except SPSDKSegmentNotPresent:
                pass

        ivt = next((seg for seg in segments if seg.SEGMENT_IDENTIFIER == HabSegmentEnum.IVT))
        assert isinstance(ivt, HabSegmentIvt)
        bdt = next((seg for seg in segments if seg.SEGMENT_IDENTIFIER == HabSegmentEnum.BDT))
        assert isinstance(bdt, HabSegmentBDT)
        start_address = bdt.app_start
        ivt_offset = ivt.ivt_address - bdt.app_start
        flags = cls._get_flags(segments)
        return cls(
            family=family,
            flags=flags,
            ivt_offset=ivt_offset,
            start_address=start_address,
            segments=segments,
        )

    @staticmethod
    def _get_flags(segments: list[HabSegmentBase]) -> int:
        """Get flags value based on CSF segment presence and decrypt command.

        The method examines the provided segments to find a CSF (Command Sequence File) segment
        and determines the appropriate flags value based on whether a decrypt data command
        is present.

        :param segments: List of HAB segments to analyze for CSF presence and decrypt commands.
        :return: Flags value - 0xC if decrypt command exists, 0x8 if CSF exists without decrypt,
                 or 0x0 if no CSF segment is found.
        """
        csf = next((seg for seg in segments if seg.SEGMENT_IDENTIFIER == HabSegmentEnum.CSF), None)
        if csf is None:
            return 0x0
        assert isinstance(csf, HabSegmentCSF)
        decrypt = csf.get_decrypt_data_cmd()
        return 0xC if decrypt else 0x8

    def export_padding(self) -> bytes:
        """Export image as binary data with initial padding included.

        :return: Binary representation of the image including padding.
        """
        return self.image_info(padding=True).export()

    def export(self) -> bytes:
        """Export the HAB image into binary format.

        :return: Binary representation of the HAB image.
        """
        return self.image_info(padding=False).export()

    def __len__(self) -> int:
        """Get length of HAB image.

        Calculates the total length by finding the segment with the highest offset
        and adding its size to determine the overall image length.

        :return: Total length of the HAB image in bytes.
        """
        last_offset = 0
        last_len = 0
        for seg in self.segments:
            if seg.offset > last_offset:
                last_offset = seg.offset
                last_len = seg.size
        return last_offset + last_len

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for HAB image configuration.

        The method generates validation schemas based on the specified family revision,
        including HAB options, input configurations, and sections. It dynamically updates
        the schema with supported families and available boot devices for the given family.

        :param family: Family revision to generate schemas for.
        :return: List of validation schema dictionaries for HAB image configuration.
        """
        hab_schema = get_schema_file(DatabaseManager.HAB)

        schemas: list[dict[str, Any]] = []
        sch_hab = hab_schema["hab"]
        update_validation_schema_family(
            sch_hab["properties"]["options"]["properties"], cls.get_supported_families(), family
        )

        if family:
            sch_hab["properties"]["options"]["properties"]["bootDevice"]["enum"] = [
                dev.label for dev in cls.get_boot_devices(family)
            ]
        schemas = [sch_hab]
        schemas.extend([hab_schema[x] for x in ["hab_input", "hab_sections"]])
        return schemas

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Generate HAB configuration template.

        Creates a configuration template for Hardware Abstraction Boot (HAB) image
        based on the specified family revision and validation schemas.

        :param family: Target MCU family and revision for template generation.
        :return: Configuration template as a string with proper formatting and comments.
        """
        return CommentedConfig(
            "HAB Configuration template.", cls.get_validation_schemas(family)
        ).get_template()

    @classmethod
    def transform_configuration(cls, config: dict[Any, Any]) -> dict[Any, Any]:
        """Transform configuration from BD parser to flat YAML structure.

        Converts section IDs to human-readable names and flattens the options structure
        for easier YAML representation. Maps numeric section identifiers to their
        corresponding command names and extracts options into a simplified format.

        :param config: Parsed configuration dictionary from BD parser containing sections
                       and source file information
        :return: Transformed configuration with named sections and flattened structure
        """
        section_id_to_name = {
            20: "Header",
            21: "InstallSRK",
            22: "InstallCSFK",
            23: "InstallNOCAK",
            24: "AuthenticateCSF",
            25: "InstallKey",
            26: "AuthenticateData",
            27: "SecretKey",
            28: "Decrypt",
            29: "NOP",
            30: "SetMid",
            31: "SetEngine",
            32: "Init",
            33: "Unlock",
        }

        result = []  # Extract options for each section and replace section_id with name
        for section in config.get("sections", []):
            section_id = section["section_id"]
            section_name = section_id_to_name.get(section_id)
            if not section_name:
                continue
            options = {}
            for option in section["options"]:
                options.update(option)
            result.append({section_name: options})

        config["sections"] = result
        config["inputImageFile"] = config["sources"]["elfFile"]
        return config

    @classmethod
    def transform_bd_configuration(cls, config: Config) -> Config:
        """Transform configuration from flat structure to BD structure.

        Converts a flat configuration structure from the BD parser into a structured
        format with sections containing IDs, options, and commands. Maps section names
        to their corresponding numeric identifiers and restructures the data for
        further processing.

        :param config: Parsed configuration from BD parser containing sections and input image file.
        :return: Transformed configuration with structured sections and sources.
        """
        section_name_to_id = {
            "Header": 20,
            "InstallSRK": 21,
            "InstallCSFK": 22,
            "InstallNOCAK": 23,
            "AuthenticateCSF": 24,
            "InstallKey": 25,
            "AuthenticateData": 26,
            "SecretKey": 27,
            "Decrypt": 28,
            "NOP": 29,
            "SetMid": 30,
            "SetEngine": 31,
            "Init": 32,
            "Unlock": 33,
        }

        sections = []
        for section in config.get("sections", []):
            for section_name, options in section.items():
                section_id = section_name_to_id.get(section_name)
                if section_id is not None:
                    sections.append(
                        {
                            "section_id": section_id,
                            "options": [{k: v} for k, v in options.items()],
                            "commands": [],
                        }
                    )

        config["sections"] = sections
        sources = {"sources": {"elfFile": config["inputImageFile"]}}
        config.update(sources)
        return config

    @staticmethod
    def get_boot_devices(family: FamilyRevision) -> list[BootDevice]:
        """Get all supported boot devices for given family.

        The method retrieves boot device information from the database for the specified
        family and returns a list of BootDevice objects created from the available
        memory types.

        :param family: Target family revision to get boot devices for.
        :return: List of supported boot devices for the specified family.
        """
        db = get_db(family)
        return [
            BootDevice.from_label(dev)
            for dev in list(db.get_dict(DatabaseManager.HAB, "mem_types").keys())
        ]

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export steps for all segments in the HAB image.

        This method iterates through all segments in the image and executes their
        post-export operations, collecting any generated files from each segment.

        :param output_path: Directory path where post-export files should be generated.
        :return: List of file paths that were generated during post-export operations.
        """
        generated_files: list[str] = []
        for segment in self.segments:
            generated_files.extend(segment.post_export(output_path))
        return generated_files
