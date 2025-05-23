#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains HAB container related code."""

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
    """Boot device enum."""

    FLEXSPI_NOR = (0, "flexspi_nor")
    FLEXSPI_NAND = (1, "flexspi_nand")
    SEMC_NAND = (2, "semc_nand")
    SD = (3, "sd")
    MMC = (4, "mmc")
    SERIAL_DOWNLOADER = (5, "serial_downloader")


class HabImage(FeatureBaseClass):
    """Hab image."""

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
        """HAB image initialization.

        :param flags: Flags
        :param ivt_offset: IVT offset value which is actually the HAB image offset
        :param start_address: Start address of bootable image
        :param segments: Segments list
        :param image_pattern: Image pattern used to fill empty spaces
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
        return (
            "HAB Image:\n"
            f"  Family:             {self.family}\n"
            f"  Is Authenticated:   {self.is_authenticated}\n"
            f"  Is Encrypted:       {self.is_encrypted}\n"
            f"  IVT Offset:         {hex(self.ivt_offset)}\n"
            f"  Start Address:      {hex(self.start_address)}\n"
        )

    def __repr__(self) -> str:
        return f"HAB Image for {self.family}"

    def verify(self) -> Verifier:
        """Verify HAB image data."""
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
        """IVT offset property."""
        if self._ivt_offset is not None:
            return self._ivt_offset
        if self.boot_device:
            return self.db.get_int(
                DatabaseManager.BOOTABLE_IMAGE,
                ["mem_types", self.boot_device.label, "segments", "hab_container"],
            )
        raise SPSDKError("IVT offset could not be found.")

    def get_supported_boot_devices(self) -> list[BootDevice]:
        """Get supported boot devices(target memories)."""
        return self.get_boot_devices(self.family)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
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
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
        """
        options = config.get_config("options")
        options.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(options)
        return cls.get_validation_schemas(family)

    def get_segment(self, segment: HabSegmentEnum) -> Optional[HabSegmentBase]:
        """Get image's segment.

        :param segment: Segment enum
        """
        for seg in self.segments:
            if seg.SEGMENT_IDENTIFIER == segment:
                return seg
        return None

    @property
    def is_encrypted(self) -> bool:
        """Returns true if image is encrypted, false otherwise."""
        return bool(((self.flags << 1) & 0xF) >> 3)

    @property
    def is_authenticated(self) -> bool:
        """Returns true if image is authenticated, false otherwise."""
        return bool((self.flags & 0xF) >> 3)

    @property
    def ivt_segment(self) -> HabSegmentIvt:
        """IVT segment object."""
        seg = self.get_segment(HabSegmentEnum.IVT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.IVT.label} is missing")
        assert isinstance(seg, HabSegmentIvt)
        return seg

    @property
    def bdt_segment(self) -> HabSegmentBDT:
        """BDT segment object."""
        seg = self.get_segment(HabSegmentEnum.BDT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.BDT.label} is missing")
        assert isinstance(seg, HabSegmentBDT)
        return seg

    @property
    def dcd_segment(self) -> Optional[HabSegmentDcd]:
        """DCD segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegmentEnum.DCD)
        return seg  # type: ignore

    @property
    def xmcd_segment(self) -> Optional[HabSegmentXMCD]:
        """XMCD segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegmentEnum.XMCD)
        return seg  # type: ignore

    @property
    def app_segment(self) -> HabSegmentApp:
        """APP segment object."""
        seg = self.get_segment(HabSegmentEnum.APP)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegmentEnum.APP.label} is missing")
        assert isinstance(seg, HabSegmentApp)
        return seg

    @property
    def csf_segment(self) -> Optional[HabSegmentCSF]:
        """CSF segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegmentEnum.CSF)
        return seg  # type: ignore

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the HAB image object from parsed bd_data configuration.

        :param config: Image configuration
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
        blocks = []

        def add_block(offset: int, block_size: int) -> None:
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
        """Update the CSF segment including signing and encryption."""
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

        :return: BinaryImage object of HAB image.
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

        :param data: Binary to be parsed
        :param family: Chip family name
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
        csf = next((seg for seg in segments if seg.SEGMENT_IDENTIFIER == HabSegmentEnum.CSF), None)
        if csf is None:
            return 0x0
        assert isinstance(csf, HabSegmentCSF)
        decrypt = csf.get_decrypt_data_cmd()
        return 0xC if decrypt else 0x8

    def export_padding(self) -> bytes:
        """Get into binary including initial padding."""
        return self.image_info(padding=True).export()

    def export(self) -> bytes:
        """Export into binary."""
        return self.image_info(padding=False).export()

    def __len__(self) -> int:
        """Get length of HAB image."""
        last_offset = 0
        last_len = 0
        for seg in self.segments:
            if seg.offset > last_offset:
                last_offset = seg.offset
                last_len = seg.size
        return last_offset + last_len

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
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
        """Generate configuration template.

        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        return CommentedConfig(
            "HAB Configuration template.", cls.get_validation_schemas(family)
        ).get_template()

    @classmethod
    def transform_configuration(cls, config: dict[Any, Any]) -> dict[Any, Any]:
        """Transform configuration from BD parser to flat YAML structure.

        :param config: Parsed configuration from BD parser
        :return: Transformed configuration
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

        :param config: Parsed configuration from BD parser
        :return: Transformed configuration
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

        :param family: Target family name.
        :return: List of supported boot devices.
        """
        db = get_db(family)
        return [
            BootDevice.from_label(dev)
            for dev in list(db.get_dict(DatabaseManager.HAB, "mem_types").keys())
        ]

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export steps."""
        generated_files: list[str] = []
        for segment in self.segments:
            generated_files.extend(segment.post_export(output_path))
        return generated_files
