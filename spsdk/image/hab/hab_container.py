#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains HAB container related code."""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.commands.commands import ImageBlock
from spsdk.image.hab.hab_config import HabConfig
from spsdk.image.hab.segments import (
    SEGMENTS_MAPPING,
    AppHabSegment,
    BdtHabSegment,
    CsfHabSegment,
    DcdHabSegment,
    HabSegment,
    HabSegmentBase,
    HabSegments,
    IvtHabSegment,
    XmcdHabSegment,
)
from spsdk.sbfile.sb2.sly_bd_parser import BDParser
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, load_configuration, load_text
from spsdk.utils.schema_validator import (
    CommentedConfig,
    check_config,
    update_validation_schema_family,
)

logger = logging.getLogger(__name__)


class HabContainer:
    """Hab container."""

    def __init__(
        self,
        flags: int,
        ivt_offset: int,
        start_address: int,
        segments: HabSegments,
        image_pattern: str = "zeros",
    ) -> None:
        """HAB container initialization.

        :param flags: Flags
        :param ivt_offset: IVT offset value which is actually the HAB container offset
        :param start_address: Start address of bootable image
        :param segments: Segments list
        :param image_pattern: Image pattern used to fill empty spaces
        """
        self.flags = flags
        self.ivt_offset = ivt_offset
        self.start_address = start_address
        self.segments = segments
        self.image_pattern = image_pattern

    def get_segment(self, segment: HabSegment) -> Optional[HabSegmentBase]:
        """Get container's segment.

        :param segment: Segment enum
        """
        try:
            seg = self.segments.get_segment(segment)
            return seg
        except SPSDKSegmentNotPresent:
            return None

    @property
    def is_encrypted(self) -> bool:
        """Returns true if container is encrypted, false otherwise."""
        return bool(((self.flags << 1) & 0xF) >> 3)

    @property
    def is_authenticated(self) -> bool:
        """Returns true if container is authenticated, false otherwise."""
        return bool((self.flags & 0xF) >> 3)

    @property
    def ivt_segment(self) -> IvtHabSegment:
        """IVT segment object."""
        seg = self.get_segment(HabSegment.IVT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegment.IVT.label} is missing")
        assert isinstance(seg, IvtHabSegment)
        return seg

    @property
    def bdt_segment(self) -> BdtHabSegment:
        """BDT segment object."""
        seg = self.get_segment(HabSegment.BDT)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegment.BDT.label} is missing")
        assert isinstance(seg, BdtHabSegment)
        return seg

    @property
    def dcd_segment(self) -> Optional[DcdHabSegment]:
        """DCD segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegment.DCD)
        return seg  # type: ignore

    @property
    def xmcd_segment(self) -> Optional[XmcdHabSegment]:
        """XMCD segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegment.XMCD)
        return seg  # type: ignore

    @property
    def app_segment(self) -> AppHabSegment:
        """APP segment object."""
        seg = self.get_segment(HabSegment.APP)
        if not seg:
            raise SPSDKSegmentNotPresent(f"Segment {HabSegment.APP.label} is missing")
        assert isinstance(seg, AppHabSegment)
        return seg

    @property
    def csf_segment(self) -> Optional[CsfHabSegment]:
        """CSF segment object if exists, None otherwise."""
        seg = self.get_segment(HabSegment.CSF)
        return seg  # type: ignore

    @classmethod
    def load_from_config(
        cls,
        config: dict[str, Any],
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Load the HAB container object from parsed bd_data configuration.

        :param config: Image configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        hab_config = HabConfig.load_from_config(config, search_paths)
        segments = HabSegments()
        for segment_cls in SEGMENTS_MAPPING.values():
            try:
                segment = segment_cls.load_from_config(hab_config, search_paths=search_paths)
                segments.append(segment)
            except SPSDKSegmentNotPresent:
                pass
        hab = cls(
            flags=hab_config.options.flags,
            ivt_offset=hab_config.options.get_ivt_offset(),
            start_address=hab_config.options.start_address,
            segments=segments,
        )
        hab.update_csf()
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
            [HabSegment.IVT, HabSegment.BDT],
            [HabSegment.DCD],
            [HabSegment.XMCD],
        ]
        for segments_names in segment_blocks:
            all_defined = all([self.get_segment(seg_name) for seg_name in segments_names])
            if all_defined:
                block_size = sum(
                    [
                        self.get_segment(seg_name).size  # type: ignore
                        for seg_name in segments_names
                        if self.segments.contains(seg_name)
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
            self.bdt_segment.segment.app_length += CsfHabSegment.KEYBLOB_SIZE
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
        """Create Binary image of HAB container.

        :return: BinaryImage object of HAB container.
        """
        bin_image = BinaryImage(
            name="HAB container",
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
    def parse(cls, data: bytes) -> Self:
        """Parse existing binary into HAB container object.

        :param data: Binary to be parsed
        """
        segments = HabSegments()
        for seg_class in SEGMENTS_MAPPING.values():
            try:
                segment = seg_class.parse(data)
                segments.append(segment)
            except SPSDKSegmentNotPresent:
                pass

        ivt = segments.get_segment(HabSegment.IVT)
        assert isinstance(ivt, IvtHabSegment)
        bdt = segments.get_segment(HabSegment.BDT)
        assert isinstance(bdt, BdtHabSegment)
        start_address = bdt.segment.app_start
        ivt_offset = ivt.segment.ivt_address - bdt.segment.app_start
        flags = cls._get_flags(segments)
        return cls(
            flags=flags, ivt_offset=ivt_offset, start_address=start_address, segments=segments
        )

    @staticmethod
    def _get_flags(segments: HabSegments) -> int:
        if not segments.contains(HabSegment.CSF):
            return 0x0
        csf = segments.get_segment(HabSegment.CSF)
        assert isinstance(csf, CsfHabSegment)
        decrypt = csf.get_decrypt_data_cmd()
        return 0xC if decrypt else 0x8

    def export_padding(self) -> bytes:
        """Get into binary including initial padding."""
        return self.image_info(padding=True).export()

    def export(self) -> bytes:
        """Export into binary."""
        return self.image_info(padding=False).export()

    def __len__(self) -> int:
        """Get length of HAB container."""
        last_offset = 0
        last_len = 0
        for seg in self.segments:
            if seg.offset > last_offset:
                last_offset = seg.offset
                last_len = seg.size
        return last_offset + last_len

    @classmethod
    def get_validation_schemas(cls, family: Optional[str] = None) -> list[dict[str, Any]]:
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
            sch_hab["properties"]["options"]["properties"]["bootDevice"]["enum"] = (
                cls.get_boot_devices(family)
            )
        schemas = [sch_hab]
        schemas.extend([hab_schema[x] for x in ["hab_input", "hab_sections"]])
        return schemas

    @classmethod
    def generate_config_template(cls, family: Optional[str] = None) -> str:
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
    def transform_bd_configuration(cls, config: dict[Any, Any]) -> dict[Any, Any]:
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

    @classmethod
    def load_configuration(
        cls,
        config_path: str,
        external_files: Optional[list[str]] = None,
        search_paths: Optional[list[str]] = None,
    ) -> dict:
        """Load the BD or YAML Configuration.

        :param config_path: Path to configuration file either BD or YAML formatted.
        :param external_files: Optional list of external files for BD processing
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Dictionary with parsed configuration.
        """
        try:
            # Load it first as BD
            parser = BDParser()
            bd_file_content = load_text(config_path, search_paths=search_paths)
            config_data = parser.parse(text=bd_file_content, extern=external_files)
            if config_data is None:
                raise SPSDKError("Invalid bd file, secure binary file generation terminated")
        except SPSDKError:
            # if loading as BD fails try it as YAML
            parsed_conf = load_configuration(config_path, search_paths=search_paths)
            schemas = cls.get_validation_schemas(family=parsed_conf["options"].get("family"))
            check_config(parsed_conf, schemas, search_paths=search_paths)
            config_data = cls.transform_bd_configuration(parsed_conf)
        return config_data

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get all supported families for HAB container.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.HAB)

    @staticmethod
    def get_boot_devices(family: str) -> list[str]:
        """Get all supported boot devices for given family.

        :param family: Target family name.
        :return: List of supported boot devices.
        """
        db = get_db(family)
        return list(db.get_dict(DatabaseManager.HAB, "mem_types").keys())
