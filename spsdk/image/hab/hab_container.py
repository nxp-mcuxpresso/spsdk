#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains HAB related code."""

import logging
import os
from typing import Any, Dict, List, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image import IMG_DATA_FOLDER, segments
from spsdk.image.hab.config_parser import ImageConfig
from spsdk.image.hab.csf_builder import CsfBuildDirector, CsfBuilder
from spsdk.image.hab.hab_binary_image import HabBinaryImage, HabSegment
from spsdk.image.images import BootImgRT
from spsdk.sbfile.sb2.sly_bd_parser import BDParser
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import load_binary, load_configuration, load_text
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas, check_config

HAB_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "sch_hab.yaml")


logger = logging.getLogger(__name__)


class HabContainer:
    """Hab container."""

    IVT_VERSION = 0x40

    def __init__(self, hab_image: HabBinaryImage) -> None:
        """HAB Constructor.

        :param binary_image: Binary image with required segments.
        """
        self.hab_image = hab_image

    @property
    def ivt_segment(self) -> Optional[bytes]:
        """IVT segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.IVT)
        return segment.binary if segment else None

    @property
    def bdt_segment(self) -> Optional[bytes]:
        """BDT segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.BDT)
        return segment.binary if segment else None

    @property
    def dcd_segment(self) -> Optional[bytes]:
        """DCD segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.DCD)
        return segment.binary if segment else None

    @property
    def xmcd_segment(self) -> Optional[bytes]:
        """XMCD segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.XMCD)
        return segment.binary if segment else None

    @property
    def app_segment(self) -> Optional[bytes]:
        """APP segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.APP)
        return segment.binary if segment else None

    @property
    def csf_segment(self) -> Optional[bytes]:
        """APP segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.CSF)
        return segment.binary if segment else None

    @classmethod
    def load_from_config(
        cls,
        config: Dict[str, Any],
        search_paths: Optional[List[str]] = None,
    ) -> Self:
        """Load the HAB container object from parsed bd_data configuration.

        :param config: Image configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        image_config = ImageConfig.parse(config)
        timestamp = image_config.options.signature_timestamp
        hab_image = HabBinaryImage()
        # IVT
        ivt = segments.SegIVT2(HabContainer.IVT_VERSION)
        ivt.app_address = image_config.options.entrypoint_address
        ivt.ivt_address = image_config.options.start_address + image_config.options.ivt_offset
        ivt.bdt_address = ivt.ivt_address + ivt.size
        ivt.csf_address = 0
        hab_image.add_hab_segment(HabSegment.IVT, ivt.export())
        ivt_image = hab_image.get_hab_segment(HabSegment.IVT)
        # BDT
        bdt = segments.SegBDT(app_start=image_config.options.start_address)
        hab_image.add_hab_segment(HabSegment.BDT, bdt.export())
        # DCD
        if image_config.options.dcd_file_path is not None:
            dcd_bin = load_binary(image_config.options.dcd_file_path, search_paths=search_paths)
            hab_image.add_hab_segment(HabSegment.DCD, dcd_bin)
            ivt.dcd_address = ivt.ivt_address + HabBinaryImage.DCD_OFFSET
            ivt_image.binary = ivt.export()
        # XMCD
        if image_config.options.xmcd_file_path is not None:
            xmcd_bin = load_binary(image_config.options.xmcd_file_path, search_paths=search_paths)
            hab_image.add_hab_segment(HabSegment.XMCD, xmcd_bin)
        # APP
        app_bin = BinaryImage.load_binary_image(
            image_config.elf_file,
            search_paths=search_paths,
        )
        app_offset = image_config.options.initial_load_size - image_config.options.ivt_offset
        hab_image.add_hab_segment(HabSegment.APP, app_bin.export(), offset_override=app_offset)

        bdt.app_length = image_config.options.ivt_offset + len(hab_image)
        bdt_image = hab_image.get_hab_segment(HabSegment.BDT)
        bdt_image.binary = bdt.export()
        # Calculate CSF offset
        app_image = hab_image.get_hab_segment(HabSegment.APP)
        image_len = app_offset + len(app_image) + image_config.options.ivt_offset
        csf_offset = HabContainer._calculate_csf_offset(image_len)
        csf_offset = csf_offset - image_config.options.ivt_offset

        csf_builder = CsfBuilder(
            image_config,
            csf_offset=csf_offset,
            search_paths=search_paths,
            timestamp=timestamp,
            hab_image=hab_image,
        )
        if csf_builder.is_authenticated or csf_builder.is_encrypted:
            bdt.app_length = image_config.options.ivt_offset + csf_offset + HabBinaryImage.CSF_SIZE
            if csf_builder.is_encrypted:
                bdt.app_length += HabBinaryImage.KEYBLOB_SIZE
            bdt_image.binary = bdt.export()
            ivt.csf_address = ivt.ivt_address + csf_offset
            ivt_image.binary = ivt.export()
        # CSF
        director = CsfBuildDirector(csf_builder)
        director.build_csf()
        return cls(hab_image=hab_image)

    @staticmethod
    def _calculate_csf_offset(image_len: int) -> int:
        """Calculate CSF offset from image length.

        :param image_len: Image length
        :return: CSF offset
        """
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000
        return csf_offset

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse existing binary into HAB container object.

        :param data: Binary to be parsed
        """
        rt_img = BootImgRT.parse(data)
        # IVT
        hab_image = HabBinaryImage()
        hab_image.add_hab_segment(HabSegment.IVT, rt_img.ivt.export())
        # BDT
        if rt_img.bdt is not None:
            hab_image.add_hab_segment(HabSegment.BDT, rt_img.bdt.export())
        # DCD
        if rt_img.dcd is not None:
            hab_image.add_hab_segment(HabSegment.DCD, rt_img.dcd.export())
        # XMCD
        if rt_img.xmcd is not None:
            hab_image.add_hab_segment(HabSegment.XMCD, rt_img.xmcd.export())
        # CSF
        if rt_img.csf is not None:
            hab_image.add_hab_segment(
                HabSegment.CSF,
                rt_img.csf.export(),
                offset_override=rt_img.ivt.csf_address - rt_img.ivt.ivt_address,
            )
        # APP
        if rt_img.app is not None:
            hab_image.add_hab_segment(
                HabSegment.APP,
                rt_img.app.export(),
                offset_override=rt_img.app_offset - rt_img.ivt_offset,
            )
        return cls(hab_image)

    def export(self) -> bytes:
        """Export into binary."""
        return self.hab_image.export()

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        hab_schema = ValidationSchemas.get_schema_file(HAB_SCH_FILE)

        schemas: List[Dict[str, Any]] = []
        schemas.extend([hab_schema[x] for x in ["hab_input", "hab"]])
        schemas = [hab_schema[x] for x in ["hab_input", "hab", "hab_sections"]]
        return schemas

    @classmethod
    def generate_config_template(cls) -> str:
        """Generate configuration template.

        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        return CommentedConfig(
            "HAB Configuration template.",
            cls.get_validation_schemas(),
        ).export_to_yaml()

    @classmethod
    def transform_configuration(cls, config: Dict[Any, Any]) -> Dict[Any, Any]:
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
        for section in config["sections"]:
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
    def transform_bd_configuration(cls, config: Dict[Any, Any]) -> Dict[Any, Any]:
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
        for section in config["sections"]:
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
        external_files: Optional[List[str]] = None,
        search_paths: Optional[List[str]] = None,
    ) -> Dict:
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
            schemas = cls.get_validation_schemas()
            check_config(parsed_conf, schemas, search_paths=search_paths)
            config_data = cls.transform_bd_configuration(parsed_conf)
        return config_data
