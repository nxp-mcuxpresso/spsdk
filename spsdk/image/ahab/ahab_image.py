#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB image support.

This module provides functionality for creating, parsing, validating, and exporting AHAB
(Advanced High Assurance Boot) images used in NXP secure boot process. AHAB images consist
of multiple containers that include headers, image arrays, and digital signatures to ensure
secure boot functionality.

The module supports different container types (V1, V1forV2, V2) and various target memory
configurations. It enables operations such as adding containers, updating container fields,
verifying container configurations, and exporting complete AHAB images to binary format.

Additionally, it provides utilities for loading AHAB images from configurations, parsing
binary data into AHAB image objects, and generating validation schemas for configuration
validation.
"""

import logging
from copy import deepcopy
from typing import Any, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKLengthError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_container import AHABContainer, AHABContainerV1forV2, AHABContainerV2
from spsdk.image.ahab.ahab_data import (
    CONTAINER_ALIGNMENT,
    AHABSignHashAlgorithmV1,
    AHABSignHashAlgorithmV2,
    AHABTags,
    AhabTargetMemory,
    create_chip_config,
)
from spsdk.image.ahab.ahab_iae import ImageArrayEntryTemplates
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import BinaryPattern, align, load_binary
from spsdk.utils.spsdk_enum import SpsdkSoftEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class AHABImage(FeatureBaseClass):
    """Class representing an AHAB image.

    The image consists of multiple AHAB containers.
    """

    FEATURE = DatabaseManager.AHAB
    SUB_FEATURE = "ahab_image"

    def __init__(
        self,
        family: FamilyRevision,
        target_memory: str = AhabTargetMemory.TARGET_MEMORY_STANDARD.label,
        ahab_containers: Optional[list[Union[AHABContainer, AHABContainerV2]]] = None,
    ) -> None:
        """Initialize AHAB Image object.

        :param family: Name of device family.
        :param target_memory: Target memory for AHAB image [serial_downloader, standard, nand], defaults to "standard".
        :param ahab_containers: List of initial AHAB containers to include, defaults to None.
        :raises SPSDKValueError: Invalid input configuration.
        """
        self.chip_config = create_chip_config(family=family, target_memory=target_memory)
        self.ahab_containers: list[Union[AHABContainer, AHABContainerV2]] = ahab_containers or []
        self._container_type: Optional[
            Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]
        ] = None
        self.db = get_db(family)

    @property
    def family(self) -> FamilyRevision:
        """Just public family member."""
        return self.chip_config.family

    @family.setter
    def family(self, value: FamilyRevision) -> None:
        """Just public family member."""
        self.chip_config.family = value

    @property
    def container_type(
        self,
    ) -> Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]:
        """Get container class type.

        Determines the container type based on the first container in the list.
        If the container type is already set, returns the stored type.

        :raises SPSDKError: If there are no containers in the list.
        :return: The container class type.
        """
        if self._container_type is None:
            if len(self.ahab_containers) == 0:
                raise SPSDKError("Can't determine the AHAB Container type.")
            self._container_type = type(self.ahab_containers[0])
        return self._container_type

    @property
    def start_recommended_image_address(self) -> int:
        """Start recommended address for data images.

        :return: Start address for data images based on target memory type.
        :raises SPSDKError: If no containers are defined.
        """
        if len(self.ahab_containers) == 0:
            raise SPSDKError(
                "Cannot determine the Start data images address without defined container version."
            )
        return (
            self.ahab_containers[0].START_IMAGE_ADDRESS_NAND
            if self.chip_config.target_memory
            in [
                AhabTargetMemory.TARGET_MEMORY_NAND_2K.label,
                AhabTargetMemory.TARGET_MEMORY_NAND_4K.label,
            ]
            else self.ahab_containers[0].START_IMAGE_ADDRESS
        )

    @property
    def start_real_image_address(self) -> int:
        """Start data images address."""
        if len(self.ahab_containers) == 0:
            raise SPSDKError(
                "Cannot determine the Start data images address without defined container version."
            )
        all_offsets = [self.start_recommended_image_address] + [
            x.start_of_images for x in self.ahab_containers
        ]
        return align(min(all_offsets), CONTAINER_ALIGNMENT)

    def __repr__(self) -> str:
        return f"AHAB Image for {self.chip_config.family}"

    def __str__(self) -> str:
        return (
            "AHAB Image:\n"
            f"  Family:             {self.chip_config.family}\n"
            f"  Target memory:      {self.chip_config.target_memory.label}\n"
            f"  Max cont. count:    {self.chip_config.containers_max_cnt}"
            f"  Max image. count:   {self.chip_config.images_max_cnt}"
            f"  Containers count:   {len(self.ahab_containers)}"
        )

    def add_container(self, container: Union[AHABContainer, AHABContainerV2]) -> None:
        """Add new container into AHAB Image.

        Validates container compatibility before adding:
        - V2 containers can be mixed with V1forV2 containers
        - V1 containers must all be of the same type
        - Cannot mix V1 with V2/V1forV2 containers

        :param container: AHAB container to be added to the image.
        :raises SPSDKLengthError: If maximum container count is reached.
        :raises SPSDKError: If container type is incompatible with existing containers.
        """
        if len(self.ahab_containers) >= self.chip_config.containers_max_cnt:
            raise SPSDKLengthError(
                "Cannot add new container because the AHAB Image already reached"
                f" the maximum count: {self.chip_config.containers_max_cnt}"
            )

        # Handle V2 containers which can be mixed with V1forV2
        if isinstance(container, (AHABContainerV2, AHABContainerV1forV2)):
            if self._container_type and not isinstance(
                self._container_type, (AHABContainerV2, AHABContainerV1forV2)
            ):
                raise SPSDKError("Cannot mix V2/V1forV2 containers with V1 containers")
        # Handle V1 containers which must be same type
        elif len(self.ahab_containers) and not isinstance(container, type(self.ahab_containers[0])):
            raise SPSDKError("All V1 containers must be same type")

        self.ahab_containers.append(container)

    def clear(self) -> None:
        """Clear list of containers."""
        self.ahab_containers.clear()

    def update_fields(self, update_offsets: bool = True) -> None:
        """Automatically updates all volatile fields in every AHAB container.

        :param update_offsets: Update also offsets for serial_downloader.
        """
        for ahab_container in self.ahab_containers:
            ahab_container.update_fields()

        if update_offsets:
            # Update the Image offsets to be without gaps
            offset = self.start_recommended_image_address
            for ahab_container in self.ahab_containers:
                for image in ahab_container.image_array:
                    if ahab_container.chip_config.locked or image.image_offset > 0:
                        offset = image.image_offset
                    else:
                        image.image_offset = offset
                    offset = image.get_valid_offset(
                        offset + image.image_size + image.gap_after_image
                    )

                ahab_container.chip_config.locked = True

        # Sign the image header
        for ahab_container in self.ahab_containers:
            ahab_container.sign_itself()

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        :return: Size in Bytes of AHAB Image.
        """
        lengths = [0]
        for container in self.ahab_containers:
            lengths.extend([align(x.image_offset + x.image_size) for x in container.image_array])
        return align(
            max(lengths),
            (
                CONTAINER_ALIGNMENT
                if self.chip_config.target_memory
                == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER
                else self.chip_config.container_image_size_alignment
            ),
        )

    def export(self) -> bytes:
        """Export AHAB Image.

        :raises SPSDKValueError: mismatch between number of containers and offsets.
        :raises SPSDKValueError: number of images mismatch.
        :return: bytes AHAB  Image.
        """
        self.verify().validate()
        return self.image_info().export()

    def image_info(self) -> BinaryImage:
        """Get Image info object."""
        ret = BinaryImage(
            name="AHAB Image",
            size=len(self),
            alignment=(
                CONTAINER_ALIGNMENT
                if self.chip_config.target_memory
                == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER
                else self.chip_config.container_image_size_alignment
            ),
            offset=0,
            description=f"AHAB Image for {self.chip_config.family}",
            pattern=BinaryPattern("zeros"),
        )
        ahab_containers = BinaryImage(
            name="AHAB Containers",
            size=self.start_real_image_address,
            offset=0,
            description="AHAB Containers block",
            pattern=BinaryPattern("zeros"),
        )
        ret.add_image(ahab_containers)

        for cnt_ix, container in enumerate(self.ahab_containers):
            container_image = container.image_info()
            container_image.name = container_image.name + f" {cnt_ix}"
            container_image.offset = container.get_container_offset(cnt_ix)
            ahab_containers.add_image(container_image)

            # Add also all data images
            for img_ix, image_entry in enumerate(container.image_array):
                image_name = (
                    image_entry.image_name or f"Container {cnt_ix} AHAB Data Image {img_ix}"
                )
                data_image = BinaryImage(
                    name=image_name,
                    binary=image_entry.image,
                    size=image_entry.image_size,
                    offset=image_entry.image_offset,
                    description=(
                        f"AHAB {'encrypted ' if image_entry.flags_is_encrypted else ''}"
                        f"data block for {image_entry.flags_core_id_name} core "
                        f"and {image_entry.flags_image_type_name} Image Type."
                    ),
                )

                ret.add_image(data_image)

        return ret

    def verify(self) -> Verifier:
        """Perform comprehensive verification of the AHAB image.

        Validates multiple aspects of the AHAB image:
        - Container counts and offsets
        - Image counts per container
        - Image offsets and alignments
        - Serial downloader mode requirements
        - Checks for overlapping images

        The verification results are organized hierarchically in the returned Verifier object,
        including SUCCESS, WARNING, and ERROR status for each checked item.

        :return: Verifier object containing the detailed verification results.
        """

        def verify_container_offsets(container: AHABContainer) -> None:
            # Verify the container offset
            for ix, cnt in enumerate(self.ahab_containers):
                offset = container.get_container_offset(ix)
                if container == cnt:
                    ver_cnt.add_record(
                        "Container offset",
                        (
                            VerifierResult.ERROR
                            if container.chip_config.container_offset != offset
                            else VerifierResult.SUCCEEDED
                        ),
                        f"0x{container.chip_config.container_offset:04X}.",
                    )
                    break

        ret = Verifier("AHAB", description=str(self))

        ret.add_record_range(
            "Containers count",
            len(self.ahab_containers),
            max_val=self.chip_config.containers_max_cnt,
        )
        for container in self.ahab_containers:
            ver_cnt = container.verify()
            verify_container_offsets(container)
            ver_cnt.add_record_range(
                "Container image count",
                len(container.image_array),
                max_val=self.chip_config.images_max_cnt,
            )
            ret.add_child(ver_cnt)

        # Verify correct data image offsets
        offset = self.start_recommended_image_address
        alignment = self.ahab_containers[0].image_array[0].get_valid_alignment()
        ver_images = Verifier("Data images")
        for cnt_ix, container in enumerate(self.ahab_containers):
            for img_ix, image in enumerate(container.image_array):
                ver_img = Verifier(f"Data image{img_ix}")
                if image.image_offset < self.start_recommended_image_address:
                    ver_img.add_record(
                        "Minimal Offset",
                        VerifierResult.WARNING,
                        "The offset of data image (container"
                        f"{cnt_ix}/image{img_ix}) is under minimal allowed value."
                        f" {hex(image.image_offset)} < {hex(self.start_recommended_image_address)}",
                    )
                else:
                    ver_img.add_record(
                        "Minimal Offset",
                        VerifierResult.SUCCEEDED,
                        hex(image.image_offset),
                    )

                if image.image_offset != align(image.image_offset, alignment):
                    ver_img.add_record(
                        "Alignment",
                        VerifierResult.WARNING,
                        f"Invalid Image Offset alignment for target memory '{self.chip_config.target_memory.label}': "
                        f"{hex(image.image_offset)} "
                        f"should be with alignment {hex(alignment)}.",
                    )
                else:
                    ver_img.add_record("Alignment", VerifierResult.SUCCEEDED)

                if (
                    self.chip_config.target_memory
                    == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER
                ):
                    if offset != image.image_offset and not container.chip_config.locked:
                        ver_img.add_record(
                            "Serial Downloader mode offset",
                            VerifierResult.ERROR,
                            "Invalid image offset for Serial Downloader mode."
                            f"\n Expected {hex(offset)}, Used:{hex(image.image_offset)}",
                        )
                    else:
                        ver_img.add_record(
                            "Serial Downloader mode offset", VerifierResult.SUCCEEDED
                        )
                        offset = image.image_offset

                    offset = image.get_valid_offset(
                        offset + image.image_size + image.gap_after_image
                    )
                alignment = image.get_valid_alignment()
                ver_images.add_child(ver_img)

        ret.add_child(ver_images)

        # Validate also overlapped images
        try:
            self.image_info().validate()
        except SPSDKError:
            ver_images.add_record(
                "Image overlapping", VerifierResult.ERROR, self.image_info().draw(), raw=True
            )
        else:
            ver_images.add_record("Image overlapping", VerifierResult.SUCCEEDED)

        return ret

    def post_export(self, output_path: str) -> list[str]:
        """Write scripts for fuses.

        :param output_path: Path to store the data files of configuration.
        :return: List of generated files.
        """
        generated_files = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            generated_files.extend(container.post_export(output_path, cnt_ix))

        return generated_files

    @staticmethod
    def _parse_container_type(
        data: bytes,
    ) -> Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]:
        """Recognize container type from binary data.

        :param data: Binary data
        :raises SPSDKParsingError: In case of invalid data detected.
        :return: Container type
        """
        if not AHABContainer.check_container_head(data).has_errors:
            logger.debug("Detected AHAB container classic version in parsed data.")
            return AHABContainer
        if not AHABContainerV1forV2.check_container_head(data).has_errors:
            logger.debug(
                "Detected AHAB container classic version but with offsets for PQC version in parsed data."
            )
            return AHABContainerV1forV2
        if not AHABContainerV2.check_container_head(data).has_errors:
            logger.debug("Detected AHAB container PQC version in parsed data.")
            return AHABContainerV2

        raise SPSDKParsingError("Cannot determine the container type")

    def _container_type_from_config(
        self, config: Config
    ) -> Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]:
        """Recognize container type from config data.

        :param config: Configuration data
        :raises SPSDKParsingError: In case of invalid data detected.
        :return: Container type
        """
        cnt_types_dict = {1: AHABContainer, 2: AHABContainerV2}
        if len(self.chip_config.container_types) == 1:
            return cnt_types_dict[self.chip_config.container_types[0]]

        # There are two options !
        # try to check if exists forcing config
        force_type = config.get("container_version")
        if force_type:
            return cnt_types_dict[force_type]

        # Check if type is already set (by previous adding)
        if self._container_type:
            return self._container_type

        # If all other cases fails, just get the default (first in list)
        return cnt_types_dict[self.chip_config.container_types[0]]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an AHAB image object.

        "config" content array of containers configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :raises SPSDKValueError: if the count of AHAB containers is invalid.
        :raises SPSDKParsingError: Cannot parse input binary AHAB container.
        :return: Initialized AHAB Image.
        """
        containers_config = config.get_list_of_configs("containers")
        family = FamilyRevision.load_from_config(config)
        target_memory = config.get_str("target_memory", "standard")
        ahab = cls(family=family, target_memory=target_memory)
        i = 0
        for container_config in containers_config:
            if "binary_container" in container_config:
                binary_container = container_config.get_config("binary_container")
                ahab_bin = load_binary(binary_container.get_input_file_name("path"))
                # Get container type of first container
                base_container_type = container_type = cls._parse_container_type(ahab_bin)
                for j in range(ahab.chip_config.containers_max_cnt):
                    try:
                        container_data = ahab_bin[container_type.get_container_offset(i) :]
                        if base_container_type == AHABContainerV2:
                            container_type = cls._parse_container_type(container_data)
                        ahab.add_container(
                            container_type.parse(
                                ahab_bin,
                                chip_config=ahab.chip_config,
                                offset=container_type.get_container_offset(i),
                            )
                        )
                        i += 1
                    except SPSDKError as exc:
                        if j == 0:
                            raise SPSDKParsingError(
                                f"AHAB Binary Container parsing failed. ({str(exc)})"
                            ) from exc
                        break

            else:
                container_type = ahab._container_type_from_config(config)
                ahab.add_container(
                    container_type.load_from_config(
                        ahab.chip_config, container_config.get_config("container"), i
                    )
                )
                i += 1

        return ahab

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: Optional[FamilyRevision] = None,
        target_memory: str = AhabTargetMemory.TARGET_MEMORY_STANDARD.label,
    ) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data to parse
        :param family: The MCU family
        :param target_memory: AHAB container target memory.

        :raises SPSDKError: No AHAB container found in binary data.
        """
        if family is None:
            raise SPSDKValueError("Missing family parameter to parse AHAB")
        ret = cls(family=family, target_memory=target_memory)
        # Get container type of first container, rest should be same
        base_container_type = container_type = ret._parse_container_type(data)
        for i in range(ret.chip_config.containers_max_cnt):
            try:
                container_data = data[container_type.get_container_offset(i) :]
                if base_container_type == AHABContainerV2 and container_data[3] in [
                    AHABTags.CONTAINER_HEADER.tag,
                    AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag,
                ]:
                    container_type = ret._parse_container_type(container_data)
                ver_header = container_type.check_container_head(container_data)
                if not ver_header.has_errors:
                    container = container_type.parse(
                        data,
                        chip_config=ret.chip_config,
                        offset=container_type.get_container_offset(i),
                    )
                    ret.ahab_containers.append(container)
            except SPSDKError as exc:
                logger.debug(f"AHAB Container parsing index {i} failed: {str(exc)}")
                if not ver_header.has_errors:
                    pre_ver = container_type.pre_parse_verify(
                        data[container_type.get_container_offset(i) :]
                    )
                    raise SPSDKError(
                        f"AHAB Container parsing failed on container on index: {i}. \nException: \n{str(exc)}. "
                        f"\nThe pre-parse verify reason: \n{pre_ver.draw()}"
                    ) from exc
        if len(ret.ahab_containers) == 0:
            raise SPSDKError("No AHAB Container has been found in binary data.")

        return ret

    @staticmethod
    def pre_parse_verify(data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB Image.

        This method performs a preliminary validation of binary data to determine if it appears
        to be a valid AHAB Image. It tries to identify the container type (V1, V1forV2, or V2)
        and then checks for the presence of valid containers at expected offsets.

        Unlike full parsing, this method only examines container headers without processing
        the entire content, making it faster for initial validation before committing to more
        resource-intensive operations.

        The returned Verifier object contains hierarchical validation results for each detected
        container, including information about detected errors or warnings.

        :param data: Binary data with AHAB Image to pre-parse.
        :return: Verifier object containing validation results of the pre-parsed binary data.
        """
        ret = Verifier("Pre-parsed AHAB Image")

        try:
            base_container_type = container_type = AHABImage._parse_container_type(data)
        except SPSDKError:
            ret.add_record("Container 0", VerifierResult.ERROR, "Not detected in data")
            return ret

        for i, address in enumerate(
            range(0, container_type.CONTAINER_SIZE * 4, container_type.CONTAINER_SIZE)
        ):
            container_data = data[container_type.get_container_offset(i) :]
            if base_container_type == AHABContainerV2 and container_data[3] in [
                AHABTags.CONTAINER_HEADER.tag,
                AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag,
            ]:
                container_type = AHABImage._parse_container_type(container_data)
            ver_just_container = container_type.check_container_head(data[address:])
            if i == 0 or not ver_just_container.has_errors:
                ret.add_child(
                    container_type.pre_parse_verify(data[address:]), f"Container at {hex(address)}"
                )
            else:
                break
        return ret

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: Validation list of schemas.
        """
        db = get_db(family)
        extra_images = db.get_list(DatabaseManager.AHAB, "extra_images", [])
        container_type = db.get_list(DatabaseManager.AHAB, "container_types", [])
        certificate_supported = "certificate_supported" in db.get_list(
            DatabaseManager.AHAB, "sub_features", []
        )
        hide_force_container_type = len(container_type) <= 1
        container_type_2 = 2 in container_type
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", db.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        db_image_types = db.get_dict(DatabaseManager.AHAB, "image_types")
        image_types = []
        for v in db_image_types.values():
            for v1 in v.values():
                image_types.append(v1[1])

        sch_family = get_schema_file("general")
        sch = get_schema_file(DatabaseManager.AHAB)
        update_validation_schema_family(
            sch_family["family"]["properties"], AHABImage.get_supported_families(), family
        )
        sch["whole_ahab_image"]["properties"]["container_version"][
            "skip_in_template"
        ] = hide_force_container_type
        sch_cnt: dict[str, Any] = sch["whole_ahab_image"]["properties"]["containers"]["items"][
            "oneOf"
        ][1]["properties"]["container"]["properties"]
        if not certificate_supported:
            sch_cnt.pop("certificate")
        if container_type_2:
            sch_cnt["check_all_signatures"]["skip_in_template"] = False
            sch_cnt["fast_boot"]["skip_in_template"] = False
            sch_cnt["srk_table"]["properties"]["srk_table_#2"]["skip_in_template"] = False
            sch_cnt["signer_#2"]["skip_in_template"] = False

        images = sch["whole_ahab_image"]["properties"]["containers"]["items"]["oneOf"][1][
            "properties"
        ]["container"]["properties"]["images"]["items"].pop("oneOf")

        # Find general image tak the content and optionally add it to each extension without binary_image
        std_properties = {}
        for image in images:
            if "general_image" == image["image_identifier"]:
                image["properties"]["core_id"]["enum"] = core_ids.labels()
                image["properties"]["image_type"]["enum"] = image_types
                image["properties"]["hash_type"]["enum"] = [
                    x.lower()
                    for x in (
                        AHABSignHashAlgorithmV2.labels()
                        if container_type_2
                        else AHABSignHashAlgorithmV1.labels()
                    )
                ]
                org_std_properties: dict[str, Any] = deepcopy(image)
                break

        # Take standard properties to use them as hidden in all IAE templates
        std_properties = deepcopy(org_std_properties["properties"])
        std_properties.pop("image_path")
        for p in std_properties.values():
            p["skip_in_template"] = True

        iae_classes = ImageArrayEntryTemplates.__subclasses__()

        result_images = []
        for extra_image in extra_images:
            defaults_description = ""
            for template_class in iae_classes:
                if template_class.KEY == extra_image:
                    defaults_description = "\n" + template_class.get_default_setting_description(
                        family
                    )
                    break

            for image in images:
                if extra_image == image["image_identifier"]:
                    image["skip_in_template"] = False
                    image["properties"].update(std_properties)
                    image["description"] = image["description"] + defaults_description
                    result_images.append(image)
                    break
        result_images.append(org_std_properties)

        sch["whole_ahab_image"]["properties"]["containers"]["items"]["oneOf"][1]["properties"][
            "container"
        ]["properties"]["images"]["items"]["oneOf"] = result_images

        return [sch_family["family"], sch["whole_ahab_image"]]

    @staticmethod
    def get_signing_validation_schemas(family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for signing the container.

        :param family: Family for which the validation schema should be generated.
        :return: list of schemas for signing the container.
        """
        schemas = AHABImage.get_validation_schemas(family)
        # Remove images property from the container
        schemas[1]["properties"]["containers"]["items"]["oneOf"][1]["properties"]["container"][
            "properties"
        ].pop("images")
        # Required is just srk_set, remove images
        schemas[1]["properties"]["containers"]["items"]["oneOf"][1]["properties"]["container"][
            "required"
        ] = ["srk_set"]
        return [
            schemas[0],
            schemas[1]["properties"]["containers"]["items"]["oneOf"][1]["properties"]["container"],
        ]

    @classmethod
    def get_signing_template(cls, family: FamilyRevision) -> str:
        """Get AHAB configuration template for signing the containers.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        schemas = AHABImage.get_signing_validation_schemas(family)
        return cls._get_config_template(family, schemas)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the AHAB Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.c
        """
        cfg = Config()
        cfg["family"] = self.chip_config.family.name
        cfg["revision"] = self.chip_config.family.revision
        cfg["target_memory"] = self.chip_config.target_memory.label
        cfg["output"] = "N/A"
        cfg_containers = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            cfg_containers.append(container.get_config(data_path, cnt_ix))
        cfg["containers"] = cfg_containers

        return cfg

    @staticmethod
    def find_offset_of_ahab(binary: bytes, do_detail_search: bool = False) -> int:
        """Try to find the start of the AHAB Image in data blob.

        :param binary: Data  to be used to find AHAB container.
        :param do_detail_search: Do also the detail search (slow, by precise).
        :return: Offset in data to new data container.
        """

        class DummyContainer(HeaderContainer):
            """Dummy container class to use fast checking the base format."""

            VERSION = [0, 2]
            TAG = AHABTags.CONTAINER_HEADER.tag

        logger.debug("Trying to find AHAB container on every 0x400 bytes")
        for offset in range(0, len(binary), 0x400):
            if not DummyContainer.check_container_head(binary[offset:]).has_errors:
                return offset

        if do_detail_search:
            logger.debug("Trying to find AHAB container on every 4 bytes")
            for offset in range(0, len(binary), 4):
                if not DummyContainer.check_container_head(binary[offset:]).has_errors:
                    return offset
        raise SPSDKError("The AHAB container has not been found in given binary data")
