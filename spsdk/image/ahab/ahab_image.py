#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK AHAB (Advanced High Assurance Boot) image management utilities.

This module provides functionality for creating, parsing, validating, and exporting AHAB
images used in NXP secure boot process. AHAB images consist of multiple containers that
include headers, image arrays, and digital signatures to ensure secure boot functionality.
The module supports different container types and various target memory configurations,
enabling operations such as adding containers, updating container fields, verifying
configurations, and exporting complete AHAB images to binary format.
"""

import logging
from copy import deepcopy
from typing import Any, Optional, Type, Union

from prettytable import PrettyTable
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
    """AHAB Image representation for secure boot operations.

    This class manages AHAB (Advanced High Assurance Boot) images consisting of
    multiple AHAB containers. It provides functionality for creating, configuring,
    and manipulating secure boot images for NXP MCU devices with support for
    different target memory types and container versions.

    :cvar FEATURE: Database feature identifier for AHAB operations.
    :cvar SUB_FEATURE: Sub-feature identifier for AHAB image operations.
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

        Creates a new AHAB (Advanced High Assurance Boot) image instance with the specified
        device family configuration and optional containers.

        :param family: Device family and revision specification.
        :param target_memory: Target memory type for AHAB image deployment, options include
            serial_downloader, standard, or nand, defaults to "standard".
        :param ahab_containers: List of AHAB containers to initialize the image with,
            defaults to None.
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
        """Get the family revision information.

        Returns the family revision configuration from the chip configuration.

        :return: Family revision information for the AHAB image.
        """
        return self.chip_config.family

    @family.setter
    def family(self, value: FamilyRevision) -> None:
        """Set the family revision for the chip configuration.

        :param value: The family revision to set for the chip configuration.
        """
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
        """Get the recommended start address for data images.

        The method determines the appropriate start address based on the target memory type,
        using different addresses for NAND memory types versus other memory types.

        :return: Start address for data images based on target memory type.
        :raises SPSDKError: If no containers are defined.
        """
        if len(self.ahab_containers) == 0:
            raise SPSDKError(
                "Cannot determine the Start data images address without defined container version."
            )
        return (
            self.ahab_containers[0].START_IMAGE_ADDRESS_NAND
            if self.chip_config.target_memory.is_nand
            else self.ahab_containers[0].START_IMAGE_ADDRESS
        )

    @property
    def start_real_image_address(self) -> int:
        """Get the start address for real data images.

        Calculates the minimum aligned address where data images should start based on
        the recommended image address and container image start addresses. The address
        is aligned to container alignment requirements.

        :raises SPSDKError: When no AHAB containers are defined and container version
            cannot be determined.
        :return: Aligned start address for data images.
        """
        if len(self.ahab_containers) == 0:
            raise SPSDKError(
                "Cannot determine the Start data images address without defined container version."
            )
        all_offsets = [self.start_recommended_image_address] + [
            x.start_of_images for x in self.ahab_containers
        ]
        return align(min(all_offsets), CONTAINER_ALIGNMENT)

    def __repr__(self) -> str:
        """Return string representation of AHAB Image.

        :return: String representation containing the chip family name.
        """
        return f"AHAB Image for {self.chip_config.family}"

    def __str__(self) -> str:
        """Get string representation of AHAB Image.

        Provides a formatted string containing key information about the AHAB image
        including chip family, target memory, container limits, and current container count.

        :return: Formatted string with AHAB image details.
        """
        return (
            "AHAB Image:\n"
            f"  Family:             {self.chip_config.family}\n"
            f"  Target memory:      {self.chip_config.target_memory.memory_type.label}\n"
            f"  Max cont. count:    {self.chip_config.containers_max_cnt}"
            f"  Max image. count:   {self.chip_config.images_max_cnt}"
            f"  Containers count:   {len(self.ahab_containers)}"
        )

    def add_container(self, container: Union[AHABContainer, AHABContainerV2]) -> None:
        """Add new container into AHAB Image.

        The method validates container count limits, type compatibility, and family support.
        V2 and V1forV2 containers can be mixed together, but V1 containers must all be the same type.

        :param container: AHAB container to be added to the image.
        :raises SPSDKLengthError: If maximum container count is reached.
        :raises SPSDKError: If container type is incompatible with existing containers.
        :raises SPSDKValueError: If container type is not supported by the family.
        """
        if len(self.ahab_containers) >= self.chip_config.containers_max_cnt:
            raise SPSDKLengthError(
                "Cannot add new container because the AHAB Image already reached"
                f" the maximum count: {self.chip_config.containers_max_cnt}"
            )

        # ADD THIS VALIDATION:
        self._validate_container_type_support(type(container))

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
        """Clear the list of AHAB containers.

        This method removes all containers from the ahab_containers list, effectively
        resetting the image to an empty state.
        """
        self.ahab_containers.clear()

    def update_fields(self, update_offsets: bool = True) -> None:
        """Update all volatile fields in AHAB containers and optionally adjust image offsets.

        This method updates volatile fields in all AHAB containers and can optionally update
        image offsets for serial downloader mode. When updating offsets, it eliminates gaps
        between images while respecting locked configurations and existing non-zero offsets.
        The method also signs all container headers after updates.

        :param update_offsets: If True, updates image offsets to eliminate gaps and logs
            the changes in a detailed table format.
        """
        for ahab_container in self.ahab_containers:
            ahab_container.update_fields()
            if update_offsets:
                # Update the Image offsets to be without gaps
                offset = self.start_recommended_image_address

                # Collect offset update information for logging
                offset_updates = []
                for container_idx, ahab_container in enumerate(self.ahab_containers):
                    for image_idx, image in enumerate(ahab_container.image_array):
                        old_offset = image.image_offset
                        offset_changed = False
                        if ahab_container.chip_config.locked or image.image_offset > 0:
                            offset = image.image_offset
                            action = "PRESERVED" if image.image_offset > 0 else "LOCKED"
                        else:
                            image.image_offset = offset
                            offset_changed = True
                            action = "UPDATED"

                        # Store information for logging
                        offset_updates.append(
                            {
                                "container": container_idx,
                                "image": image_idx,
                                "old_offset": old_offset,
                                "new_offset": image.image_offset,
                                "size": image.image_size,
                                "gap": image.gap_after_image,
                                "action": action,
                                "changed": offset_changed,
                            }
                        )

                        offset = image.get_valid_offset(
                            offset + image.image_size + image.gap_after_image
                        )

                    ahab_container.chip_config.locked = True
                # Log the offset updates table if any changes were made
                if any(update["changed"] for update in offset_updates):
                    logger.info("AHAB Image Offset has been updated in serial downloader mode.")

                    table = PrettyTable()
                    table.field_names = [
                        "Container",
                        "Image",
                        "Old Offset",
                        "New Offset",
                        "Image Size",
                        "Gap After",
                        "Action",
                    ]

                    for update in offset_updates:
                        table.add_row(
                            [
                                update["container"],
                                update["image"],
                                f"0x{update['old_offset']:X}",
                                f"0x{update['new_offset']:X}",
                                f"0x{update['size']:X}",
                                f"0x{update['gap']:X}",
                                update["action"],
                            ]
                        )

                    logger.info("AHAB Image Offset Updates:")
                    for line in str(table).split("\n"):
                        logger.info(line)

                    # Summary information
                    updated_count = sum(1 for update in offset_updates if update["changed"])
                    preserved_count = sum(
                        1 for update in offset_updates if update["action"] == "PRESERVED"
                    )
                    locked_count = sum(
                        1 for update in offset_updates if update["action"] == "LOCKED"
                    )

                    logger.info(
                        f"Summary: {updated_count} updated, {preserved_count} preserved, {locked_count} locked"
                    )
        # Sign the image header
        for ahab_container in self.ahab_containers:
            ahab_container.sign_itself()

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        The method calculates the maximum size by examining all containers and their image arrays,
        finding the largest aligned offset plus image size, and then aligning the result based on
        the target memory type configuration.

        :return: Size in bytes of AHAB Image.
        """
        lengths = [0]
        for container in self.ahab_containers:
            lengths.extend([x.image_offset + x.image_size for x in container.image_array])
        return max(lengths)

    def export(self) -> bytes:
        """Export AHAB Image to binary format.

        :raises SPSDKValueError: Mismatch between number of containers and offsets.
        :raises SPSDKValueError: Number of images mismatch.
        :return: Binary representation of AHAB Image.
        """
        return self.image_info().export()

    def image_info(self) -> BinaryImage:
        """Get AHAB image information as a structured binary image object.

        Creates a hierarchical BinaryImage structure containing the complete AHAB image layout,
        including all containers and their associated data images with proper offsets and metadata.

        :return: Binary image object with complete AHAB image structure and layout information.
        """
        ret = BinaryImage(
            name="AHAB Image",
            size=len(self),
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

        Validates multiple aspects of the AHAB image including container counts and offsets,
        image counts per container, image offsets and alignments, serial downloader mode
        requirements, and checks for overlapping images. The verification results are
        organized hierarchically in the returned Verifier object, including SUCCESS,
        WARNING, and ERROR status for each checked item.

        :return: Verifier object containing the detailed verification results.
        """

        def verify_container_offsets(container: AHABContainer) -> None:
            """Verify container offsets against expected values.

            Validates that the container offset stored in the chip configuration matches
            the calculated offset based on the container's position in the AHAB containers list.

            :param container: AHAB container to verify offsets for.
            """
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
                        "Invalid Image Offset alignment for target memory "
                        f"'{self.chip_config.target_memory.memory_type.label}': "
                        f"{hex(image.image_offset)} "
                        f"should be with alignment {hex(alignment)}.",
                    )
                else:
                    ver_img.add_record("Alignment", VerifierResult.SUCCEEDED)

                if self.chip_config.target_memory.force_no_gaps:
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
        """Write scripts for fuses after image export.

        The method processes all AHAB containers and generates their post-export files,
        typically fuse scripts and configuration data files.

        :param output_path: Path to store the data files of configuration.
        :return: List of generated files.
        """
        generated_files = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            generated_files.extend(container.post_export(output_path, cnt_ix))

        return generated_files

    @staticmethod
    def _parse_container_type(
        data: bytes, ignore_length: bool = False
    ) -> Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]:
        """Recognize container type from binary data.

        Analyzes the provided binary data to determine which AHAB container type
        it represents by checking container headers against known formats.

        :param data: Binary data containing AHAB container information.
        :raises SPSDKParsingError: In case of invalid data detected.
        :return: Container class type (AHABContainer, AHABContainerV1forV2, or AHABContainerV2).
        """
        if not AHABContainer.check_container_head(data, ignore_length=ignore_length).has_errors:
            logger.debug("Detected AHAB container classic version in parsed data.")
            return AHABContainer
        if not AHABContainerV1forV2.check_container_head(
            data, ignore_length=ignore_length
        ).has_errors:
            logger.debug(
                "Detected AHAB container classic version but with offsets for PQC version in parsed data."
            )
            return AHABContainerV1forV2
        if not AHABContainerV2.check_container_head(data, ignore_length=ignore_length).has_errors:
            logger.debug("Detected AHAB container PQC version in parsed data.")
            return AHABContainerV2

        raise SPSDKParsingError("Cannot determine the container type")

    def _container_type_from_config(
        self, config: Config
    ) -> Union[Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]]:
        """Recognize container type from configuration data.

        The method determines the appropriate AHAB container type based on chip configuration,
        forced container version from config, or previously set container type. Falls back to
        the default container type if no specific type is determined.

        :param config: Configuration data containing container settings.
        :raises SPSDKParsingError: In case of invalid data detected.
        :return: Container class type (AHABContainer, AHABContainerV1forV2, or AHABContainerV2).
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
        """Create AHAB image object from configuration.

        Converts the configuration containing array of containers configurations into
        an initialized AHAB image object. Supports both binary containers and
        configuration-based containers.

        :param config: Configuration object containing AHAB containers setup.
        :raises SPSDKValueError: If the count of AHAB containers is invalid.
        :raises SPSDKParsingError: Cannot parse input binary AHAB container.
        :return: Initialized AHAB Image object.
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

        This method analyzes binary data to extract AHAB containers, validates container types
        against family support, and creates a parsed container object with all found containers.

        :param data: Binary data to parse into AHAB containers.
        :param family: The MCU family revision for validation and configuration.
        :param target_memory: AHAB container target memory type.
        :raises SPSDKError: No AHAB container found in binary data or container parsing failed.
        :raises SPSDKValueError: Missing family parameter or family doesn't support detected
            container type.
        :return: Parsed AHAB image object containing all found containers.
        """
        if family is None:
            raise SPSDKValueError("Missing family parameter to parse AHAB")
        ret = cls(family=family, target_memory=target_memory)
        # Get container type of first container, rest should be same
        base_container_type = container_type = ret._parse_container_type(data)

        if family:
            # Check if the detected container type is supported by the family
            detected_version = 2 if base_container_type == AHABContainerV2 else 1
            supported_versions = ret.chip_config.container_types

            if detected_version not in supported_versions:
                supported_str = ", ".join([f"V{v}" for v in supported_versions])
                error_msg = (
                    f"Family '{family}' does not support container type V{detected_version}. "
                    f"Supported types: {supported_str}"
                )
                logger.error(error_msg)
                raise SPSDKValueError(error_msg)

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
            except (SPSDKError, IndexError) as exc:
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
        """Pre-parse verify of AHAB Image.

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
    def get_image_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of image validation schemas for AHAB container images.

        This method retrieves and processes validation schemas for different types of AHAB container
        images based on the specified family. It combines general image properties with family-specific
        configurations, including core IDs, image types, and hash algorithms. The method also
        incorporates extra image templates and their default settings.

        :param family: Family revision for which the validation schema should be generated.
        :return: List of dictionaries containing image validation schemas with processed properties
                 and templates.
        """
        db = get_db(family)
        container_type = db.get_list(DatabaseManager.AHAB, "container_types", [])
        container_type_2 = 2 in container_type
        extra_images = db.get_list(DatabaseManager.AHAB, "extra_images", [])
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", db.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        db_image_types = db.get_dict(DatabaseManager.AHAB, "image_types")
        image_types = []
        for v in db_image_types.values():
            for v1 in v.values():
                image_types.append(v1[1])

        sch = get_schema_file(DatabaseManager.AHAB)
        images = sch["whole_ahab_image"]["properties"]["containers"]["items"]["oneOf"][1][
            "properties"
        ]["container"]["properties"]["images"]["items"].pop("oneOf")

        # Find general image take the content and optionally add it to each extension without binary_image
        std_properties = {}
        for image in images:
            if "general_image" == image["image_identifier"]:
                image["properties"]["core_id"]["enum"] = core_ids.labels()
                image["properties"]["core_id"]["template_value"] = core_ids.labels()[0]
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

        return result_images

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for AHAB image configuration.

        This method generates validation schemas based on the specified family's capabilities,
        including container types, certificate support, and image-specific schemas. The schemas
        are used to validate AHAB image configuration files.

        :param family: Family revision for which the validation schema should be generated.
        :return: List containing family and AHAB image validation schemas.
        """
        db = get_db(family)
        container_type = db.get_list(DatabaseManager.AHAB, "container_types", [])
        certificate_supported = "certificate_supported" in db.get_list(
            DatabaseManager.AHAB, "sub_features", []
        )
        hide_force_container_type = len(container_type) <= 1
        container_type_2 = 2 in container_type

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

        # Get image schemas using the extracted function
        result_images = cls.get_image_schemas(family)

        # Update the container schema with the image schemas
        sch["whole_ahab_image"]["properties"]["containers"]["items"]["oneOf"][1]["properties"][
            "container"
        ]["properties"]["images"]["items"]["oneOf"] = result_images

        return [sch_family["family"], sch["whole_ahab_image"]]

    @staticmethod
    def get_signing_validation_schemas(family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for signing the container.

        This method retrieves validation schemas specifically configured for container signing
        by removing image-related properties and requirements from the base validation schemas.

        :param family: Family for which the validation schema should be generated.
        :return: List of schemas for signing the container.
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
        :return: AHAB configuration template as a string.
        """
        schemas = AHABImage.get_signing_validation_schemas(family)
        return cls._get_config_template(family, schemas)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the AHAB Image.

        The method generates a configuration dictionary containing family information, target memory
        settings, and container configurations for the AHAB image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with AHAB image settings.
        """
        cfg = Config()
        cfg["family"] = self.chip_config.family.name
        cfg["revision"] = self.chip_config.family.revision
        cfg["target_memory"] = self.chip_config.target_memory.memory_type.label
        cfg["output"] = "N/A"
        cfg_containers = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            cfg_containers.append(container.get_config(data_path, cnt_ix))
        cfg["containers"] = cfg_containers

        return cfg

    @staticmethod
    def find_offset_of_ahab(binary: bytes, do_detail_search: bool = False) -> int:
        """Find the start of the AHAB Image in binary data.

        Searches for AHAB container header by checking data at regular intervals.
        First performs a fast search every 0x400 bytes, then optionally does a
        detailed search every 4 bytes if enabled.

        :param binary: Binary data to search for AHAB container.
        :param do_detail_search: Enable detailed search every 4 bytes (slower but more precise).
        :return: Offset in binary data where AHAB container starts.
        :raises SPSDKError: AHAB container not found in the provided binary data.
        """

        class DummyContainer(HeaderContainer):
            """AHAB dummy container for fast format validation.

            This class provides a lightweight container implementation used for quickly
            checking the basic AHAB container format without full processing overhead.
            It inherits from HeaderContainer and defines minimal required attributes
            for format validation.

            :cvar VERSION: Container format version [0, 2].
            :cvar TAG: Container header tag identifier.
            """

            VERSION = [0, 2]
            TAG = [AHABTags.CONTAINER_HEADER.tag, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag]

        logger.debug("Trying to find AHAB container on every 0x400 bytes")
        for offset in range(0, len(binary), 0x400):
            if not DummyContainer.check_container_head(
                binary[offset:], ignore_length=True
            ).has_errors:
                return offset

        if do_detail_search:
            logger.debug("Trying to find AHAB container on every 4 bytes")
            for offset in range(0, len(binary), 4):
                if not DummyContainer.check_container_head(
                    binary[offset:], ignore_length=True
                ).has_errors:
                    return offset
        raise SPSDKError("The AHAB container has not been found in given binary data")

    def _validate_container_type_support(
        self,
        container_type: Union[
            Type[AHABContainer], Type[AHABContainerV1forV2], Type[AHABContainerV2]
        ],
    ) -> None:
        """Validate that the family supports the given container type.

        This method checks if the specified AHAB container type is supported by the current
        chip family configuration and raises an error if not supported.

        :param container_type: AHAB container class type to validate against family support
        :raises SPSDKValueError: If container type is unknown or not supported by the family
        """
        if container_type == AHABContainerV2:
            required_version = 2
        elif container_type in [AHABContainer, AHABContainerV1forV2]:
            required_version = 1
        else:
            raise SPSDKValueError(f"Unknown container type: {container_type}")

        supported_versions = self.chip_config.container_types

        if required_version not in supported_versions:
            supported_str = ", ".join([f"V{v}" for v in supported_versions])
            raise SPSDKValueError(
                f"Family '{self.family}' does not support container type V{required_version}. "
                f"Supported types: {supported_str}"
            )
