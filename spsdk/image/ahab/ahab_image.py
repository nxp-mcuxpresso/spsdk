#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB image support."""

import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional

from spsdk.exceptions import (
    SPSDKError,
    SPSDKLengthError,
    SPSDKParsingError,
    SPSDKValueError,
    SPSDKVerificationError,
)
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_container import AHABContainer
from spsdk.image.ahab.ahab_data import (
    CONTAINER_ALIGNMENT,
    START_IMAGE_ADDRESS,
    START_IMAGE_ADDRESS_NAND,
    TARGET_MEMORY_BOOT_OFFSETS,
    AhabChipConfig,
    AHABTags,
    AhabTargetMemory,
    FlagsSrkSet,
)
from spsdk.image.ahab.ahab_iae import ImageArrayEntryTemplates
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, align, load_binary
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.spsdk_enum import SpsdkSoftEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: Dict, val: Any) -> Any:
    """Get Dictionary key by its value or default.

    :param dictionary: Dictionary to search in.
    :param val: Value to search
    :raises SPSDKValueError: In case that dictionary doesn't contains the value.
    :return: Key.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class AHABImage:
    """Class representing an AHAB image.

    The image consists of multiple AHAB containers.
    """

    def __init__(
        self,
        family: str,
        revision: str = "latest",
        target_memory: str = AhabTargetMemory.TARGET_MEMORY_NOR.label,
        ahab_containers: Optional[List[AHABContainer]] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """AHAB Image constructor.

        :param family: Name of device family.
        :param revision: Device silicon revision, defaults to "latest"
        :param target_memory: Target memory for AHAB image [serial_downloader, nor, nand], defaults to "nor"
        :param ahab_containers: _description_, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid input configuration.
        """
        if target_memory not in AhabTargetMemory.labels():
            raise SPSDKValueError(
                f"Invalid AHAB target memory [{target_memory}]."
                f" The list of supported images: [{','.join(AhabTargetMemory.labels())}]"
            )
        start_image_address = (
            START_IMAGE_ADDRESS_NAND
            if target_memory
            in [
                AhabTargetMemory.TARGET_MEMORY_NAND_2K.label,
                AhabTargetMemory.TARGET_MEMORY_NAND_4K.label,
            ]
            else START_IMAGE_ADDRESS
        )
        self._database = get_db(family, revision)
        containers_max_cnt = self._database.get_int(DatabaseManager.AHAB, "containers_max_cnt")
        images_max_cnt = self._database.get_int(DatabaseManager.AHAB, "oem_images_max_cnt")
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", self._database.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        image_types = SpsdkSoftEnum.create_from_dict(
            "AHABImageTypes", self._database.get_dict(DatabaseManager.AHAB, "image_types")
        )
        valid_offset_minimal_alignment = self._database.get_int(
            DatabaseManager.AHAB, "valid_offset_minimal_alignment", 4
        )
        container_image_size_alignment = self._database.get_int(
            DatabaseManager.AHAB, "container_image_size_alignment", 1
        )
        self.chip_config = AhabChipConfig(
            family=family,
            revision=self._database.name,
            target_memory=AhabTargetMemory.from_label(target_memory),
            core_ids=core_ids,
            image_types=image_types,
            start_image_address=start_image_address,
            containers_max_cnt=containers_max_cnt,
            images_max_cnt=images_max_cnt,
            valid_offset_minimal_alignment=valid_offset_minimal_alignment,
            container_image_size_alignment=container_image_size_alignment,
            search_paths=search_paths,
        )
        self.ahab_containers: List[AHABContainer] = ahab_containers or []

    def __repr__(self) -> str:
        return f"AHAB Image for {self.chip_config.family}"

    def __str__(self) -> str:
        return (
            "AHAB Image:\n"
            f"  Family:             {self.chip_config.family}\n"
            f"  Revision:           {self.chip_config.revision}\n"
            f"  Target memory:      {self.chip_config.target_memory.label}\n"
            f"  Max cont. count:    {self.chip_config.containers_max_cnt}"
            f"  Max image. count:   {self.chip_config.images_max_cnt}"
            f"  Containers count:   {len(self.ahab_containers)}"
        )

    def add_container(self, container: AHABContainer) -> None:
        """Add new container into AHAB Image.

        The order of the added images is important.
        :param container: New AHAB Container to be added.
        :raises SPSDKLengthError: The container count in image is overflowed.
        """
        if len(self.ahab_containers) >= self.chip_config.containers_max_cnt:
            raise SPSDKLengthError(
                "Cannot add new container because the AHAB Image already reached"
                f" the maximum count: {self.chip_config.containers_max_cnt}"
            )

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
            offset = self.chip_config.start_image_address
            for ahab_container in self.ahab_containers:
                for image in ahab_container.image_array:
                    if ahab_container.chip_config.locked or image.image_offset > 0:
                        offset = image.image_offset
                    else:
                        image.image_offset = offset
                    offset = image.get_valid_offset(offset + image.image_size)

                ahab_container.chip_config.locked = True

        # Sign the image header
        for ahab_container in self.ahab_containers:
            if (
                ahab_container.flag_srk_set != FlagsSrkSet.NONE
                and ahab_container.signature_block.signature
            ):
                ahab_container.signature_block.signature.sign(ahab_container.get_signature_data())

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        :return: Size in Bytes of AHAB Image.
        """
        lengths = [0]
        for container in self.ahab_containers:
            lengths.extend([align(x.image_offset + x.image_size) for x in container.image_array])
        return align(max(lengths), CONTAINER_ALIGNMENT)

    def get_containers_size(self) -> int:
        """Get maximal containers size.

        In fact get the offset where could be stored first data.

        :return: Size of containers.
        """
        if len(self.ahab_containers) == 0:
            return 0
        sizes = [
            container.header_length() + AHABImage.get_container_offset(ix)
            for ix, container in enumerate(self.ahab_containers)
        ]
        return align(max(sizes), CONTAINER_ALIGNMENT)

    def get_first_data_image_address(self) -> int:
        """Get first data image address.

        :return: Address of first data image.
        """
        addresses = []
        for container in self.ahab_containers:
            addresses.extend([x.image_offset for x in container.image_array])
        return min(addresses)

    def export(self) -> bytes:
        """Export AHAB Image.

        :raises SPSDKValueError: mismatch between number of containers and offsets.
        :raises SPSDKValueError: number of images mismatch.
        :return: bytes AHAB  Image.
        """
        self.update_fields()
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
            description=f"AHAB Image for {self.chip_config.family}_{self.chip_config.revision}",
            pattern=BinaryPattern("zeros"),
        )
        ahab_containers = BinaryImage(
            name="AHAB Containers",
            size=self.chip_config.start_image_address,
            offset=0,
            description="AHAB Containers block",
            pattern=BinaryPattern("zeros"),
        )
        ret.add_image(ahab_containers)

        for cnt_ix, container in enumerate(self.ahab_containers):

            container_image = container.image_info()
            container_image.name = container_image.name + f" {cnt_ix}"
            container_image.offset = AHABImage.get_container_offset(cnt_ix)
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
                        f"data block with {image_entry.flags_image_type_name} Image Type."
                    ),
                )

                ret.add_image(data_image)

        return ret

    def verify(self) -> Verifier:
        """Verifier object data."""

        def verify_container_offsets(container: AHABContainer) -> None:
            # Verify the container offset
            for ix, cnt in enumerate(self.ahab_containers):
                offset = AHABImage.get_container_offset(ix)
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
        offset = self.chip_config.start_image_address
        alignment = self.ahab_containers[0].image_array[0].get_valid_alignment()
        ver_images = Verifier("Data images")
        for cnt_ix, container in enumerate(self.ahab_containers):
            for img_ix, image in enumerate(container.image_array):
                ver_img = Verifier(f"Data image{img_ix}")
                if image.image_offset_real < self.chip_config.start_image_address:
                    ver_img.add_record(
                        "Minimal Offset",
                        VerifierResult.ERROR,
                        "The offset of data image (container"
                        f"{cnt_ix}/image{img_ix}) is under minimal allowed value."
                        f" {hex(image.image_offset_real)} < {hex(self.chip_config.start_image_address)}",
                    )
                else:
                    ver_img.add_record(
                        "Minimal Offset",
                        VerifierResult.SUCCEEDED,
                        hex(image.image_offset_real),
                    )

                if image.image_offset_real != align(image.image_offset_real, alignment):
                    std_offset = hex(
                        align(image.image_offset, alignment)
                        - TARGET_MEMORY_BOOT_OFFSETS[self.chip_config.target_memory]
                    )
                    ver_img.add_record(
                        "Alignment",
                        VerifierResult.ERROR,
                        f"Invalid Image Offset alignment for target memory '{self.chip_config.target_memory.label}': "
                        f"{hex(image.image_offset_real)} "
                        f"should be with alignment {hex(alignment)}.\n"
                        "For example: Bootable image offset ("
                        f"{hex(TARGET_MEMORY_BOOT_OFFSETS[self.chip_config.target_memory])})"
                        " + offset ("
                        f"{std_offset})  is correctly aligned.",
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
                            f"\n Expected {hex(offset)}, Used:{hex(image.image_offset_real)}",
                        )
                    else:
                        ver_img.add_record(
                            "Serial Downloader mode offset", VerifierResult.SUCCEEDED
                        )
                        offset = image.image_offset

                    offset = image.get_valid_offset(offset + image.image_size)
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

    @staticmethod
    def get_target_memory(config: Dict[str, Any]) -> str:
        """Get target memory from the configuration.

        With backward compatibility for the obsolete key 'image_type'.

        :param config: Configuration dictionary.
        :return: Target memory.
        """
        target_memory = config.get("target_memory")
        if target_memory is None:
            # backward compatible reading of obsolete image type
            image_type = config.get("image_type")
            if not image_type:
                return "standard"
            target_memory = {
                "xip": "nor",
                "non_xip": "nor",
                "nand": "nand_2k",
                "serial_downloader": "serial_downloader",
            }[image_type]
            logger.warning(
                f"The obsolete key 'image_type':{image_type} has been converted into 'target_memory':{target_memory}"
            )

        if target_memory == "nor":
            return "standard"

        return target_memory

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "AHABImage":
        """Converts the configuration option into an AHAB image object.

        "config" content array of containers configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: if the count of AHAB containers is invalid.
        :raises SPSDKParsingError: Cannot parse input binary AHAB container.
        :return: Initialized AHAB Image.
        """
        containers_config: List[Dict[str, Any]] = config["containers"]
        family = config["family"]
        revision = config.get("revision", "latest")
        target_memory = AHABImage.get_target_memory(config)
        ahab = AHABImage(
            family=family, revision=revision, target_memory=target_memory, search_paths=search_paths
        )
        i = 0
        for container_config in containers_config:
            binary_container = container_config.get("binary_container")
            if binary_container:
                assert isinstance(binary_container, dict)
                path = binary_container.get("path")
                assert path
                ahab_bin = load_binary(path, search_paths=search_paths)
                for j in range(ahab.chip_config.containers_max_cnt):
                    try:
                        ahab.add_container(
                            AHABContainer.parse(
                                ahab_bin[AHABImage.get_container_offset(j) :],
                                chip_config=ahab.chip_config,
                                container_id=i,
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
                ahab.add_container(
                    AHABContainer.load_from_config(
                        ahab.chip_config, container_config["container"], i
                    )
                )
                i += 1

        return ahab

    def parse(self, binary: bytes) -> None:
        """Parse input binary chunk to the container object.

        :raises SPSDKError: No AHAB container found in binary data.
        """
        self.clear()

        for i in range(self.chip_config.containers_max_cnt):
            try:
                container = AHABContainer.parse(
                    binary[AHABImage.get_container_offset(i) :],
                    chip_config=self.chip_config,
                    container_id=i,
                )
                self.ahab_containers.append(container)
            except SPSDKVerificationError as exc:
                logger.debug(f"AHAB Image parsing error:\n{str(exc)}")
            except SPSDKError as exc:
                raise SPSDKError(f"AHAB Container parsing failed: {str(exc)}.") from exc
        if len(self.ahab_containers) == 0:
            raise SPSDKError("No AHAB Container has been found in binary data.")

    @staticmethod
    def pre_parse_verify(data: bytes) -> Verifier:
        """Pre-Parse verify of AHAB Image.

        :param data: Binary data with AHAB Image to pre-parse.
        :return: Verifier of pre-parsed binary data.
        """
        ret = Verifier("Pre-parsed AHAB Image")
        for i, address in enumerate(range(0, 0xC00, 0x400)):
            ver_just_container = AHABContainer.check_container_head(data[address:])
            if i == 0 or not ver_just_container.has_errors:
                ret.add_child(
                    AHABContainer.pre_parse_verify(data[address:]), f"Container at {hex(address)}"
                )
            else:
                break
        return ret

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get all supported families for AHAB container.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.AHAB)

    @classmethod
    def get_validation_schemas_family(cls) -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for TZ supported families.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)
        return [sch["family"]]

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :param revision: Family revision of chip.
        :return: Validation list of schemas.
        """
        extra_images = None
        db = get_db(family, revision)
        extra_images = db.get_list(DatabaseManager.AHAB, "extra_images", [])
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", db.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        image_types = SpsdkSoftEnum.create_from_dict(
            "AHABImageTypes", get_db(family, revision).get_dict(DatabaseManager.AHAB, "image_types")
        )
        sch = get_schema_file(DatabaseManager.AHAB)
        sch["family"]["properties"]["family"]["template_value"] = family
        sch["family"]["properties"]["family"]["enum"] = AHABImage.get_supported_families()

        images = sch["whole_ahab_image"]["properties"]["containers"]["items"]["oneOf"][1][
            "properties"
        ]["container"]["properties"]["images"]["items"].pop("oneOf")

        # Find general image tak the content and optionally add it to each extension without binary_image
        std_properties = {}
        for image in images:
            if "general_image" == image["image_identifier"]:
                image["properties"]["core_id"]["enum"] = core_ids.labels()
                image["properties"]["image_type"]["enum"] = image_types.labels()
                org_std_properties: Dict[str, Any] = deepcopy(image)
                break

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

        return [sch["family"], sch["whole_ahab_image"]]

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> Dict[str, Any]:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :param revision: Family revision of chip.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = AHABImage.get_validation_schemas(family, revision)

        yaml_data = CommentedConfig(
            f"Advanced High-Assurance Boot Configuration template for {family}.", val_schemas
        ).get_template()

        return {f"{family}_ahab": yaml_data}

    def create_config(self, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.c
        """
        cfg: Dict[str, Any] = {}
        cfg["family"] = self.chip_config.family
        cfg["revision"] = self.chip_config.revision
        cfg["target_memory"] = self.chip_config.target_memory.label
        cfg["output"] = "N/A"
        cfg_containers = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            cfg_containers.append(container.create_config(cnt_ix, data_path))
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

    @staticmethod
    def get_container_offset(ix: int) -> int:
        """Get container offset by index.

        :param ix: Container index
        :return: Container offset
        """
        assert ix >= 0
        if ix > 3:
            raise SPSDKValueError("There is no option to have more that 4 containers")
        return 0x400 * ix
