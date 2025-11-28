#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB utility functions for image processing and management.

This module provides utility functions for working with AHAB (Advanced High Assurance Boot)
images, including image detection, key blob updates, signing operations, and signature
block management.
"""

import logging
import os
import struct
from copy import deepcopy
from typing import Optional

from spsdk.apps.utils.utils import SPSDKError
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_data import AhabChipContainerConfig, AHABTags, FlagsSrkSet
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.ahab_sign_block import SignatureBlock, SignatureBlockV2
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import SegmentAhab
from spsdk.image.mem_type import MemoryType
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


def find_ahab_image_in_file(file_path: str, image_id: int = 0, start_offset: int = 0) -> int:
    """Find offset of AHAB image in file by image ID.

    The method searches through the file starting from the specified offset,
    reading data in chunks to locate AHAB images and returns the offset of
    the image with the matching ID.

    :param file_path: File path of file containing AHAB image.
    :param image_id: The AHAB image ID to search for, defaults to 0.
    :param start_offset: Start offset in bytes to begin the search from.
    :return: Offset of AHAB image by ID, otherwise value under zero if not found.
    """
    DATA_READ = 0x1000
    file_size = os.path.getsize(file_path)
    image_count = 0
    container_count = 0
    last_container_address = 0
    container_size = 0
    with open(file_path, "r+b") as f:
        for x in range(start_offset, file_size, DATA_READ):
            try:
                f.seek(x)
                data = f.read(DATA_READ)
                container_offset = AHABImage.find_offset_of_ahab(binary=data)
                container_address = x + container_offset
                logger.debug(
                    f"AHAB image {image_count} container {container_count} at offset {hex(container_address)}"
                )

                if container_count == 0:
                    container_size = AHABImage._parse_container_type(
                        data, ignore_length=True
                    ).CONTAINER_SIZE

                if (
                    container_count > 0
                    and abs(container_address - last_container_address) > container_size
                ):
                    image_count += 1
                    container_count = 0

                if image_count == image_id:
                    return container_address

                container_count += 1
                last_container_address = container_address
            except (IndexError, SPSDKError):
                pass
    return -1


def ahab_update_keyblob(
    family: FamilyRevision,
    binary: str,
    keyblob: str,
    container_id: int,
    image_id: int = 0,
    mem_type: Optional[str] = None,
) -> None:
    """Update keyblob in AHAB image.

    This function locates an AHAB container within a binary image and replaces its existing
    keyblob with a new one. The operation validates both the old and new keyblobs and ensures
    they have matching sizes before performing the update.

    :param family: MCU family revision information
    :param binary: Path to AHAB image binary file
    :param keyblob: Path to new keyblob file to be inserted
    :param container_id: Index of the container to be updated
    :param image_id: Index of AHAB image in binary to look for, defaults to 0
    :param mem_type: Memory type used for bootable image, optional
    :raises SPSDKError: In case the container id is not present
    :raises SPSDKError: In case the AHAB image does not contain blob
    :raises SPSDKError: In case the length of keyblobs don't match
    :raises SPSDKError: In case AHAB image is not found
    """
    DATA_READ = 0x4000
    offset = 0
    database = get_db(family)
    container_max_containers = database.get_int(DatabaseManager.AHAB, "containers_max_cnt")
    if container_id >= container_max_containers:
        raise SPSDKError(
            f"Container ID {container_id} is out of range. Maximum containers: {container_max_containers}"
        )

    if mem_type:
        try:
            offset = database.get_dict(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
            )["ahab_container"]
        except KeyError:
            offset = database.get_dict(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
            )["primary_image_container_set"]

    ahab_image_offset = find_ahab_image_in_file(binary, image_id=image_id, start_offset=offset)
    if ahab_image_offset < 0:
        raise SPSDKError(f"AHAB Image ({image_id}) not found!")

    keyblob_data = load_binary(keyblob)

    with open(binary, "r+b") as f:
        try:
            f.seek(ahab_image_offset)
            first_container = f.read(DATA_READ)
            container_type = AHABImage._parse_container_type(first_container)
            address = container_type.get_container_offset(container_id)
        except IndexError as exc:
            raise SPSDKError(f"No container ID {container_id}") from exc

        logger.debug(
            f"Trying to find AHAB container header at offset {hex(address + ahab_image_offset)}"
        )
        f.seek(address + ahab_image_offset)
        data = f.read(DATA_READ)
        container_type = AHABImage._parse_container_type(data)
        (
            _,
            flags,
            _,
            _,
            _,
            signature_block_offset,
        ) = container_type._parse(data)
        f.seek(signature_block_offset + address + ahab_image_offset)
        ahab_srk_id = (flags >> container_type.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << container_type.FLAGS_USED_SRK_ID_SIZE) - 1
        )
        srk_set = (flags >> container_type.FLAGS_SRK_SET_OFFSET) & (
            (1 << container_type.FLAGS_SRK_SET_SIZE) - 1
        )
        if FlagsSrkSet.from_tag(srk_set) == FlagsSrkSet.NXP:
            logger.warning(
                "Updating keyblob of a container signed by NXP, please make sure this is intended behaviour."
            )
        container_chip_config = AhabChipContainerConfig(used_srk_id=ahab_srk_id)
        signature_block = container_type.SIGNATURE_BLOCK.parse(
            data[signature_block_offset:], chip_config=container_chip_config
        )
        blob = AhabBlob.parse(keyblob_data)
        blob.verify().validate()
        signature_block.verify().validate()
        if not signature_block.blob:
            raise SPSDKError("AHAB Container must contain BLOB in order to update it")
        if not len(signature_block.blob.export()) == len(blob.export()):
            raise SPSDKError("The size of the BLOB must be same")
        logger.debug(f"AHAB container found at offset {hex(address + ahab_image_offset)}")
        logger.debug(f"New keyblob: \n{blob}")
        logger.debug(f"Old keyblob: \n{signature_block.blob}")
        f.seek(signature_block_offset + address + signature_block._blob_offset + ahab_image_offset)
        f.write(blob.export())


def ahab_re_sign(
    family: FamilyRevision,
    binary: str,
    container_id: int,
    image_id: int,
    sign_provider_0: SignatureProvider,
    sign_provider_1: Optional[SignatureProvider] = None,
    mem_type: Optional[str] = None,
) -> None:
    """Re-sign the AHAB container in AHAB image.

    This function locates and updates the signature(s) in an existing AHAB container within
    a binary image file. It supports both single and dual signature scenarios.

    :param family: MCU family revision information.
    :param binary: Path to AHAB image binary file.
    :param container_id: Index of the container to be updated.
    :param image_id: Index of AHAB image in binary to look for.
    :param sign_provider_0: Signature provider object for main signature.
    :param sign_provider_1: Signature provider object for additional signature.
    :param mem_type: Memory type used for bootable image.
    :raises SPSDKError: If container ID not present, AHAB image not found, container lacks
        required signature or SRK table, or dual signing is not supported.
    """
    DATA_READ = 0x4000
    offset = 0
    database = get_db(family)
    container_max_containers = database.get_int(DatabaseManager.AHAB, "containers_max_cnt")
    if container_id >= container_max_containers:
        raise SPSDKError(
            f"Container ID {container_id} is out of range. Maximum containers: {container_max_containers}"
        )

    if mem_type:
        try:
            offset = database.get_dict(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
            )["ahab_container"]
        except KeyError:
            offset = database.get_dict(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
            )["primary_image_container_set"]

    ahab_image_offset = find_ahab_image_in_file(binary, image_id=image_id, start_offset=offset)
    if ahab_image_offset < 0:
        raise SPSDKError(f"AHAB Image ({image_id}) not found!")

    with open(binary, "r+b") as f:
        try:
            f.seek(ahab_image_offset)
            first_container = f.read(DATA_READ)
            container_type = AHABImage._parse_container_type(first_container)
            address = container_type.get_container_offset(container_id)
        except IndexError as exc:
            raise SPSDKError(f"No container ID {container_id}") from exc

        logger.debug(
            f"Trying to find AHAB container header at offset {hex(address + ahab_image_offset)}"
        )
        f.seek(address + ahab_image_offset)
        data = f.read(DATA_READ)
        container_type = AHABImage._parse_container_type(data)
        (
            _,
            flags,
            _,
            _,
            _,
            signature_block_offset,
        ) = container_type._parse(data)
        ahab_srk_id = (flags >> container_type.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << container_type.FLAGS_USED_SRK_ID_SIZE) - 1
        )
        container_chip_config = AhabChipContainerConfig(used_srk_id=ahab_srk_id)
        signature_block = container_type.SIGNATURE_BLOCK.parse(
            data[signature_block_offset:], chip_config=container_chip_config
        )
        signature_block.verify().validate()
        if not signature_block.signature:
            raise SPSDKError("AHAB Container must contain Signature in order to update it")
        if not signature_block.srk_assets:
            raise SPSDKError("AHAB Container must contain SRK table in order to update signature")

        # Get data to sign
        container_signature_offset = signature_block_offset + signature_block._signature_offset
        data_to_sign = data[:container_signature_offset]
        signature_data = sign_provider_0.get_signature(data_to_sign)
        container_signature_offset += struct.calcsize(ContainerSignature.format())
        old_signature_data = data[
            container_signature_offset : container_signature_offset
            + sign_provider_0.signature_length
        ]
        signature_block.signature.signature_data = signature_data
        signature_block.verify().validate()
        signature_block.verify_container_authenticity(data_to_sign).validate()
        logger.debug(f"AHAB container found at offset {hex(address + ahab_image_offset)}")
        logger.debug(f"New main signature: \n{signature_data.hex()}")
        logger.debug(f"Old main signature: \n{old_signature_data.hex()}")
        f.seek(ahab_image_offset + address + container_signature_offset)
        f.write(signature_data)

        if sign_provider_1:
            if not isinstance(signature_block, SignatureBlockV2):
                raise SPSDKError("The Container doesn't support double signing")
            if signature_block.signature_2 is None:
                raise SPSDKError("The Container doesn't contains additional signature")
            signature_data = sign_provider_1.get_signature(data_to_sign)
            container_signature_offset += sign_provider_0.signature_length + struct.calcsize(
                ContainerSignature.format()
            )
            old_signature_data = data[
                container_signature_offset : container_signature_offset
                + sign_provider_1.signature_length
            ]

            signature_block.signature_2.signature_data = signature_data
            signature_block.verify().validate()
            signature_block.verify_container_authenticity(data_to_sign).validate()
            logger.debug(f"New additional signature: \n{signature_data.hex()}")
            logger.debug(f"Old additional signature: \n{old_signature_data.hex()}")
            f.seek(
                ahab_image_offset
                + address
                + container_signature_offset
                + struct.calcsize(ContainerSignature.format())
            )
            f.write(signature_data)


def ahab_sign_image(
    image_path: str, config: Config, mem_type: str, image_id: int = 0
) -> tuple[bytes, BootableImage]:
    """Sign AHAB container set.

    Parse segments in Bootable image and sign non-NXP AHAB containers. The method validates
    the configuration, loads the bootable image, and processes each AHAB segment to sign
    OEM containers while skipping NXP and V2X containers.

    :param image_path: Path to the image file to sign.
    :param config: Configuration object containing signing parameters and validation schemas.
    :param mem_type: Memory type label for the target device.
    :param image_id: The AHAB Image ID to process, defaults to 0.
    :raises SPSDKError: Invalid configuration or image parsing errors.
    :return: Tuple of signed image data as bytes and bootable image object.
    """
    config.check(AHABImage.get_validation_schemas_basic())
    family = FamilyRevision.load_from_config(config)
    schemas = AHABImage.get_signing_validation_schemas(family)
    config.check(schemas, check_unknown_props=True)
    try:
        memory = MemoryType.from_label(mem_type)
    except KeyError:
        memory = None
    bimg = BootableImage.parse(load_binary(image_path), family=family, mem_type=memory)
    logger.info(f"Parsed Bootable image memory map: {bimg.image_info().draw()}")
    act_ahab_image_id = 0
    for segment in bimg.segments:
        logger.info(f"Segment: {segment}")
        if isinstance(segment, SegmentAhab) and isinstance(segment.ahab, AHABImage):
            if act_ahab_image_id < image_id:
                act_ahab_image_id += 1
                continue
            for container in segment.ahab.ahab_containers:
                if container.flag_srk_set not in [FlagsSrkSet.OEM, FlagsSrkSet.NONE]:
                    logger.info("Skipping signing of none OEM and non signed container")
                    continue
                # Check if container contains V2X image
                v2x_found = False
                if len(container.image_array) > 0:
                    for image in container.image_array:
                        if "v2x" in image.flags_core_id_name:
                            v2x_found = True
                            break
                if v2x_found:
                    logger.info("Skipping signing of V2X container")
                    continue
                original_container = deepcopy(container)
                container.load_from_config_generic(config)
                if (
                    isinstance(container.signature_block, (SignatureBlock, SignatureBlockV2))
                    and hasattr(container.signature_block, "blob")
                    and hasattr(container.signature_block.blob, "dek")
                ):
                    # if the blob DEK is present, set encryption flag on all images in container
                    # and update image IV (that is used for verification of encrypted image)
                    for ix, image in enumerate(container.image_array):
                        # Check if the image is not Already encrypted
                        if image.flags_is_encrypted:
                            raise SPSDKError(
                                f"Image {ix} in container 0x{container.chip_config.container_offset:04X}"
                                " is already encrypted"
                            )
                        image.flags |= 1 << image.FLAGS_IS_ENCRYPTED_OFFSET
                        if image._get_valid_size(image=image.image) != len(image.image):
                            logger.warning(
                                f"Image {ix} size does not match expected size. Padding might be required."
                                "Unlocking image, the image can change as image sizes as offsets."
                            )
                            image.image = image.image
                            container.chip_config.locked = False

                        image.image_iv = get_hash(
                            image.plain_image, algorithm=EnumHashAlgorithm.SHA256
                        )
                        # Erase existing image hash
                        image.image_hash = b""
                container.update_fields()
                # Calculate absolute offset (segment + container)
                segment_offset = segment.full_image_offset
                container_offset = container.chip_config.container_offset
                absolute_offset = segment_offset + container_offset

                changes_info = (
                    f"On container at absolute offset {hex(absolute_offset)} "
                    f"(AHAB image offset {hex(segment_offset)} + container offset {hex(container_offset)}) "
                    f"in image \n{segment.image_info()} Has been done following major updates:\n"
                    f"{container.print_diff(original_container.diff(container))}"
                )
                logger.info(changes_info)

            segment.ahab.update_fields()
            segment.ahab.verify()

        else:
            logger.error("Segment does not contain AHAB data")

    return bimg.export(), bimg


def ahab_fix_signature_block_version(
    family: FamilyRevision,
    binary: str,
) -> bytes:
    """Fix signature block version in AHAB v2 signature blocks.

    The imx-mkimage tool is known to create incorrect signature block versions. This method
    corrects the version to match the expected AHAB v2 signature block version by scanning
    the binary data for signature blocks with version 0 and updating them to version 1.

    :param family: Family revision of the target device.
    :param binary: Path to the binary AHAB image file to fix.
    :raises SPSDKError: If the fix is not applicable for AHAB v2 containers or if
                        verification of the fixed image fails.
    :return: Fixed binary data with corrected signature block versions.
    """
    data = bytearray(load_binary(binary))
    database = get_db(family)
    supported_containers = database.get_list(DatabaseManager.AHAB, "container_types")

    if supported_containers[0] != 2:
        raise SPSDKError("This fix is only applicable for AHAB v2 containers")

    class DummySignature(HeaderContainer):
        """AHAB dummy signature container for format validation.

        This class provides a lightweight signature container implementation used for
        fast validation of AHAB signature block format without full signature processing.

        :cvar VERSION: Supported version numbers for the dummy signature format.
        :cvar TAG: AHAB signature block tag identifier.
        """

        VERSION = [0]
        TAG = AHABTags.SIGNATURE_BLOCK.tag

    logger.info("Trying to find signature blocks version 0 on every 0x10 bytes")
    for offset in range(0, len(data), 0x10):
        if not DummySignature.check_container_head(data[offset : offset + 0x10]).has_errors:
            _, length, version = HeaderContainer.parse_head(data[offset : offset + 0x10])
            if length == 16 and version == 0:
                data[offset] = 1
                logger.info(f"Fixed signature block version at {hex(offset)}")

    bimg = BootableImage.parse(bytes(data), family, None)
    if bimg.verify().has_errors:
        raise SPSDKError("Verification of fixed image failed")

    return data
