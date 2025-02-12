#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB utils module."""
import logging
import os
import struct
from typing import Callable, Optional

from spsdk.apps.utils.utils import SPSDKError
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.fuses.fuses import FuseScript
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_data import AhabChipContainerConfig, FlagsSrkSet
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.ahab_sign_block import SignatureBlock, SignatureBlockV2
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import SegmentAhab
from spsdk.image.mem_type import MemoryType
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.misc import (
    get_abs_path,
    get_printable_path,
    load_binary,
    load_configuration,
    write_file,
)
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)


def ahab_update_keyblob(
    family: str,
    binary: str,
    keyblob: str,
    container_id: int,
    mem_type: Optional[str],
) -> None:
    """Update keyblob in AHAB image.

    :param family: MCU family
    :param binary: Path to AHAB image binary
    :param keyblob: Path to keyblob
    :param container_id: Index of the container to be updated
    :param mem_type: Memory type used for bootable image
    :raises SPSDKError: In case the container id not present
    :raises SPSDKError: In case the AHAB image does not contain blob
    :raises SPSDKError: In case the length of keyblobs don't match
    """
    DATA_READ = 0x4000
    offset = 0
    if mem_type:
        database = get_db(family)
        offset = database.get_dict(
            DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
        )["ahab_container"]

    keyblob_data = load_binary(keyblob)

    with open(binary, "r+b") as f:
        try:
            f.seek(offset)
            first_container = f.read(DATA_READ)
            container_type = AHABImage._parse_container_type(first_container)
            address = container_type.get_container_offset(container_id)
        except IndexError as exc:
            raise SPSDKError(f"No container ID {container_id}") from exc

        logger.debug(f"Trying to find AHAB container header at offset {hex(address + offset)}")
        f.seek(address + offset)
        data = f.read(DATA_READ)
        (
            _,
            flags,
            _,
            _,
            _,
            signature_block_offset,
        ) = container_type._parse(data)
        f.seek(signature_block_offset + address + offset)
        ahab_srk_id = (flags >> container_type.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << container_type.FLAGS_USED_SRK_ID_SIZE) - 1
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
        logger.debug(f"AHAB container found at offset {hex(address + offset)}")
        logger.debug(f"New keyblob: \n{blob}")
        logger.debug(f"Old keyblob: \n{signature_block.blob}")
        f.seek(signature_block_offset + address + signature_block._blob_offset + offset)
        f.write(blob.export())


def ahab_re_sign(
    family: str,
    binary: str,
    container_id: int,
    sign_provider_0: SignatureProvider,
    sign_provider_1: Optional[SignatureProvider] = None,
    mem_type: Optional[str] = None,
) -> None:
    """Re-sign the AHAB container in AHAB image.

    :param family: MCU family
    :param binary: Path to AHAB image binary
    :param container_id: Index of the container to be updated
    :param sign_provider_0: Signature provider object for main signature
    :param sign_provider_1: Signature provider object for additional signature
    :param mem_type: Memory type used for bootable image
    :raises SPSDKError: In case the container id not present
    """
    DATA_READ = 0x4000
    offset = 0
    if mem_type:
        database = get_db(family)
        offset = database.get_dict(
            DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
        )["ahab_container"]

    with open(binary, "r+b") as f:
        try:
            f.seek(offset)
            first_container = f.read(DATA_READ)
            container_type = AHABImage._parse_container_type(first_container)
            address = container_type.get_container_offset(container_id)
        except IndexError as exc:
            raise SPSDKError(f"No container ID {container_id}") from exc

        logger.debug(f"Trying to find AHAB container header at offset {hex(address + offset)}")
        f.seek(address + offset)
        data = f.read(DATA_READ)
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
        container_signature_offset = signature_block_offset + signature_block.signature_offset
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
        logger.debug(f"AHAB container found at offset {hex(address + offset)}")
        logger.debug(f"New main signature: \n{signature_data.hex()}")
        logger.debug(f"Old main signature: \n{old_signature_data.hex()}")
        f.seek(offset + address + container_signature_offset)
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
                offset
                + address
                + container_signature_offset
                + struct.calcsize(ContainerSignature.format())
            )
            f.write(signature_data)


def ahab_sign_image(image_path: str, config_path: str, mem_type: str) -> bytes:
    """Sign AHAB container set.

    Parse segments in Bootable image and sign non NXP AHAB containers.
    """
    config_data = load_configuration(config_path)
    config_dir = os.path.dirname(config_path)
    check_config(config_data, AHABImage.get_validation_schemas_family())
    family = config_data["family"]
    revision = config_data.get("revision", "latest")
    schemas = AHABImage.get_signing_validation_schemas(family, revision)
    check_config(config_data, schemas, search_paths=[config_dir])
    try:
        memory = MemoryType.from_label(mem_type)
    except KeyError:
        memory = None
    bimg = BootableImage.parse(
        load_binary(image_path),
        family=family,
        mem_type=memory,
        revision=revision,
    )
    logger.info(f"Parsed Bootable image memory map: {bimg.image_info().draw()}")

    for segment in bimg.segments:
        logger.info(f"Segment: {segment}")
        if isinstance(segment, SegmentAhab) and isinstance(segment.ahab, AHABImage):
            for container in segment.ahab.ahab_containers:
                if container.flag_srk_set == FlagsSrkSet.NXP:
                    logger.info("Skipping signing of NXP container")
                    continue
                container.load_from_config_generic(config_data)
                if (
                    isinstance(container.signature_block, (SignatureBlock, SignatureBlockV2))
                    and hasattr(container.signature_block, "blob")
                    and hasattr(container.signature_block.blob, "dek")
                ):
                    # if the blob DEK is present, set encryption flag on all images in container
                    # and update image IV (that is used for verification of encrypted image)
                    for image in container.image_array:
                        image.flags |= 1 << image.FLAGS_IS_ENCRYPTED_OFFSET
                        image.image_iv = get_hash(
                            image.plain_image, algorithm=EnumHashAlgorithm.SHA256
                        )
                        # Erase existing image hash
                        image.image_hash = b""
                container.update_fields()
                logger.info(container)
                logger.info(
                    f"Signed container at offset {hex(container.chip_config.container_offset)}"
                )
            segment.ahab.update_fields()
            segment.ahab.verify()
        else:
            logger.error("Segment does not contain AHAB data")

    return bimg.export()


def write_ahab_fuses(
    ahab: AHABImage,
    ahab_output_dir: str,
    ahab_output_file_no_ext: str,
    print_func: Callable[[str], None],
) -> None:
    """Write AHAB fuses."""
    for cnt_ix, container in enumerate(ahab.ahab_containers):
        if container.flag_srk_set == FlagsSrkSet.NXP:
            logger.debug("Skipping generating hashes for NXP container")
            continue
        if container.image_array_len > 0 and container.image_array[0].flags_core_id_name == "v2x-1":
            logger.debug("Skipping generating hashes for v2x-1 container")
            continue
        if container.signature_block:
            for srk_id in range(container.signature_block.SUPPORTED_SIGNATURES_CNT):
                srk_hash = container.get_srk_hash(srk_id)
                if srk_hash:
                    file_name = f"{ahab_output_file_no_ext}_{container.flag_srk_set.label}{cnt_ix}_srk{srk_id}_hash"
                    srk_hash_file = get_abs_path(f"{file_name}.txt", ahab_output_dir)
                    write_file(srk_hash.hex().upper(), srk_hash_file)
                    print_func(
                        f"Generated file containing SRK hash: {get_printable_path(srk_hash_file)}"
                    )
                    try:
                        fuse_script = FuseScript(
                            ahab.chip_config.family, ahab.chip_config.revision, DatabaseManager.AHAB
                        )
                        logger.info(
                            f"\nFuses info:\n{fuse_script.generate_script(container, info_only=True)}"
                        )
                        output_path = fuse_script.write_script(
                            file_name, ahab_output_dir, container
                        )
                        print_func(
                            "Generated script for writing fuses for container "
                            f"{cnt_ix}: {get_printable_path(output_path)}"
                        )
                    except SPSDKError:
                        logger.info(
                            f"Failed to generate script for writing fuses for container {cnt_ix}"
                        )
