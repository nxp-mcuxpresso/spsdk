#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB utils module."""
import logging
import struct
from typing import Callable, Optional

from spsdk.apps.utils.utils import SPSDKError
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.crypto.utils import get_matching_key_id
from spsdk.exceptions import SPSDKValueError
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_container import AHABContainerBase
from spsdk.image.ahab.ahab_data import FlagsSrkSet
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.ahab_sign_block import SignatureBlock
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.fuses import FuseScript
from spsdk.utils.misc import get_abs_path, get_printable_path, load_binary, write_file

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
    DATA_READ = 0x2000
    offset = 0
    if mem_type:
        database = get_db(family)
        offset = database.get_dict(
            DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
        )["ahab_container"]

    keyblob_data = load_binary(keyblob)

    try:
        address = AHABImage.get_container_offset(container_id)
    except IndexError as exc:
        raise SPSDKError(f"No container ID {container_id}") from exc

    with open(binary, "r+b") as f:
        logger.debug(f"Trying to find AHAB container header at offset {hex(address + offset)}")
        f.seek(address + offset)
        data = f.read(DATA_READ)
        (
            _,
            _,
            _,
            _,
            signature_block_offset,
        ) = AHABContainerBase._parse(data)
        f.seek(signature_block_offset + address + offset)
        signature_block = SignatureBlock.parse(f.read(DATA_READ))
        blob = AhabBlob.parse(keyblob_data)
        blob.verify().validate()
        signature_block.update_fields()
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
    sign_provider: SignatureProvider,
    container_id: int,
    mem_type: Optional[str],
) -> None:
    """Re-sign the AHAB container in AHAB image.

    :param family: MCU family
    :param binary: Path to AHAB image binary
    :param sign_provider: Signature provider object
    :param container_id: Index of the container to be updated
    :param mem_type: Memory type used for bootable image
    :raises SPSDKError: In case the container id not present
    """
    DATA_READ = 0x400
    offset = 0
    if mem_type:
        database = get_db(family)
        offset = database.get_dict(
            DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "segments"]
        )["ahab_container"]

    try:
        address = AHABImage.get_container_offset(container_id)
    except IndexError as exc:
        raise SPSDKError(f"No container ID {container_id}") from exc

    with open(binary, "r+b") as f:
        logger.debug(f"Trying to find AHAB container header at offset {hex(address + offset)}")
        f.seek(address + offset)
        data = f.read(DATA_READ)
        (
            flags,
            _,
            _,
            _,
            signature_block_offset,
        ) = AHABContainerBase._parse(data)
        signature_block = SignatureBlock.parse(data[signature_block_offset:])
        signature_block.update_fields()
        signature_block.verify().validate()
        if not signature_block.signature:
            raise SPSDKError("AHAB Container must contain Signature in order to update it")
        if not signature_block.srk_table:
            raise SPSDKError("AHAB Container must contain SRK table in order to update signature")
        # Validate input signature provider type and match to already inserted public keys in SRK table
        public_keys = signature_block.srk_table.get_source_keys()
        try:
            match_key_id = get_matching_key_id(
                public_keys=public_keys, signature_provider=sign_provider
            )
        except SPSDKValueError as exc:
            raise SPSDKError(
                "The provided signature provider doesn't match to any public key in SRK table"
            ) from exc
        ahab_srk_id = (flags >> AHABContainerBase.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << AHABContainerBase.FLAGS_USED_SRK_ID_SIZE) - 1
        )
        if match_key_id != ahab_srk_id:
            raise SPSDKError(
                f"The provided signature provider doesn't match to public key ID ({ahab_srk_id}) in SRK table."
                f"It matches index {match_key_id}."
            )

        # Get data to sign
        container_signature_offset = signature_block_offset + signature_block.signature_offset
        data_to_sign = data[:container_signature_offset]
        signature_data = sign_provider.get_signature(data_to_sign)
        old_signature_data = data[
            container_signature_offset
            + struct.calcsize(ContainerSignature.format()) : container_signature_offset
            + sign_provider.signature_length
            + struct.calcsize(ContainerSignature.format())
        ]

        if not len(signature_block.signature.signature_data) == len(signature_data):
            raise SPSDKError("The size of the signature must be same")
        logger.debug(f"AHAB container found at offset {hex(address + offset)}")
        logger.debug(f"New signature: \n{signature_data.hex()}")
        logger.debug(f"Old signature: \n{old_signature_data.hex()}")
        f.seek(
            offset
            + address
            + container_signature_offset
            + struct.calcsize(ContainerSignature.format())
        )
        f.write(signature_data)


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
        file_name = f"{ahab_output_file_no_ext}_{container.flag_srk_set.label}{cnt_ix}_srk_hash"
        if container.srk_hash:
            srk_hash_file = get_abs_path(f"{file_name}.txt", ahab_output_dir)
            write_file(container.srk_hash.hex().upper(), srk_hash_file)
            print_func(f"Generated file containing SRK hash: {get_printable_path(srk_hash_file)}")
            try:
                fuse_script = FuseScript(
                    ahab.chip_config.family, ahab.chip_config.revision, DatabaseManager.AHAB
                )
                logger.info(
                    f"\nFuses info:\n{fuse_script.generate_script(container, info_only=True)}"
                )
                output_path = fuse_script.write_script(file_name, ahab_output_dir, container)
                print_func(
                    f"Generated script for writing fuses for container {cnt_ix}: {get_printable_path(output_path)}"
                )
            except SPSDKError:
                logger.info(f"Failed to generate script for writing fuses for container {cnt_ix}")
