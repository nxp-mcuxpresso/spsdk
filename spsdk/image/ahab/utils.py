#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB utils module."""
import logging
from typing import Optional

from spsdk.apps.utils.utils import SPSDKError
from spsdk.image.ahab.ahab_container import AHABContainerBase, AHABImage, Blob, SignatureBlock
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


def ahab_update_keyblob(
    family: str, binary: str, keyblob: str, container_id: int, mem_type: Optional[str]
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
    offset = 0
    if mem_type:
        offset = {
            "serial_downloader": 0x400,
            "flexspi_nor": 0x1000,
            "flexspi_nand": 0x400,
            "semc_nand": 0x400,
        }[mem_type]

    keyblob_data = load_binary(keyblob)
    image = AHABImage(family)

    try:
        address = image.ahab_address_map[container_id]
    except IndexError as exc:
        raise SPSDKError(f"No container ID {container_id}") from exc

    with open(binary, "r+b") as f:
        logger.debug(f"Trying to find AHAB container header at offset {hex(address + offset)}")
        f.seek(address + offset)
        data = f.read(1024)
        (
            _,
            _,
            _,
            _,
            signature_block_offset,
        ) = AHABContainerBase._parse(data)
        f.seek(signature_block_offset + address + offset)
        signature_block = SignatureBlock.parse(f.read(1024))
        blob = Blob.parse(keyblob_data)
        blob.validate()
        signature_block.update_fields()
        signature_block.validate({})
        if not signature_block.blob:
            raise SPSDKError("AHAB Container must contain BLOB in order to update it")
        if not len(signature_block.blob.export()) == len(blob.export()):
            raise SPSDKError("The size of the BLOB must be same")
        logger.debug(f"AHAB container found at offset {hex(address + offset)}")
        logger.debug(f"New keyblob: \n{blob}")
        logger.debug(f"Old keyblob: \n{signature_block.blob}")
        f.seek(signature_block_offset + address + signature_block._blob_offset + offset)
        f.write(blob.export())
