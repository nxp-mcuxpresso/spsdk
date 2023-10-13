#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB utils module."""
import logging

from spsdk.apps.utils.utils import SPSDKError
from spsdk.image.ahab.ahab_container import AHABContainerBase, AHABImage, Blob, SignatureBlock
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


def ahab_update_keyblob(family: str, binary: str, keyblob: str, container_id: int) -> None:
    """Update keyblob in AHAB image.

    :param family: MCU family
    :param binary: Path to AHAB image binary
    :param keyblob: Path to keyblob
    :param container_id: Index of the container to be updated
    :raises SPSDKError: In case the container id not present
    :raises SPSDKError: In case the AHAB image does not contain blob
    :raises SPSDKError: In case the length of keyblobs don't match
    """
    keyblob_data = load_binary(keyblob)
    image = AHABImage(family)

    try:
        address = image.ahab_address_map[container_id]
    except IndexError as exc:
        raise SPSDKError(f"No container ID {container_id}") from exc

    with open(binary, "r+b") as f:
        f.seek(address)
        data = f.read(1024)
        (
            _,
            _,
            _,
            _,
            signature_block_offset,
        ) = AHABContainerBase._parse(data)
        f.seek(signature_block_offset + address)
        signature_block = SignatureBlock.parse(f.read(1024))
        blob = Blob.parse(keyblob_data)
        blob.validate()
        logger.debug(f"New keyblob: \n{blob}")
        signature_block.update_fields()
        signature_block.validate({})
        if not signature_block.blob:
            raise SPSDKError("AHAB Container must contain BLOB in order to update it")
        if not len(signature_block.blob.export()) == len(blob.export()):
            raise SPSDKError("The size of the BLOB must be same")
        logger.debug(f"Old keyblob: \n{signature_block.blob}")
        f.seek(signature_block_offset + address + signature_block._blob_offset)
        f.write(blob.export())
