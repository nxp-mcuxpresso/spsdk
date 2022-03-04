#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module for blhost application."""

import contextlib
import math
from typing import Any, Callable, Iterator, List, Union

import bincopy
import click

from spsdk import SPSDKError
from spsdk.mboot.commands import (
    KeyProvUserKeyType,
    TrustProvKeyType,
    TrustProvOemKeyType,
    TrustProvWrappingKeyType,
)
from spsdk.utils.misc import value_to_int


class OemGenMasterShareHelp(click.Command):
    """Class for customized "usage" help line for oem_gen_master_share command."""

    def format_usage(self, ctx: Any, formatter: Any) -> None:
        """Customizes "usage" help line for oem_gen_master_share command."""
        click.echo("Usage: blhost trust-provisioning oem_gen_master_share [OPTIONS]")
        indent = 7 * "\t"
        click.echo(indent + "OEM_SHARE_INPUT_ADDR")
        click.echo(indent + "OEM_SHARE_INPUT_SIZE")
        click.echo(indent + "OEM_ENC_SHARE_OUTPUT_ADDR")
        click.echo(indent + "OEM_ENC_SHARE_OUTPUT_SIZE")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_OUTPUT_ADDR")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_OUTPUT_SIZE")
        click.echo(indent + "OEM_CUST_CERT_PUK_OUTPUT_ADDR")
        click.echo(indent + "OEM_CUST_CERT_PUK_OUTPUT_SIZE")


class OemSetMasterShareHelp(click.Command):
    """Class for customized "usage" help line for oem_set_master_share command."""

    def format_usage(self, ctx: Any, formatter: Any) -> None:
        """Customizes "usage" help line for oem_set_master_share command."""
        click.echo("Usage: blhost trust-provisioning oem_set_master_share [OPTIONS]")
        indent = 7 * "\t"
        click.echo(indent + "OEM_SHARE_INPUT_ADDR")
        click.echo(indent + "OEM_SHARE_INPUT_SIZE")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_INPUT_ADDR")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_INPUT_SIZE")


PROPERTIES_NAMES = {
    "list-properties": 0,
    "current-version": 1,
    "available-peripherals": 2,
    "flash-start-address": 3,
    "flash-size-in-bytes": 4,
    "flash-sector-size": 5,
    "flash-block-count": 6,
    "available-commands": 7,
    "check-status": 8,
    "reserved": 9,
    "verify-writes": 10,
    "max-packet-size": 11,
    "reserved-regions": 12,
    "reserved_1": 13,
    "ram-start-address": 14,
    "ram-size-in-bytes": 15,
    "system-device-id": 16,
    "security-state": 17,
    "unique-device-id": 18,
    "flash-fac-support": 19,
    "flash-access-segment-size": 20,
    "flash-access-segment-count": 21,
    "flash-read-margin": 22,
    "qspi/otfad-init-status": 23,
    "target-version": 24,
    "external-memory-attributes": 25,
    "reliable-update-status": 26,
    "flash-page-size": 27,
    "irq-notify-pin": 28,
    "pfr-keystore_update-opt": 29,
    "byte-write-timeout-ms": 30,
}


def parse_property_tag(property_tag: str) -> int:
    """Convert the property as name or stringified number into integer.

    :param property_tag: Name or number of the property tag
    :return: Property integer tag
    """
    try:
        value = value_to_int(property_tag)
        return value if value in PROPERTIES_NAMES.values() else 0xFF
    except SPSDKError:
        return PROPERTIES_NAMES.get(property_tag, 0xFF)


def parse_key_prov_key_type(key_type: str) -> int:
    """Convert the key type as name or stringified number into integer.

    :param key_type: Name or number of the Key type
    :return: key type number
    """
    return _parse_key_type(key_type, KeyProvUserKeyType, 0xFF)


def parse_trust_prov_oem_key_type(key_type: str) -> int:
    """Convert the key type as name or stringified number into integer.

    :param key_type: Name or number of the Key type
    :return: key type number
    """
    return _parse_key_type(key_type, TrustProvOemKeyType)


def parse_trust_prov_key_type(key_type: str) -> int:
    """Convert the key type as name or stringified number into integer.

    :param key_type: Name or number of the Key type
    :return: key type number
    """
    return _parse_key_type(key_type, TrustProvKeyType)


def parse_trust_prov_wrapping_key_type(key_type: str) -> int:
    """Convert the key type as name or stringified number into integer.

    :param key_type: Name or number of the Key type
    :return: key type number
    """
    return _parse_key_type(key_type, TrustProvWrappingKeyType)


def _parse_key_type(user_input: str, collection: Any, default: int = None) -> int:
    try:
        return value_to_int(user_input)
    except SPSDKError:
        key_type = user_input.upper()
        key_type_int = collection.get(key_type, default)
        if key_type_int is None:
            raise SPSDKError(  # pylint: disable=raise-missing-from
                f"Unable to find '{user_input}' in '{collection.__name__}'"
            )
        return key_type_int


class SegmentInfo:
    """SegmentInfo class containing: start, length and data of segment."""

    ALIGNMENT = 1024

    def __init__(self, start: int, length: int, data_bin: bytes) -> None:
        """Initialize the SegmentInfo object.

        :param start: start address of segment
        :param length: length of segment
        :param data_bin: binary data in segment
        """
        self.start = start
        self.length = length
        self.data_bin = data_bin

    @property
    def aligned_start(self) -> int:
        """Returns aligned start address for erasing purposes."""
        return math.floor(self.start / self.ALIGNMENT) * self.ALIGNMENT

    @property
    def aligned_length(self) -> int:
        """Returns aligned length for erasing purposes."""
        end_address = self.start + self.length
        aligned_end = math.ceil(end_address / self.ALIGNMENT) * self.ALIGNMENT
        aligned_len = aligned_end - self.aligned_start
        return aligned_len


def parse_image_file(file_path: str) -> List[SegmentInfo]:
    """Parse image.

    :param file_path: path, where the image is stored
    :raises SPSDKError: When elf/axf files are used
    :raises SPSDKError: When binary file is used
    :raises SPSDKError: When unsupported file is used
    :return: SegmentInfo object
    """
    with open(file_path, "rb") as f:
        data = f.read(4)
    if data == b"\x7fELF":
        raise SPSDKError("Elf file is not supported")
    try:
        binfile = bincopy.BinFile(file_path)
        return [
            SegmentInfo(start=segment.address, length=len(segment.data), data_bin=segment.data)
            for segment in binfile.segments
        ]
    except UnicodeDecodeError as e:
        raise SPSDKError(
            "Error: please use write-memory command for binary file downloading."
        ) from e
    except Exception as e:
        raise SPSDKError("Error loading file") from e


@contextlib.contextmanager
def progress_bar(
    suppress: bool = False, **progress_bar_params: Union[str, int]
) -> Iterator[Callable[[int, int], None]]:
    """Creates a progress bar and return callback function for updating the progress bar.

    :param suppress: Suppress the progress bar creation; return an empty callback, defaults to False
    :param **progress_bar_params: Standard parameters for click.progressbar
    :yield: Callback for updating the progess bar
    """
    if suppress:
        yield lambda _x, _y: None
    else:
        with click.progressbar(length=100, **progress_bar_params) as p_bar:

            def progress(step: int, total_steps: int) -> None:
                per_step = 100 / total_steps
                increment = step * per_step - p_bar.pos
                p_bar.update(increment)

            yield progress
