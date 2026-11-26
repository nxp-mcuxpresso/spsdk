#!/usr/bin/env python
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK blhost application helper utilities.

This module provides helper classes and functions to support the blhost
application, including property tag parsing, key type parsing for various
provisioning operations, and output display utilities.
"""

import contextlib
import inspect
import json
from collections.abc import Callable, Iterator
from typing import Any

import click

from spsdk import get_logger
from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import (
    KeyProvUserKeyType,
    TrustProvKeyType,
    TrustProvOemKeyType,
    TrustProvWrappingKeyType,
)
from spsdk.mboot.error_codes import stringify_status_code
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import ExternalMemoryAttributesValue, PropertyTag, get_property_index
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align, size_fmt, value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = get_logger(__name__)

# Fallback erase block alignment used when the target does not report its sector size.
DEFAULT_ERASE_ALIGNMENT = 1024
# Assumed worst-case flash throughput used for the automatic timeout estimation [bytes/second].
# Deliberately pessimistic to cover slow external memories and large erase blocks.
ASSUMED_FLASH_THROUGHPUT = 32 * 1024
# Upper limit of the flash-erase-region commands used to erase a single region when the
# progress has to be reported. Keeps the command overhead negligible even for large memories.
MAX_ERASE_PROGRESS_STEPS = 100
# Regions up to this size are erased by a single flash-erase-region command. Such an erase is
# short enough that reporting its progress brings no value and would only add command overhead.
MIN_ERASE_PROGRESS_LENGTH = ASSUMED_FLASH_THROUGHPUT


class OemGenMasterShareHelp(click.Command):
    """Custom Click command for OEM master share generation help display.

    This class extends Click's Command class to provide a customized usage help
    format specifically for the blhost trust-provisioning oem_gen_master_share
    command, displaying all required memory address and size parameters in a
    structured format.
    """

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
    """Custom Click command for OEM master share operations help display.

    This class extends Click's Command class to provide customized usage help
    formatting specifically for the oem_set_master_share command in blhost
    trust provisioning operations.
    """

    def format_usage(self, ctx: Any, formatter: Any) -> None:
        """Customizes "usage" help line for oem_set_master_share command."""
        click.echo("Usage: blhost trust-provisioning oem_set_master_share [OPTIONS]")
        indent = 7 * "\t"
        click.echo(indent + "OEM_SHARE_INPUT_ADDR")
        click.echo(indent + "OEM_SHARE_INPUT_SIZE")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_INPUT_ADDR")
        click.echo(indent + "OEM_ENC_MASTER_SHARE_INPUT_SIZE")


def parse_property_tag(property_tag: str, family: FamilyRevision | None = None) -> int:
    """Convert the property as name or stringified number into integer.

    :param property_tag: Name or number of the property tag
    :param family: supported family
    :return: Property integer tag
    """
    try:
        return value_to_int(property_tag)
    except SPSDKError:
        pass
    try:
        prop = PropertyTag.from_name(property_tag)
        return get_property_index(prop, family)
    except SPSDKError:
        return get_property_index(PropertyTag.UNKNOWN, family)


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


def _parse_key_type(
    user_input: str, collection: type[SpsdkEnum], default: int | None = None
) -> int:
    try:
        return value_to_int(user_input)
    except SPSDKError:
        key_type = user_input.upper()
        key_type_int = collection.get_tag(key_type) if collection.contains(key_type) else default
        if key_type_int is None:
            raise SPSDKError(  # pylint: disable=raise-missing-from
                f"Unable to find '{user_input}' in '{collection.__name__}'"
            )
        return key_type_int


def display_output(
    response: list | None = None,
    status_code: int = 0,
    use_json: bool = False,
    suppress: bool = False,
    extra_output: str | None = None,
) -> None:
    """Displays response and status code.

    :param response: Response from the MBoot function
    :param status_code: MBoot status code
    :param use_json: Format the output in JSON format, defaults to False
    :param suppress: Suppress display
    :param extra_output: Extra string to print out, defaults to None
    :raises SPSDKAppError: Command is executed properly, how MBoot status code is non-zero
    """
    if suppress:
        pass
    elif use_json:
        data = {
            # get the name of a caller function and replace _ with -
            "command": inspect.stack()[1].function.replace("_", "-"),
            # this is just a visualization thing
            "response": response or [],
            "status": {
                "description": stringify_status_code(status_code),
                "value": status_code,
            },
        }
        print(json.dumps(data, indent=3))
    else:
        print(f"Response status = {stringify_status_code(status_code)}")
        if isinstance(response, list):
            filtered_response = filter(lambda x: x is not None, response)
            for i, word in enumerate(filtered_response):
                print(f"Response word {i + 1} = {word} ({word:#x})")
        if extra_output:
            print(extra_output)
    # Force exit to handover the current status code.
    # We could do that because this function is called as last from each subcommand
    if status_code:
        raise SPSDKAppError(stringify_status_code(status_code))


def get_erase_alignment(mboot: McuBoot, mem_id: int = 0) -> int:
    """Get the erase block alignment reported by the connected target.

    The erase granularity of the target is read from the device properties so that
    `flash-erase-region` is always invoked with an address and length aligned to a whole
    erase block. For internal flash (``mem_id`` 0) the ``FlashSectorSize`` property is used,
    for external memories the sector size from ``ExternalMemoryAttributes`` is used.
    When the target does not report the value, :data:`DEFAULT_ERASE_ALIGNMENT` is returned.

    :param mboot: Opened McuBoot instance used for the property queries.
    :param mem_id: Memory identifier, 0 for internal flash, defaults to 0.
    :return: Erase block size in bytes to be used as an alignment.
    """
    alignment: int | None = None
    try:
        if mem_id:
            values = mboot.get_property(PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, index=mem_id)
            if values:
                alignment = ExternalMemoryAttributesValue(
                    PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, values, mem_id=mem_id
                ).sector_size
        else:
            values = mboot.get_property(PropertyTag.FLASH_SECTOR_SIZE)
            if values:
                alignment = values[0]
    except SPSDKError as exc:
        logger.debug(f"Unable to read the erase block size from the target: {exc}")

    if not alignment:
        logger.debug(
            "The target does not report its erase block size, "
            f"using the default alignment of {size_fmt(DEFAULT_ERASE_ALIGNMENT)}."
        )
        return DEFAULT_ERASE_ALIGNMENT

    logger.info(f"Using the erase block alignment reported by the target: {size_fmt(alignment)}")
    return alignment


def estimate_flash_timeout(length: int, base_timeout: int) -> int:
    """Estimate a communication timeout sufficient for a flash erase or write operation.

    Erasing or writing large memory areas may take much longer than the default command
    timeout, which results in a false 'No response' error. The estimation assumes a
    pessimistic flash throughput of :data:`ASSUMED_FLASH_THROUGHPUT` and never returns a value
    lower than the given base timeout.

    :param length: Number of bytes to be erased or written.
    :param base_timeout: Timeout currently configured on the device in milliseconds.
    :return: Estimated timeout in milliseconds.
    """
    estimated = int(length / ASSUMED_FLASH_THROUGHPUT * 1000)
    return max(base_timeout, estimated)


@contextlib.contextmanager
def flash_operation_timeout(mboot: McuBoot, length: int) -> Iterator[None]:
    """Temporarily increase the device timeout for a long lasting flash operation.

    The timeout is derived from the amount of data to be processed, see
    :func:`estimate_flash_timeout`. The original timeout is restored when the context
    is left, even if the operation fails. Devices not supporting the timeout
    reconfiguration are silently skipped.

    :param mboot: Opened McuBoot instance whose device timeout is adjusted.
    :param length: Number of bytes to be erased or written.
    """
    device = mboot.interface.device
    try:
        original_timeout = device.timeout
    except (AttributeError, NotImplementedError):
        logger.debug("The interface does not support the timeout reconfiguration.")
        yield
        return

    new_timeout = estimate_flash_timeout(length, original_timeout)
    if new_timeout == original_timeout:
        yield
        return

    logger.info(
        f"Increasing the communication timeout from {original_timeout} ms to {new_timeout} ms "
        f"for an operation on {size_fmt(length)}."
    )
    device.timeout = new_timeout
    try:
        yield
    finally:
        device.timeout = original_timeout
        logger.debug(f"Restoring the communication timeout to {original_timeout} ms.")


def get_erase_chunk_size(length: int, alignment: int) -> int:
    """Compute the size of a single erase step used to report the erase progress.

    The bootloader does not report any progress during `flash-erase-region`, so the region
    has to be split into several commands to be able to update the progress bar. The chunk
    size is a whole multiple of the erase block, so no block is ever erased twice, and the
    region is split into at most :data:`MAX_ERASE_PROGRESS_STEPS` commands to keep the
    command overhead negligible even for large memories. Regions up to
    :data:`MIN_ERASE_PROGRESS_LENGTH` are erased by a single command, as splitting such a
    short operation would only add overhead without any benefit for the user.

    :param length: Total number of bytes to be erased, aligned to the erase block size.
    :param alignment: Erase block size in bytes.
    :return: Chunk size in bytes, always at least one erase block.
    """
    if length <= 0 or alignment <= 0:
        return max(alignment, 1)
    if length <= MIN_ERASE_PROGRESS_LENGTH:
        return length
    return max(alignment, align(length // MAX_ERASE_PROGRESS_STEPS, alignment))


def flash_erase_region_with_progress(
    mboot: McuBoot,
    address: int,
    length: int,
    alignment: int,
    mem_id: int = 0,
    progress_callback: Callable[[int, int], None] | None = None,
) -> bool:
    """Erase a flash region and report the progress of the operation.

    Erasing a large region may take minutes, so the region is split into several
    `flash-erase-region` commands, see :func:`get_erase_chunk_size`, and the progress
    callback is invoked after each erased chunk. The communication timeout is increased
    for every chunk according to its size. The erase is aborted as soon as a command fails.

    :param mboot: Opened McuBoot instance used to erase the memory.
    :param address: Start address of the region, must be aligned to the erase block size.
    :param length: Number of bytes to erase, must be aligned to the erase block size.
    :param alignment: Erase block size in bytes.
    :param mem_id: Memory identifier, 0 for internal flash, defaults to 0.
    :param progress_callback: Optional callback invoked with (erased_bytes, total_bytes).
    :return: True if the whole region was erased successfully, False otherwise.
    """
    chunk_size = get_erase_chunk_size(length, alignment)
    erased = 0
    while erased < length:
        chunk = min(chunk_size, length - erased)
        with flash_operation_timeout(mboot, chunk):
            if not mboot.flash_erase_region(address=address + erased, length=chunk, mem_id=mem_id):
                return False
        erased += chunk
        if progress_callback:
            progress_callback(erased, length)
    return True
