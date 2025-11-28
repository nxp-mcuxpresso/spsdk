#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK blhost application helper utilities.

This module provides helper classes and functions to support the blhost
application, including property tag parsing, key type parsing for various
provisioning operations, and output display utilities.
"""

import inspect
import json
from typing import Any, Optional, Type

import click

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import (
    KeyProvUserKeyType,
    TrustProvKeyType,
    TrustProvOemKeyType,
    TrustProvWrappingKeyType,
)
from spsdk.mboot.error_codes import stringify_status_code
from spsdk.mboot.properties import PropertyTag, get_property_index
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum


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


def parse_property_tag(property_tag: str, family: Optional[FamilyRevision] = None) -> int:
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
    user_input: str, collection: Type[SpsdkEnum], default: Optional[int] = None
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
    response: Optional[list] = None,
    status_code: int = 0,
    use_json: bool = False,
    suppress: bool = False,
    extra_output: Optional[str] = None,
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
        raise SPSDKAppError()
