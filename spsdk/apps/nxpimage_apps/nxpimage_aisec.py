#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK NXP Image AISEC protected-directory container command-line interface."""

import os
from typing import Callable

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, print_verifier_to_console
from spsdk.image.aisec.aisec_dir import AisecDirContainer
from spsdk.image.aisec.aisec_dir_parser import AisecKeys, verify_container_binary
from spsdk.image.aisec.aisec_dir_types import SRKH_SIZE, AisecKeySize
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, write_file

AISEC_CONFIG_FILE_NAME = "aisec_config.yaml"
AISEC_MMK_SIZES = tuple(size.size for size in AisecKeySize)


@click.group(name="aisec", cls=CommandsTreeGroup)
def aisec_group() -> None:
    """Group of sub-commands related to AISEC protected-directory containers."""


def _binary_option(action: str) -> Callable:
    """Click option with the container binary.

    :param action: Action performed with the binary used in the help text.
    :return: Click decorator.
    """
    return click.option(
        "-b",
        "--binary",
        type=click.Path(exists=True, dir_okay=False, resolve_path=True),
        required=True,
        help=f"Path to the AISEC dir-v5 container binary to {action}.",
    )


def _key_options(func: Callable) -> Callable:
    """Click options with the optional MMK and SRKH.

    :param func: Decorated click command.
    :return: Decorated click command.
    """
    func = click.option(
        "--srkh",
        type=str,
        required=False,
        help=(
            f"{SRKH_SIZE}-byte SRK hash binding root of a device-bound container, "
            "as a binary/HEX text file path or a HEX string."
        ),
    )(func)
    return click.option(
        "-k",
        "--mmk",
        type=str,
        required=False,
        help=(
            "Model master key, as a binary/HEX text file path or a HEX string. With the key "
            "the MACs are verified and encrypted members are decrypted; without it only the "
            "structure is verified."
        ),
    )(func)


def _load_key(source: str, name: str, sizes: tuple[int, ...]) -> bytes:
    """Load a key from a binary file, a HEX text file or a HEX string.

    A file whose whole content is a HEX text of an allowed key size is loaded as HEX text,
    otherwise as a binary key. The value is never padded or truncated, its size must be one
    of the allowed sizes.

    :param source: File path or HEX string.
    :param name: Key name used in error messages.
    :param sizes: Allowed key sizes in bytes.
    :raises SPSDKAppError: The key cannot be loaded or has an invalid size.
    :return: Key bytes.
    """
    if os.path.isfile(source):
        key = load_binary(source)
        try:
            text = key.decode("ascii").strip()
            hex_key = bytes.fromhex(text.removeprefix("0x").removeprefix("0X"))
            if len(hex_key) in sizes:
                key = hex_key
        except ValueError:
            pass
    else:
        try:
            key = bytes.fromhex(source.strip().removeprefix("0x").removeprefix("0X"))
        except ValueError as exc:
            raise SPSDKAppError(f"Invalid {name}, neither a file nor a HEX string") from exc
    if len(key) not in sizes:
        expected = " or ".join(str(size) for size in sizes)
        raise SPSDKAppError(f"Invalid {name} size {len(key)} B, expected {expected} B")
    return key


def _load_keys(mmk: str | None, srkh: str | None) -> tuple[bytes | None, bytes | None]:
    """Load the optional key material given on the command line.

    :param mmk: MMK as a file path or HEX string.
    :param srkh: SRKH as a file path or HEX string.
    :raises SPSDKAppError: The SRKH is given without the MMK.
    :return: Tuple of the MMK and SRKH.
    """
    if srkh and not mmk:
        raise SPSDKAppError("The SRKH is used only together with the MMK")
    mmk_data = _load_key(mmk, "MMK", AISEC_MMK_SIZES) if mmk else None
    srkh_data = _load_key(srkh, "SRKH", (SRKH_SIZE,)) if srkh else None
    return mmk_data, srkh_data


@aisec_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=AisecDirContainer)
def aisec_export_command(config: Config) -> None:
    """Generate an AISEC dir-v5 container from YAML/JSON configuration."""
    aisec_export(config)


def aisec_export(config: Config) -> None:
    """Generate an AISEC dir-v5 container from YAML/JSON configuration.

    :param config: AISEC container configuration.
    """
    container = AisecDirContainer.load_from_config(config)
    output = config.get_output_file_name("output")
    write_file(container.export(), output, mode="wb")
    click.echo(str(container))
    click.echo(f"Success. (AISEC container: {get_printable_path(output)} created.)")


@aisec_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=AisecDirContainer.get_supported_families())
@_binary_option("parse")
@_key_options
@spsdk_output_option(directory=True)
def aisec_parse_command(
    family: FamilyRevision, binary: str, mmk: str | None, srkh: str | None, output: str
) -> None:
    """Parse an AISEC dir-v5 container into YAML configuration and member files."""
    aisec_parse(family, binary, mmk, srkh, output)


def aisec_parse(
    family: FamilyRevision, binary: str, mmk: str | None, srkh: str | None, output: str
) -> None:
    """Parse an AISEC dir-v5 container into YAML configuration and member files.

    :param family: Target family.
    :param binary: Path to the container binary.
    :param mmk: Optional MMK as a file path or HEX string.
    :param srkh: Optional SRKH as a file path or HEX string.
    :param output: Output directory.
    """
    mmk_data, srkh_data = _load_keys(mmk, srkh)
    container = AisecDirContainer.parse(
        load_binary(binary), family=family, mmk=mmk_data, srkh=srkh_data
    )
    config_file = os.path.join(output, AISEC_CONFIG_FILE_NAME)
    write_file(container.get_config_yaml(output), config_file)
    click.echo(
        f"Success. (AISEC container: {get_printable_path(binary)} has been parsed and stored "
        f"into {get_printable_path(output)}.)"
    )
    locked = container.locked_members
    if locked:
        click.echo(
            "Encrypted members not decrypted (MMK not given), their data files are not "
            "stored and the configuration cannot be used to rebuild the container:"
        )
        for name in locked:
            click.echo(f"  - {name}")
        click.echo("Parse the container with the MMK (-k) to recover them.")
    else:
        click.echo("The MMK is not stored, provide it as 'mmk.bin' to rebuild the container.")


@aisec_group.command(name="verify", no_args_is_help=True)
@_binary_option("verify")
@_key_options
@click.option(
    "-p",
    "--problems",
    is_flag=True,
    default=False,
    help="Show just problems in the container.",
)
def aisec_verify_command(binary: str, mmk: str | None, srkh: str | None, problems: bool) -> None:
    """Verify an AISEC dir-v5 container."""
    aisec_verify(binary, mmk, srkh, problems)


def aisec_verify(binary: str, mmk: str | None, srkh: str | None, problems: bool) -> None:
    """Verify an AISEC dir-v5 container.

    :param binary: Path to the container binary.
    :param mmk: Optional MMK as a file path or HEX string.
    :param srkh: Optional SRKH as a file path or HEX string.
    :param problems: Show just problems in the container.
    :raises SPSDKAppError: The verification failed.
    """
    mmk_data, srkh_data = _load_keys(mmk, srkh)
    keys = AisecKeys(mmk=mmk_data, srkh=srkh_data) if mmk_data else None
    ver = verify_container_binary(load_binary(binary), keys)
    print_verifier_to_console(ver, problems=problems)
    if ver.has_errors:
        raise SPSDKAppError("Verify failed")


@aisec_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=AisecDirContainer.get_supported_families())
@spsdk_output_option(force=True)
def aisec_get_template_command(family: FamilyRevision, output: str) -> None:
    """Create template of AISEC container configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    aisec_get_template(family, output)


def aisec_get_template(family: FamilyRevision, output: str) -> None:
    """Create template of AISEC container configuration in YAML format.

    :param family: Target family.
    :param output: Output template file.
    """
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(AisecDirContainer.get_config_template(family), output)
