#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Nxpimage HAB group."""

import os

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, print_files
from spsdk.exceptions import SPSDKError
from spsdk.image.hab.hab_image import HabImage
from spsdk.sbfile.sb2 import sly_bd_parser as bd_parser
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, load_text, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config


@click.group(name="hab", no_args_is_help=True, cls=CommandsTreeGroup)
def hab_group() -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to HAB container."""


@hab_group.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@spsdk_family_option(families=HabImage.get_supported_families())
def hab_get_template_command(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    hab_get_template(output, family)


def hab_get_template(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    write_file(HabImage.get_config_template(family), output)
    click.echo(f"The template file {get_printable_path(output)} has been created.")


@hab_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=HabImage)
@spsdk_output_option(force=True)
def hab_export_command(
    config: Config,
    output: str,
) -> None:
    """Generate HAB container from configuration."""
    image = hab_export(config)
    write_file(image, output, mode="wb")
    click.echo(f"Success. (HAB container: {get_printable_path(output)} created.)")


def hab_export(config: Config) -> bytes:
    """Generate HAB container from configuration."""
    hab = HabImage.load_from_config(config)
    post_export_files = hab.post_export(config.config_dir)
    if post_export_files:
        print_files(post_export_files, title="Performing post export for HAB image.")
    return hab.export()


@hab_group.command(name="convert", no_args_is_help=True)
@click.option(
    "-c",
    "--command",
    type=click.Path(exists=True),
    required=True,
    help="BD configuration file for conversion to YAML",
)
@spsdk_output_option(force=True)
@click.argument("external", type=click.Path(), nargs=-1)
def hab_convert_command(
    command: str,
    output: str,
    external: list[str],
) -> None:
    """Convert BD Configuration to YAML.

    EXTERNAL is a space separated list of external binary files defined in BD file
    """
    configuration = hab_convert(command, external)
    write_file(configuration, output, mode="w")
    click.echo(f"Success. (HAB Configuration converted to YAML: {output})")


def hab_convert(command: str, external: list[str]) -> str:
    """Convert HAB BD configuration to YAML configuration."""
    try:
        parser = bd_parser.BDParser()

        bd_file_content = load_text(command)
        bd_data = parser.parse(text=bd_file_content, extern=external)

        if not bd_data:
            raise SPSDKError("Invalid bd file, generation terminated")

        config = HabImage.transform_configuration(bd_data)

        schemas = HabImage.get_validation_schemas(
            family=FamilyRevision("mimxrt1050")  # Just workaround for HAB
        )
        check_config(bd_data, schemas)
        ret = CommentedConfig(main_title="HAB converted configuration", schemas=schemas).get_config(
            config
        )
        return ret

    except SPSDKError as exc:
        raise SPSDKAppError(f"The conversion failed: ({str(exc)}).") from exc


@hab_group.command(name="parse", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary HAB image to parse.",
)
@spsdk_family_option(families=HabImage.get_supported_families())
@spsdk_output_option(directory=True)
def hab_parse_command(binary: str, family: FamilyRevision, output: str) -> None:
    """Parse HAB container into individual segments."""
    file_bin = load_binary(binary)
    created_files = hab_parse(file_bin, family, output)
    for file_path in created_files:
        click.echo(f"File has been created: {file_path}")
    click.echo(f"Success. (HAB container parsed into: {output}.)")


def hab_parse(binary: bytes, family: FamilyRevision, output: str) -> list[str]:
    """Generate HAB container from configuration."""
    hab_image = HabImage.parse(binary, family)
    generated_bins = []
    for segment in hab_image.segments:
        assert segment.SEGMENT_IDENTIFIER
        seg_out = os.path.join(output, f"{segment.SEGMENT_IDENTIFIER.label}.bin")
        write_file(segment.export(), seg_out, mode="wb")
        generated_bins.append(seg_out)
    return generated_bins
