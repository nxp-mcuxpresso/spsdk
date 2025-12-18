#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Command-line interface for HSE (Hardware Security Engine) related functionality.

This module provides CLI commands for working with HSE features, including:
- Key information management (creating templates, exporting key info)
- Other HSE-specific operations

The commands are organized in a hierarchical structure with 'hse' as the main group.
"""
import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.image.hse.key_catalog import KeyCatalogCfg
from spsdk.image.hse.key_info import KeyInfo
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, write_file
from spsdk.utils.schema_validator import CommentedConfig


@click.group(name="hse", no_args_is_help=True, cls=CommandsTreeGroup)
def hse_group() -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to HSE (Hardware Security Engine)."""


@hse_group.group(name="key-info", no_args_is_help=True, cls=CommandsTreeGroup)
def key_info_group() -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to key import functionality."""


@key_info_group.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@spsdk_family_option(families=KeyInfo.get_supported_families())
def key_info_get_template_command(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    key_info_get_template(output, family)


def key_info_get_template(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    write_file(KeyInfo.get_config_template(family), output)
    click.echo(f"The template file {get_printable_path(output)} has been created.")


@key_info_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=KeyInfo)
def key_info_export_command(config: Config) -> None:
    """Create template of configuration in YAML format."""
    key_info_export(config)


def key_info_export(config: Config) -> None:
    """Generate Key Info binary from YAML/JSON configuration.

    :param config: Path to the YAML/JSON configuration
    """
    key_info = KeyInfo.load_from_config(config)
    key_info_data = key_info.export()
    output_file_path = config.get_output_file_name("output")
    write_file(key_info_data, output_file_path, mode="wb")
    click.echo(f"Success. (Key Info: {get_printable_path(output_file_path)} created.)")


@key_info_group.command(name="parse", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary with key info.",
)
@spsdk_family_option(families=KeyInfo.get_supported_families())
@spsdk_output_option()
def key_info_parse_command(binary: str, family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format."""
    data = load_binary(binary)
    key_info = KeyInfo.parse(data, family)
    cfg = key_info.get_config(data_path=output)
    yaml_data = CommentedConfig(
        main_title=("Key info configuration:"),
        schemas=key_info.get_validation_schemas(family),
    ).get_config(cfg)

    write_file(yaml_data, output)

    click.echo(f"Success. (Key Info: {binary} has been parsed and stored into {output} )")


def key_info_parse(config: Config) -> None:
    """Generate Key Info binary from YAML/JSON configuration.

    :param config: Path to the YAML/JSON configuration
    """
    key_info = KeyInfo.load_from_config(config)
    key_info_data = key_info.export()
    output_file_path = config.get_output_file_name("output")
    write_file(key_info_data, output_file_path, mode="wb")
    click.echo(f"Success. (Key Info: {get_printable_path(output_file_path)} created.)")


@hse_group.group(name="key-catalog", no_args_is_help=True, cls=CommandsTreeGroup)
def key_catalog_group() -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to key catalog functionality."""


@key_catalog_group.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@spsdk_family_option(families=KeyCatalogCfg.get_supported_families())
def key_catalog_get_template_command(output: str, family: FamilyRevision) -> None:
    """Create template of key catalog configuration in YAML format."""
    key_catalog_get_template(output, family)


def key_catalog_get_template(output: str, family: FamilyRevision) -> None:
    """Create template of key catalog configuration in YAML format.

    :param output: Path to the output template file
    :param family: Family revision
    """
    write_file(KeyCatalogCfg.get_config_template(family), output)
    click.echo(f"The template file {get_printable_path(output)} has been created.")


@key_catalog_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=KeyCatalogCfg)
def key_catalog_export_command(config: Config) -> None:
    """Create Key Catalog binary from YAML/JSON configuration."""
    key_catalog_export(config)


def key_catalog_export(config: Config) -> None:
    """Generate Key Catalog binary from YAML/JSON configuration.

    :param config: Path to the YAML/JSON configuration
    """
    key_catalog = KeyCatalogCfg.load_from_config(config)
    key_catalog_data = key_catalog.export()
    output_file_path = config.get_output_file_name("output")
    write_file(key_catalog_data, output_file_path, mode="wb")
    click.echo(f"Success. (Key Catalog: {get_printable_path(output_file_path)} created.)")


@key_catalog_group.command(name="parse", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary with key catalog cfg.",
)
@spsdk_family_option(families=KeyCatalogCfg.get_supported_families())
@spsdk_output_option()
def key_catalog_parse_command(binary: str, family: FamilyRevision, output: str) -> None:
    """Parse a binary key catalog file and display its contents."""
    data = load_binary(binary)
    key_catalog = KeyCatalogCfg.parse(data, family)
    cfg = key_catalog.get_config(data_path=output)
    yaml_data = CommentedConfig(
        main_title=("Key catalog configuration:"),
        schemas=key_catalog.get_validation_schemas(family),
    ).get_config(cfg)

    write_file(yaml_data, output)

    click.echo(f"Success. (Key Catalog cfg: {binary} has been parsed and stored into {output} )")
