#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for WPC operations."""


import logging
import os
import sys
from typing import Callable, List, Optional, Tuple

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.utils.misc import load_configuration, write_file
from spsdk.wpc.utils import (
    WPCCertificateService,
    WPCTarget,
    check_main_config,
    generate_template_config,
)

services = WPCCertificateService.get_providers()
targets = WPCTarget.get_providers()


def service_type_option(required: bool = True) -> Callable:
    """Service type click option.

    Provides: `service-type: str` a name of the service adapter.
    """

    def decorator(options: FC) -> FC:
        options = click.option(
            "-st",
            "--service-type",
            type=click.Choice(list(services.keys())),
            required=required,
            help="Name of the WPC service type.",
        )(options)
        return options

    return decorator


def target_type_option(required: bool = True) -> Callable:
    """Target type click decorator.

    Provides: `target_type: str` a name of target adapter.s
    """

    def decorator(options: FC) -> FC:
        options = click.option(
            "-tt",
            "--target-type",
            type=click.Choice(list(targets.keys())),
            required=required,
            help="Name of the MCU target type.",
        )(options)
        return options

    return decorator


def update_config(config_data: dict, name: str, values: Tuple[str]) -> dict:
    """Parse string with coma-separated key-pairs into a dictionary."""
    if not values:
        return config_data
    try:
        if name not in config_data:
            config_data[name] = {}
        for param in values:
            key, value = param.split("=")
            config_data[name][key] = value
        return config_data
    except Exception as e:
        raise SPSDKAppError(f"Unable to parse parameters: '{values}'") from e


@click.group(name="nxpwpc", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """Utility covering WPC operations."""
    spsdk_logger.install(level=log_level or logging.WARNING)


@main.command(name="insert-cert", no_args_is_help=True)
@service_type_option(required=False)
@click.option(
    "-sp",
    "--service-parameters",
    type=str,
    multiple=True,
    help="'key=value' to set/override a service adapter setting. Can be used multiple times.",
)
@target_type_option(required=False)
@click.option(
    "-tp",
    "--target-parameters",
    type=str,
    multiple=True,
    help="'key=value' to set/override a service adapter setting. Can be used multiple times.",
)
@spsdk_config_option(required=False)
@click.option(
    "-s",
    "--save-debug-data",
    is_flag=True,
    default=False,
    help="Save the data being transferred (for debugging purposes).",
)
def insert_cert(
    service_type: str,
    service_parameters: Tuple[str],
    target_type: str,
    target_parameters: Tuple[str],
    config: str,
    save_debug_data: bool,
) -> None:
    """Perform full WPC Cert chain flow.

    \b
      - Retrieve WPC ID from the target
      - Generate WPC cert chain on service
      - Insert WPC certificate into the target.

    Parameters for target and service may be passed using "-tp" or "-sp" options respectively,
    or via a config file ("-c"). The config file template can be generated using "get-template" command.
    """
    config_data = load_configuration(config) if config else {}
    config_data = update_config(config_data, "service_parameters", service_parameters)
    config_data = update_config(config_data, "target_parameters", target_parameters)
    if target_type:
        config_data["target_type"] = target_type
    if service_type:
        config_data["service_type"] = service_type
    search_paths: Optional[List[str]] = None
    if config:
        search_paths = [os.path.dirname(os.path.abspath(config))]
    check_main_config(config_data=config_data, search_paths=search_paths)

    target_cls = targets[config_data["target_type"]]
    target = target_cls.from_config(config_data=config_data, search_paths=search_paths)

    service_cls = services[config_data["service_type"]]
    service = service_cls.from_config(config_data=config_data, search_paths=search_paths)

    wpc_id_data = target.get_wpc_id()
    if save_debug_data:
        write_file(wpc_id_data, "x_csr.pem")
    wpc_cert = service.get_wpc_cert(wpc_id_data=wpc_id_data)
    if save_debug_data:
        wpc_cert.save(chain_path="x_cert_chain.bin")
    target.wpc_insert_cert(wpc_cert)
    click.echo("Inserting WPC certificate finished successfully.")


@main.command(name="get-template", no_args_is_help=True)
@service_type_option(required=True)
@target_type_option(required=True)
@spsdk_family_option(families=WPCTarget.get_supported_families())
@spsdk_output_option(force=True)
def get_template(service_type: str, target_type: str, family: str, output: str) -> None:
    """Generate a configuration template."""
    template = generate_template_config(
        family=family, service=services[service_type], target=targets[target_type]
    )
    write_file(template, output)
    click.echo(f"Creating {output} template file.")


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
