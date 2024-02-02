#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SB file."""

import logging
import os
import sys

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    isp_interfaces,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, catch_spsdk_error
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.mboot.scanner import get_mboot_interface
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.devhsm.utils import get_devhsm_class
from spsdk.utils.misc import load_configuration, write_file

logger = logging.getLogger(__name__)


@click.group(name="nxpdevhsm", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Nxpdevhsm application is designed to create SB3 provisioning file for initial provisioning of device by OEM."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(no_args_is_help=True)
@isp_interfaces(uart=True, usb=True, sdio=True, lpcusbsio=True, buspal=True, json_option=False)
@spsdk_family_option(families=DevHsm.get_supported_families())
@click.option(
    "-k",
    "--key",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=False,
    help="""Customer Master Key Symmetric Key secret file (32-bytes long binary file).
    CUST_MK_SK (provisioned by OEM, known by OEM).
    This is a 256-bit pre-shared AES key provisioned by OEM. CUST_MK_SK is used to derive FW image encryption keys.""",
)
@click.option(
    "-i",
    "--oem-share-input",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="OEM share input file to use as a seed to randomize the provisioning process (16-bytes long binary file).",
)
@click.option(
    "-w",
    "--workspace",
    type=click.Path(file_okay=False),
    required=False,
    help="Workspace folder to store temporary files, that could be used for future review.",
)
@click.option(
    "-ir/-IR",
    "--initial-reset/--no-init-reset",
    default=False,
    help=(
        "Reset device BEFORE DevHSM operation. The DevHSM operation can run only once between resets. "
        "Do not enable this option on Linux/Mac when using USB. By default this reset is DISABLED."
    ),
)
@click.option(
    "-fr/-FR",
    "--final-reset/--no-final-reset",
    default=True,
    help=(
        "Reset device AFTER DevHSM operation. This reset is required if you need to use the device "
        "after DevHSM operation for other security related operations (e.g. receive-sb-file). "
        "By default this reset is ENABLED."
    ),
)
@click.option(
    "-ba",
    "--buffer-address",
    type=INT(),
    help="Override the communication buffer base address. The default address is family-specific.",
)
@spsdk_output_option(required=False)
@spsdk_config_option(required=False)
def generate(
    port: str,
    usb: str,
    sdio: str,
    buspal: str,
    lpcusbsio: str,
    oem_share_input: str,
    key: str,
    output: str,
    workspace: str,
    config: str,
    timeout: int,
    family: str,
    initial_reset: bool,
    final_reset: bool,
    buffer_address: int,
) -> None:
    """Generate provisioning SB file."""
    interface = get_mboot_interface(
        port=port, usb=usb, lpcusbsio=lpcusbsio, timeout=timeout, buspal=buspal, sdio=sdio
    )
    assert isinstance(interface, MbootProtocolBase)

    oem_share_in = DevHsm.get_oem_share_input(oem_share_input)
    cust_mk_sk = DevHsm.get_cust_mk_sk(key) if key else None
    family_from_cfg = None
    out_file = None

    if config:
        cfg_dict = load_configuration(config)
        family_from_cfg = cfg_dict.get("family")
        if not isinstance(family_from_cfg, str):
            raise SPSDKError("Family parameter is not provided in the container configuration")
        out_file = cfg_dict.get("containerOutputFile")

    if (family and config) and (family != family_from_cfg):
        raise SPSDKError(
            f"Family from json configuration file: {family_from_cfg} differs from the family parameter {family}"
        )

    if output:
        out_file = output
    if not out_file:
        raise SPSDKError("Output file was not provided")

    devhsm_cls = get_devhsm_class(family)
    with McuBoot(interface) as mboot:
        devhsm = devhsm_cls(
            mboot=mboot,
            cust_mk_sk=cust_mk_sk,
            oem_share_input=oem_share_in,
            info_print=click.echo,
            container_conf=config,
            workspace=workspace,
            family=family,
            initial_reset=initial_reset,
            final_reset=final_reset,
            buffer_address=buffer_address,
        )
        devhsm.create_sb()
        write_file(devhsm.export(), out_file, "wb")

    click.echo(f"Final SB file has been written: {os.path.abspath(out_file)}")


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=DevHsm.get_supported_families())
@spsdk_output_option(force=True)
def get_template_command(family: str, output: str) -> None:
    """Create template of configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    get_template(family, output)


def get_template(family: str, output: str) -> None:
    """Create template of configuration in YAML format."""
    click.echo(f"Creating {output} template file.")
    write_file(
        get_devhsm_class(family).generate_config_template(family)[f"sb_{family}_devhsm"], output
    )


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
