#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP DevHSM utilities for secure boot file generation.

This module provides command-line interface and functionality for generating
initialization Secure Boot (SB) files using NXP Development Hardware Security
Module (DevHSM). It supports SB3.1 and SB4 families with master key management,
customer firmware authentication, and secure provisioning operations.
"""

import os
import sys
from typing import Type, Union

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_mboot_interface,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.mboot.commands import TrustProvOemKeyType
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import DeviceUidValue, PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.devhsm.utils import get_devhsm_class
from spsdk.sbfile.sb4.devhsm import DevHsmSB4
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, write_file

SB31_SB4_FAMILIES = list(
    set(DevHsmSB31.get_supported_families() + DevHsmSB4.get_supported_families())
)
SB31_SB4_FAMILIES.sort()


@click.group(name="nxpdevhsm", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Nxpdevhsm application is designed to create SB3 provisioning file for initial provisioning of device by OEM."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="generate", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_config_option(required=False)
def generate_command(interface: MbootProtocolBase, config: Config) -> None:
    """Generate provisioning SB file."""
    generate(interface=interface, config=config)


def generate(interface: MbootProtocolBase, config: Config) -> None:
    """Generate provisioning SB file."""
    out_file = config.get_output_file_name("containerOutputFile")

    devhsm_cls = get_devhsm_class(FamilyRevision.load_from_config(config))
    with McuBoot(interface, family=FamilyRevision.load_from_config(config)) as mboot:
        devhsm = devhsm_cls.load_from_config(config, mboot=mboot, info_print=click.echo)
        devhsm.create_sb()
        write_file(devhsm.export(), out_file, "wb")

    click.echo(f"Final SB file has been written: {get_printable_path(os.path.abspath(out_file))}")


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=DevHsm.get_supported_families())
@spsdk_output_option(force=True)
def get_template_command(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    get_template(family, output)


def get_template(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format."""
    write_file(get_devhsm_class(family).get_config_template(family), output)
    click.echo(
        f"The DevHsm template for {family} has been saved into {get_printable_path(output)} YAML file"
    )


def get_devhsm_class_sb3_sb4(family: FamilyRevision) -> Union[Type[DevHsmSB31], Type[DevHsmSB4]]:
    """Get DevHsm class for SB3.1 and SB4 families."""
    if family in DevHsmSB31.get_supported_families():
        return DevHsmSB31
    if family in DevHsmSB4.get_supported_families():
        return DevHsmSB4
    raise SPSDKAppError(f"Unsupported family for DevHSM: {family}")


@main.command(name="gen-master-share", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=SB31_SB4_FAMILIES)
@click.option(
    "-i",
    "--oem-share-input",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="OEM share input file to use as a seed to randomize the provisioning process (16-bytes long binary file).",
)
@spsdk_output_option(
    required=False,
    directory=True,
    help="Path to optional directory where to store generated OEM shares.",
)
@click.option(
    "-ir/-IR",
    "--initial-reset/--no-init-reset",
    default=True,
    help=(
        "Reset device BEFORE DevHSM operation. The DevHSM operation can run only once between resets. "
        "Do not enable this option on Linux/Mac when using USB. By default this reset is ENABLED."
    ),
)
@click.option(
    "-ba",
    "--buffer-address",
    type=INT(),
    help="Override the communication buffer base address. The default address is family-specific.",
)
def gen_master_share(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    oem_share_input: str,
    output: str,
    initial_reset: bool,
    buffer_address: int,
) -> None:
    """Generate OEM SHARE on target and optionally store results."""
    seed_data = DevHsm.get_oem_share_input(oem_share_input)

    with McuBoot(interface=interface, family=family) as mboot:
        if initial_reset:
            mboot.reset(timeout=500, reopen=True)

        devhsm = get_devhsm_class_sb3_sb4(family)(
            mboot=mboot,
            oem_share_input=seed_data,
            initial_reset=True,
            family=family,
            commands=[],
            buffer_address=buffer_address,
        )
        enc_oem_share, enc_oem_master_share, oem_cert = devhsm.oem_generate_master_share()

    if output:
        write_file(seed_data, os.path.join(output, "OEM_SEED.bin"), mode="wb")
        write_file(enc_oem_share, os.path.join(output, "ENC_OEM_SHARE.bin"), mode="wb")
        write_file(
            enc_oem_master_share, os.path.join(output, "ENC_OEM_MASTER_SHARE.bin"), mode="wb"
        )
        if len(oem_cert):
            write_file(oem_cert, os.path.join(output, "NXP_CUST_CA_PUK.bin"), mode="wb")

    click.echo("OEM MASTER SHARE successfully generated.")


@main.command(name="set-master-share", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=SB31_SB4_FAMILIES)
@click.option(
    "-i",
    "--oem-share-input",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to OEM_SEED binary.",
)
@click.option(
    "-e",
    "--enc-oem-master-share",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to OEM ENC MASTER SHARE.",
)
@click.option(
    "-ba",
    "--buffer-address",
    type=INT(),
    help="Override the communication buffer base address. The default address is family-specific.",
)
def set_master_share(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    oem_share_input: str,
    enc_oem_master_share: str,
    buffer_address: int,
) -> None:
    """Set OEM SHARE."""
    with McuBoot(interface=interface, family=family) as mboot:
        devhsm = get_devhsm_class_sb3_sb4(family)(
            mboot=mboot, family=family, commands=[], buffer_address=buffer_address
        )
        devhsm.oem_set_master_share(
            oem_seed=load_binary(oem_share_input),
            enc_oem_share=load_binary(enc_oem_master_share),
        )
    click.echo("OEM MASTER SHARE successfully set.")


@main.command(name="wrap-cust-mk-sk", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=DevHsmSB31.get_supported_families())
@click.option("-i", "--cust-mk-sk", type=click.Path(exists=True, dir_okay=False), required=True)
@spsdk_output_option(directory=True)
@click.option(
    "-ba",
    "--buffer-address",
    type=INT(),
    help="Override the communication buffer base address. The default address is family-specific.",
)
def wrap_cust_mk_sk(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    cust_mk_sk: str,
    output: str,
    buffer_address: int,
) -> None:
    """Wrap CUST_MK_SK key."""
    with McuBoot(interface=interface, family=family) as mboot:
        devhsm = DevHsmSB31(mboot=mboot, family=family, buffer_address=buffer_address)
        wrapped_key = devhsm.wrap_key(load_binary(cust_mk_sk))
    write_file(wrapped_key, os.path.join(output, "CUST_MK_SK_BLOB.bin"), mode="wb")
    click.echo("Wrapped CUST_MK_SK successfully created.")


@main.command(name="get-cust-fw-auth", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=DevHsmSB31.get_supported_families())
@click.option(
    "-i",
    "--oem-share-input",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Path to OEM_SEED binary.",
)
@click.option(
    "-e",
    "--enc-oem-master-share",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Path to OEM ENC MASTER SHARE.",
)
@spsdk_output_option(directory=True)
@click.option(
    "-ba",
    "--buffer-address",
    type=INT(),
    help="Override the communication buffer base address. The default address is family-specific.",
)
def get_cust_fw_auth(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    oem_share_input: str,
    enc_oem_master_share: str,
    output: str,
    buffer_address: int,
) -> None:
    """Generate CUST FW AUTH key.

    If OEM shares are not provided, nxpdevhsm gen-master-share must be called first.
    """
    with McuBoot(interface=interface, family=family) as mboot:
        uuid_list = mboot.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid_list:
            raise SPSDKAppError(f"Unable to read UUID. Error: {mboot.status_string}")
        uuid_obj = DeviceUidValue(PropertyTag.UNIQUE_DEVICE_IDENT, uuid_list)
        uuid = str(uuid_obj.to_int())

        # allow for previously set OEM Shares
        devhsm = DevHsmSB31(
            mboot=mboot, family=family, oem_share_input=bytes(), buffer_address=buffer_address
        )
        if oem_share_input and enc_oem_master_share:
            devhsm.oem_set_master_share(
                oem_seed=load_binary(oem_share_input),
                enc_oem_share=load_binary(enc_oem_master_share),
            )
        else:
            click.echo(
                "OEM SHARE INPUT or ENC OEM MASTER SHARE (or both) are missing. Reusing existing OEM SHARE settings."
            )
        prk, puk = devhsm.generate_key(key_type=TrustProvOemKeyType.MFWISK)
    write_file(uuid, os.path.join(output, "UUID.txt"))
    write_file(prk, os.path.join(output, "CUST_FW_AUTH_PRK.bin"), mode="wb")
    write_file(puk, os.path.join(output, "CUST_FW_AUTH_PRK_PUK.bin"), mode="wb")
    click.echo("CUST FW AUTH key pair successfully created.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
