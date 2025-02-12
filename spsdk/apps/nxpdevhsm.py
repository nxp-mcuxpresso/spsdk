#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SB file."""

import os
import sys
from typing import Optional

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
from spsdk.apps.utils.utils import (
    INT,
    SPSDKAppError,
    catch_spsdk_error,
    resolve_path_relative_to_config,
)
from spsdk.mboot.commands import TrustProvOemKeyType
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import DeviceUidValue, PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.devhsm.utils import DevHSMConfig, get_devhsm_class
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.utils.misc import get_printable_path, load_binary, write_file


@click.group(name="nxpdevhsm", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Nxpdevhsm application is designed to create SB3 provisioning file for initial provisioning of device by OEM."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="generate", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=DevHsm.get_supported_families(), required=False)
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
    "-e",
    "--enc-oem-master-share",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to Encrypted OEM MASTER SHARE binary.",
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
    default=None,
    help=(
        "Reset device BEFORE DevHSM operation. The DevHSM operation can run only once between resets. "
        "Do not enable this option on Linux/Mac when using USB. By default this reset is DISABLED."
    ),
)
@click.option(
    "-fr/-FR",
    "--final-reset/--no-final-reset",
    default=None,
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
def generate_command(
    interface: MbootProtocolBase,
    oem_share_input: str,
    enc_oem_master_share: str,
    key: str,
    output: str,
    workspace: str,
    config: str,
    family: str,
    initial_reset: bool,
    final_reset: bool,
    buffer_address: int,
) -> None:
    """Generate provisioning SB file."""
    generate(
        interface=interface,
        oem_share_input=oem_share_input,
        enc_oem_master_share=enc_oem_master_share,
        key=key,
        output=output,
        workspace=workspace,
        config=config,
        family=family,
        initial_reset=initial_reset,
        final_reset=final_reset,
        buffer_address=buffer_address,
    )


def generate(
    interface: MbootProtocolBase,
    oem_share_input: Optional[str] = None,
    enc_oem_master_share: Optional[str] = None,
    key: Optional[str] = None,
    output: Optional[str] = None,
    workspace: Optional[str] = None,
    config: Optional[str] = None,
    family: Optional[str] = None,
    initial_reset: Optional[bool] = False,
    final_reset: Optional[bool] = True,
    buffer_address: Optional[int] = None,
) -> None:
    """Generate provisioning SB file."""
    app_config = DevHSMConfig(
        config=config,
        oem_share_input=oem_share_input,
        enc_oem_master_share=enc_oem_master_share,
        key=key,
        output=output,
        workspace=workspace,
        family=family,
        initial_reset=initial_reset,
        final_reset=final_reset,
        buffer_address=buffer_address,
    )
    search_paths = [app_config.config_path] if app_config.config_path else None
    oem_share_in = DevHsm.get_oem_share_input(app_config.oem_share_input, search_paths)
    enc_oem_master_share_in = DevHsm.get_oem_master_share(
        app_config.enc_oem_master_share, search_paths
    )
    cust_mk_sk = DevHsm.get_cust_mk_sk(app_config.key, search_paths) if app_config.key else None
    out_file = resolve_path_relative_to_config(
        "containerOutputFile", app_config.config, app_config.output
    )
    if not app_config.family:
        raise SPSDKAppError("Family is not specified.")
    devhsm_cls = get_devhsm_class(app_config.family)
    with McuBoot(interface) as mboot:
        devhsm = devhsm_cls(
            mboot=mboot,
            cust_mk_sk=cust_mk_sk,
            oem_share_input=oem_share_in,
            oem_enc_master_share_input=enc_oem_master_share_in,
            info_print=click.echo,
            container_conf=config,
            workspace=app_config.workspace,
            family=app_config.family,
            initial_reset=app_config.initial_reset,
            final_reset=app_config.final_reset,
            buffer_address=app_config.buffer_address,
        )
        devhsm.create_sb()
        write_file(devhsm.export(), out_file, "wb")

    click.echo(f"Final SB file has been written: {get_printable_path(os.path.abspath(out_file))}")


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
    write_file(get_devhsm_class(family).generate_config_template(family), output)
    click.echo(
        f"The DevHsm template for {family} has been saved into {get_printable_path(output)} YAML file"
    )


@main.command(name="gen-master-share", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=DevHsmSB31.get_supported_families())
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
        "Do not enable this option on Linux/Mac when using USB. By default this reset is DISABLED."
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
    family: str,
    oem_share_input: str,
    output: str,
    initial_reset: bool,
    buffer_address: int,
) -> None:
    """Generate OEM SHARE on target and optionally store results."""
    seed_data = DevHsm.get_oem_share_input(oem_share_input)

    with McuBoot(interface=interface) as mboot:
        if initial_reset:
            mboot.reset(timeout=500, reopen=True)
        devhsm = DevHsmSB31(
            mboot=mboot,
            oem_share_input=seed_data,
            initial_reset=True,
            family=family,
            buffer_address=buffer_address,
        )
        enc_oem_share, enc_oem_master_share, oem_cert = devhsm.oem_generate_master_share()

    if output:
        write_file(seed_data, os.path.join(output, "OEM_SEED.bin"), mode="wb")
        write_file(enc_oem_share, os.path.join(output, "ENC_OEM_SHARE.bin"), mode="wb")
        write_file(
            enc_oem_master_share, os.path.join(output, "ENC_OEM_MASTER_SHARE.bin"), mode="wb"
        )
        write_file(oem_cert, os.path.join(output, "NXP_CUST_CA_PUK.bin"), mode="wb")
    click.echo("OEM MASTER SHARE successfully generated.")


@main.command(name="set-master-share", no_args_is_help=True)
@spsdk_mboot_interface(identify_by_family=True)
@spsdk_family_option(families=DevHsmSB31.get_supported_families())
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
    family: str,
    oem_share_input: str,
    enc_oem_master_share: str,
    buffer_address: int,
) -> None:
    """Set OEM SHARE."""
    with McuBoot(interface=interface) as mboot:
        devhsm = DevHsmSB31(mboot=mboot, family=family, buffer_address=buffer_address)
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
    interface: MbootProtocolBase, family: str, cust_mk_sk: str, output: str, buffer_address: int
) -> None:
    """Wrap CUST_MK_SK key."""
    with McuBoot(interface=interface) as mboot:
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
    family: str,
    oem_share_input: str,
    enc_oem_master_share: str,
    output: str,
    buffer_address: int,
) -> None:
    """Generate CUST FW AUTH key."""
    with McuBoot(interface=interface) as mboot:
        uuid_list = mboot.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid_list:
            raise SPSDKAppError(f"Unable to read UUID. Error: {mboot.status_string}")
        uuid_obj = DeviceUidValue(PropertyTag.UNIQUE_DEVICE_IDENT.tag, uuid_list)
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
