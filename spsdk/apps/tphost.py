#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Trust provisioning host application."""
import logging
import os
import sys
from typing import List

import click

from spsdk.apps.tp_utils import (
    TPHostConfig,
    device_help,
    get_counters,
    list_tpdevices,
    list_tptargets,
    process_tp_inputs,
    target_help,
    tp_device_options,
    tp_target_options,
)
from spsdk.apps.utils import CommandsTreeGroup, catch_spsdk_error, spsdk_apps_common_options
from spsdk.crypto import Encoding
from spsdk.tp import TP_DATA_FOLDER, TpDevInterface, TpTargetInterface, TrustProvisioningHost
from spsdk.tp.utils import get_supported_devices, scan_tp_devices, scan_tp_targets


@click.group(name="tphost", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Application to secure Trust provisioning process of loading application in Un-trusted environment."""
    logging.basicConfig(level=log_level or logging.WARNING)
    return 0


@main.command(name="load", no_args_is_help=True)
@tp_device_options
@tp_target_options
@click.option(
    "-f",
    "--family",
    type=click.Choice(get_supported_devices(), case_sensitive=False),
    help="The target device name.",
)
@click.option(
    "-fw",
    "--firmware",
    type=click.Path(exists=True, dir_okay=False),
    help="The application firmware SB file.",
)
@click.option(
    "-pfw",
    "--prov-firmware",
    type=click.Path(exists=True, dir_okay=False),
    help="OEM Provisioning Firmware SB file.",
)
@click.option(
    "-to",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to TPHost config file.",
)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=False, dir_okay=False),
    help="Path TP audit log yaml file",
)
@click.option(
    "-s",
    "--save-debug-data",
    is_flag=True,
    default=False,
    help="Save the data being transferred (for debugging purposes)",
)
def load(
    tp_device: str,
    tp_device_parameter: List[str],
    tp_target: str,
    tp_target_parameter: List[str],
    family: str,
    firmware: str,
    prov_firmware: str,
    timeout: int,
    config: str,
    audit_log: str,
    save_debug_data: bool,
) -> None:
    """Command to provision target MCU."""
    tp_config = TPHostConfig(
        tp_device=tp_device,
        tp_device_parameter=tp_device_parameter,
        tp_target=tp_target,
        tp_target_parameter=tp_target_parameter,
        family=family,
        firmware=firmware,
        prov_firmware=prov_firmware,
        audit_log=audit_log,
        timeout=timeout,
        config=config,
    )

    tp_interface = process_tp_inputs(
        tp_type=tp_config.tp_device,
        tp_parameters=tp_config.tp_device_parameter,
        header="device",
        scan_func=scan_tp_devices,
        print_func=click.echo,
    )
    tp_device_instance = tp_interface.create_interface()
    assert isinstance(tp_device_instance, TpDevInterface)

    tp_interface = process_tp_inputs(
        tp_type=tp_config.tp_target,
        tp_parameters=tp_config.tp_target_parameter,
        header="target",
        scan_func=scan_tp_targets,
        print_func=click.echo,
    )
    tp_target_instance = tp_interface.create_interface()
    assert isinstance(tp_target_instance, TpTargetInterface)

    tp_worker = TrustProvisioningHost(tp_device_instance, tp_target_instance, click.echo)
    tp_worker.do_provisioning(
        family=tp_config.family,
        audit_log=tp_config.audit_log,
        prov_fw=tp_config.prov_firmware_data,
        product_fw=tp_config.firmware_data,
        timeout=tp_config.timeout,
        save_debug_data=save_debug_data,
    )


@main.command(name="get-cfg-template", no_args_is_help=True)
@click.option(
    "-f",
    "--family",
    type=click.Choice(get_supported_devices(), case_sensitive=False),
    default="lpc55s6x",
    help="Chip family to generate the TPHost config for.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=True,
    help="The output YAML template configuration file name",
)
def get_cfg_template(
    family: str,
    output: str,
) -> None:
    """Command to generate tphost template of configuration YML file."""
    with open(os.path.join(TP_DATA_FOLDER, "tphost_cfg_template.yml"), "r") as file:
        template = file.read()

    with open(str(output), "w") as file:
        file.write(template)

    click.echo(f"The configuration template created. {os.path.abspath(output)}")


@main.command(name="verify", no_args_is_help=True)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path TP audit log yaml file",
)
@click.option(
    "-k",
    "--audit-log-key",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to private/public key to verify the TP audit log yaml file",
)
@click.option(
    "-d",
    "--destination",
    type=click.Path(file_okay=False),
    help="Destination directory for certificate extraction(non-existent or empty)",
)
@click.option(
    "-e",
    "--encoding",
    type=click.Choice(["PEM", "DER"], case_sensitive=False),
    default="PEM",
    show_default=True,
    help="X509 certificate encoding.",
)
@click.option(
    "-n",
    "--skip-nxp",
    is_flag=True,
    default=False,
    help="Skip extracting the NXP Devattest certificates",
)
@click.option(
    "-o",
    "--skip-oem",
    is_flag=True,
    default=False,
    help="Skip extracting the OEM x509 Devattest certificates",
)
@click.option(
    "-i",
    "--cert-index",
    type=click.IntRange(0, 3),
    show_choices=True,
    metavar="[0-3]",
    help="""
    Index of an individual OEM certificate to extract.
    If not specified, all available OEM certificates will be extracted
    """,
)
@click.option(
    "-j",
    "--processes",
    type=int,
    help=f"How many processes to use; if not specified use cpu_count: {os.cpu_count()}",
)
@click.option(
    "--force-rewrite",
    is_flag=True,
    default=False,
    help="Rewrite certificates in 'destination' directory",
)
def verify(
    audit_log: str,
    audit_log_key: str,
    destination: str,
    encoding: str,
    skip_nxp: bool,
    skip_oem: bool,
    cert_index: int,
    processes: int,
    force_rewrite: bool,
) -> None:
    """Verify audit log integrity and optionally extract certificates.

    Certificate extraction takes place if `-d/--destination` is specified.
    """
    TrustProvisioningHost.verify_extract_log(
        audit_log=audit_log,
        audit_log_key=audit_log_key,
        destination=destination,
        skip_nxp=skip_nxp,
        skip_oem=skip_oem,
        cert_index=cert_index,
        encoding=Encoding.PEM if encoding.lower() == "pem" else Encoding.DER,
        max_processes=processes,
        info_print=click.echo,
        force_rewrite=force_rewrite,
    )


@main.command(name="check-log-owner", no_args_is_help=True)
@tp_device_options
@click.option(
    "-t",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to configuration file (parameters on CLI take precedence).",
    required=False,
)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Path TP audit log yaml file",
)
def check_log_owner(
    tp_device: str,
    tp_device_parameter: List[str],
    timeout: int,
    config: str,
    audit_log: str,
) -> None:
    """Check whether TP Device ID matches the ID in audit log."""
    TPHostConfig.SCHEMA_MEMBERS = ["device", "audit_log"]
    tp_config = TPHostConfig(
        tp_device=tp_device,
        tp_device_parameter=tp_device_parameter,
        config=config,
        timeout=timeout,
        audit_log=audit_log,
    )

    tp_interface = process_tp_inputs(
        tp_type=tp_config.tp_device,
        tp_parameters=tp_config.tp_device_parameter,
        header="device",
        scan_func=scan_tp_devices,
        print_func=click.echo,
    )
    tp_dev = tp_interface.create_interface()
    assert isinstance(tp_dev, TpDevInterface)

    tp_worker = TrustProvisioningHost(
        tpdev=tp_dev,
        tptarget=None,  # type: ignore  # target is not used, we set it to None on purpose
        info_print=click.echo,
    )
    tp_worker.check_audit_log_owner(tp_config.audit_log)


main.add_command(device_help)
main.add_command(target_help)
main.add_command(list_tpdevices)
main.add_command(list_tptargets)
main.add_command(get_counters)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
