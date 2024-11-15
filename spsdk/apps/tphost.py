#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Trust provisioning host application."""
import logging
import os
import sys

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
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm, hashes
from spsdk.crypto.keys import PublicKeyEcc
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError
from spsdk.tp.data_container import AuthenticationType, Container, PayloadType
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpDevInterface, TpTargetInterface
from spsdk.tp.tphost import TrustProvisioningHost
from spsdk.tp.utils import get_supported_devices, scan_tp_devices, scan_tp_targets
from spsdk.utils.database import get_common_data_file_path
from spsdk.utils.misc import load_binary, load_text, write_file


@click.group(name="tphost", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Application to secure Trust provisioning process of loading application in Un-trusted environment."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="load", no_args_is_help=True)
@tp_device_options
@tp_target_options
@spsdk_family_option(families=get_supported_devices(), required=False)
@spsdk_config_option(required=False)
@click.option(
    "-fw",
    "--firmware",
    type=click.Path(exists=True, dir_okay=False),
    help="The application firmware SB file. If not specified, TP flow ends after loading OEM assets and reset.",
)
@click.option(
    "-pfw",
    "--prov-firmware",
    type=click.Path(exists=True, dir_okay=False),
    help="OEM Provisioning Firmware SB file. If not specified, the TP flow starts immediately.",
)
@click.option(
    "-to",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=False, dir_okay=False),
    help="Path TP audit log yaml file.",
)
@click.option(
    "-s",
    "--save-debug-data",
    is_flag=True,
    default=False,
    help="Save the data being transferred (for debugging purposes).",
)
def load(
    tp_device: str,
    tp_device_parameter: list[str],
    tp_target: str,
    tp_target_parameter: list[str],
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
    tp_target_instance = tp_interface.create_interface(family=tp_config.family)
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


@main.command(name="load-tpfw", no_args_is_help=True)
@tp_target_options
@spsdk_family_option(families=get_supported_devices(), required=False)
@spsdk_config_option(required=False)
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
    "-s",
    "--skip-test",
    is_flag=True,
    help="Skip test whether Provisioning FW boot-ed up.",
)
def load_tpfw(
    tp_target: str,
    tp_target_parameter: list[str],
    family: str,
    prov_firmware: str,
    timeout: int,
    config: str,
    skip_test: bool,
) -> None:
    """Command to load Provisioning Firmware to the target MCU."""
    TPHostConfig.SCHEMA_MEMBERS = ["family", "provisioning_firmware", "tp_timeout", "target"]
    tp_config = TPHostConfig(
        tp_target=tp_target,
        tp_target_parameter=tp_target_parameter,
        family=family,
        prov_firmware=prov_firmware,
        timeout=timeout,
        config=config,
    )

    if not tp_config.prov_firmware_data:
        raise SPSDKAppError("Provisioning Firmware to load is not defined.")

    tp_interface = process_tp_inputs(
        tp_type=tp_config.tp_target,
        tp_parameters=tp_config.tp_target_parameter,
        header="target",
        scan_func=scan_tp_targets,
        print_func=click.echo,
    )
    tp_target_instance = tp_interface.create_interface(family=tp_config.family)
    assert isinstance(tp_target_instance, TpTargetInterface)

    tp_worker = TrustProvisioningHost(
        tpdev=None,  # type: ignore  # we don't need TPDevice in this case
        tptarget=tp_target_instance,
        info_print=click.echo,
    )
    tp_worker.load_provisioning_fw(
        family=tp_config.family,
        prov_fw=tp_config.prov_firmware_data,
        timeout=tp_config.timeout,
        skip_test=skip_test,
        keep_target_open=False,
        skip_usb_enumeration=skip_test,
    )


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=get_supported_devices())
@spsdk_output_option(force=True)
# pylint: disable=unused-argument   # preparation for the future
def get_template(
    family: str,
    output: str,
) -> None:
    """Command to generate tphost template of configuration YML file."""
    template_name = "tphost_cfg_template.yaml"
    template = load_text(get_common_data_file_path(os.path.join("tp", template_name)))
    template = template.replace("TMP_FAMILY", family)
    write_file(template, output)

    click.echo(f"The TPHost template for {family} has been saved into {output} YAML file")


@main.command(name="verify", no_args_is_help=True)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path TP audit log yaml file.",
)
@click.option(
    "-k",
    "--audit-log-key",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to private/public key to verify the TP audit log yaml file.",
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
    "-sn",
    "--skip-nxp",
    is_flag=True,
    default=False,
    help="Skip extracting the NXP Devattest certificates.",
)
@click.option(
    "-so",
    "--skip-oem",
    is_flag=True,
    default=False,
    help="Skip extracting the OEM x509 Devattest certificates.",
)
@click.option(
    "-i",
    "--cert-index",
    type=click.IntRange(0, 3),
    show_choices=True,
    metavar="[0-3]",
    help="""
    Index of an individual OEM certificate to extract.
    If not specified, all available OEM certificates will be extracted.
    """,
)
@click.option(
    "-j",
    "--processes",
    type=INT(),
    help=f"How many processes to use; if not specified use cpu_count: {os.cpu_count()}",
)
@spsdk_output_option(
    required=False,
    directory=True,
    force=True,
    help="Destination directory for certificate extraction(non-existent or empty).",
)
def verify(
    audit_log: str,
    audit_log_key: str,
    output: str,
    encoding: str,
    skip_nxp: bool,
    skip_oem: bool,
    cert_index: int,
    processes: int,
) -> None:
    """Verify audit log integrity and optionally extract certificates.

    Certificate extraction takes place if `-o/--output` is specified.
    """
    TrustProvisioningHost.verify_extract_log(
        audit_log=audit_log,
        audit_log_key=audit_log_key,
        destination=output,
        skip_nxp=skip_nxp,
        skip_oem=skip_oem,
        cert_index=cert_index,
        encoding=SPSDKEncoding.PEM if encoding.lower() == "pem" else SPSDKEncoding.DER,
        max_processes=processes,
        info_print=click.echo,
    )


@main.command(name="check-log-owner", no_args_is_help=True)
@tp_device_options
@click.option(
    "-t",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@spsdk_config_option(
    help="Path to configuration file (parameters on CLI take precedence).",
)
@click.option(
    "-l",
    "--audit-log",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Path TP audit log yaml file.",
)
def check_log_owner(
    tp_device: str,
    tp_device_parameter: list[str],
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
    tp_worker.check_audit_log_owner(tp_config.audit_log, timeout=tp_config.timeout)


@main.command(name="get-tp-response", no_args_is_help=True)
@tp_target_options
@spsdk_family_option(families=get_supported_devices(), required=False)
@spsdk_config_option(
    help="Path to configuration file (parameters on CLI take precedence).",
    required=False,
)
@click.option(
    "-to",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@click.option(
    "-r",
    "--response-file",
    type=click.Path(dir_okay=False),
    help="Path where to store the TP_RESPONSE",
    required=True,
)
@click.option(
    "-k",
    "--key-flags",
    type=INT(),
    default="1",
    help="OEM Key Flags. Default: 0x01",
)
@click.option(
    "-s",
    "--save-debug-data",
    is_flag=True,
    default=False,
    help="Save the data being transferred (for debugging purposes).",
)
def get_tp_response(
    tp_target: str,
    tp_target_parameter: list[str],
    family: str,
    timeout: int,
    config: str,
    response_file: str,
    key_flags: int,
    save_debug_data: bool,
) -> None:
    """Retrieve TP_RESPONSE from the target."""
    TPHostConfig.SCHEMA_MEMBERS = ["family", "tp_timeout", "target"]

    tp_config = TPHostConfig(
        tp_target=tp_target,
        tp_target_parameter=tp_target_parameter,
        family=family,
        timeout=timeout,
        config=config,
    )

    tp_interface = process_tp_inputs(
        tp_type=tp_config.tp_target,
        tp_parameters=tp_config.tp_target_parameter,
        header="target",
        scan_func=scan_tp_targets,
        print_func=click.echo,
    )
    tp_target_instance = tp_interface.create_interface(family=tp_config.family)
    assert isinstance(tp_target_instance, TpTargetInterface)

    tp_worker = TrustProvisioningHost(
        tpdev=None,  # type: ignore  # device is not used, we set it to None on purpose
        tptarget=tp_target_instance,
        info_print=click.echo,
    )
    tp_worker.get_tp_response(
        response_file=response_file,
        timeout=tp_config.timeout,
        oem_key_flags=key_flags,
        save_debug_data=save_debug_data,
    )


@main.command(name="check-cot", no_args_is_help=True)
@click.option(
    "-r",
    "--root-cert",
    help="NXP Glob Root Certificate authority certificate.",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
)
@click.option(
    "-i",
    "--intermediate-cert",
    help="NXP Product Intermediate certificate.",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "-t",
    "--tp-response",
    help="TP Response from MCU, or NXP_DEV_CERT from IFR memory.",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
)
# pylint: disable=broad-except,line-too-long  # true source of potential error is not known in advance
def check_cot(root_cert: str, intermediate_cert: str, tp_response: str) -> None:
    """Check Chain-of-Trust in Trust Provisioning.

    \b
    Root and intermediate certificates are provided from NXP.
    TP_RESPONSE can be obtained from `tphost get-tp-response`, or you can use NXP_DEV_CERT from IFR memory using a debugger.
    Please note that using the NXP_DEV_CERT has only limited Chain-Of-Trust checking capability (it doesn't attest the device's private key).
    """
    overall_result = True

    nxp_glob_puk = extract_public_key(root_cert) if root_cert else None
    if not nxp_glob_puk:
        click.echo("NXP_GLOB key/cert not specified. NXP_PROD cert verification will be skipped.")

    nxp_prod_cert_data = load_binary(intermediate_cert)
    try:
        nxp_prod_cert = Certificate.parse(nxp_prod_cert_data)
        nxp_prod_puk = nxp_prod_cert.get_public_key()
    except SPSDKError as e:
        logging.debug(str(e))
        if nxp_glob_puk:
            raise SPSDKAppError(f"Unable to load NXP_PROD certificate: {str(e)}") from e
        click.echo("Failed to load NXP_PROD as certificate, attempting to load raw public key")
        nxp_prod_puk = PublicKeyEcc.parse(nxp_prod_cert_data)

    if nxp_glob_puk:
        assert isinstance(nxp_glob_puk, PublicKeyEcc)
        message = "validating NXP_PROD_CERT signature..."
        try:
            assert isinstance(nxp_prod_cert.signature_hash_algorithm, hashes.HashAlgorithm)
            nxp_glob_puk.verify_signature(
                nxp_prod_cert.signature,
                nxp_prod_cert.tbs_certificate_bytes,
                EnumHashAlgorithm.from_label(nxp_prod_cert.signature_hash_algorithm.name),
            )
            message += "OK"
        except Exception:
            message += "FAILED!"
            overall_result = False
        click.echo(message)

    message = "Parsing TP_RESPONSE data container..."
    try:
        tp_data = load_binary(tp_response)
        tp_response_container = Container.parse(tp_data)
        message += "OK"
    except Exception:
        message += "FAILED!"
        overall_result = False
    click.echo(message)

    message = "Extracting NXP_DIE_ID_CERT..."
    try:
        nxp_die_cert_data = tp_response_container.get_entry(
            PayloadType.NXP_DIE_ID_AUTH_CERT
        ).payload
        nxp_die_cert = Container.parse(nxp_die_cert_data)
        message += "OK"
    except Exception:
        message += "FAILED!"
        overall_result = False
    click.echo(message)

    assert isinstance(nxp_die_cert, Container)
    message = "Validating NXP_DIE_ID_CERT signature..."
    if nxp_die_cert.validate(nxp_prod_puk.export(SPSDKEncoding.DER)):
        message += "OK"
    else:
        message += "FAILED!"
        overall_result = False
    click.echo(message)

    if tp_response_container.get_auth_type() != AuthenticationType.ECDSA_256:
        # This is not a full Prove Genuinity response, skip further checks
        if overall_result is False:
            raise SPSDKAppError()
        return

    message = "Validating TP_RESPONSE signature..."
    try:
        nxp_die_puk_data = nxp_die_cert.get_entry(PayloadType.NXP_DIE_ATTEST_AUTH_PUK).payload
    except SPSDKTpError:
        nxp_die_puk_data = nxp_die_cert.get_entry(PayloadType.NXP_DIE_ID_AUTH_PUK).payload
    nxp_die_puk = PublicKeyEcc.parse(nxp_die_puk_data)
    if tp_response_container.validate(nxp_die_puk.export(SPSDKEncoding.DER)):
        message += "OK"
    else:
        message += "FAILED!"
        overall_result = False
    click.echo(message)
    if overall_result is False:
        raise SPSDKAppError()


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
