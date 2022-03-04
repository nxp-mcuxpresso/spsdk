#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import contextlib
import logging
import os
import struct
import sys
from typing import Dict, Iterator, List

import click
import colorama

from spsdk import SPSDK_DATA_FOLDER, SPSDKError, SPSDKValueError
from spsdk import __version__ as spsdk_version
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils import (
    catch_spsdk_error,
    check_destination_dir,
    check_file_exists,
    load_configuration,
)
from spsdk.dat import DebugAuthenticateResponse, DebugAuthenticationChallenge, dm_commands
from spsdk.dat.debug_credential import DebugCredential
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.debuggers.utils import DebugProbeUtils, test_ahb_access

logger = logging.getLogger(__name__)
colorama.init()
NXPDEBUGMBOX_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpdebugmbox")

# pylint: disable=protected-access
LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]
PROTOCOL_VERSIONS = ["1.0", "1.1", "2.0", "2.1", "2.2"]


def determine_protocol_version(protocol: str) -> bool:
    """Validate the protocol version correctness, determine whether rsa or ecc is used.

    :param protocol: one of the values: '1.0', '1.1', '2.0', '2.1', '2.2'
    :return: is_rsa (true/false)
    :raises SPSDKValueError: In case that protocol is using unsupported key type.
    """
    if protocol not in PROTOCOL_VERSIONS:
        raise SPSDKValueError(f"Unsupported protocol '{protocol}' was given.")
    protocol_version = protocol.split(".")
    is_rsa = protocol_version[0] == "1"
    return is_rsa


def print_output(succeeded: bool, title: str) -> None:
    """Do output console print and set the right exit code.

    :param succeeded: Result of operation.
    :param title: Name of operation
    """
    if succeeded:
        logger.info(f"{title} succeeded.")
    else:
        logger.error(f"{title} failed!")
    click.get_current_context().exit(0 if succeeded else 1)


@contextlib.contextmanager
def _open_debugmbox(pass_obj: Dict) -> Iterator[DebugMailbox]:
    """Method opens DebugMailbox object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active DebugMailbox object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    interface = pass_obj["interface"]
    serial_no = pass_obj["serial_no"]
    debug_probe_params = pass_obj["debug_probe_params"]
    timing = pass_obj["timing"]
    reset = pass_obj["reset"]
    operation_timeout = pass_obj["operation_timeout"]

    debug_probes = DebugProbeUtils.get_connected_probes(
        interface=interface, hardware_id=serial_no, user_params=debug_probe_params
    )
    selected_probe = debug_probes.select_probe()
    debug_probe = selected_probe.get_probe(debug_probe_params)
    debug_probe.open()

    dm = DebugMailbox(
        debug_probe=debug_probe, reset=reset, moredelay=timing, op_timeout=operation_timeout
    )
    try:
        yield dm
    except SPSDKError as exc:
        raise SPSDKError(f"Failed Debug Mailbox command:({str(exc)}).") from exc
    finally:
        dm.close()


@click.group(no_args_is_help=True)
@click.option("-i", "--interface")
@click.option(
    "-p",
    "--protocol",
    "protocol",
    metavar="VERSION",
    default="1.0",
    help=f"Set the protocol version. Default is 1.0 (RSA). "
    f'Available options are: {", ".join(PROTOCOL_VERSIONS)}',
    type=click.Choice(PROTOCOL_VERSIONS),
)
@click.option(
    "-d",
    "--debug",
    "log_level",
    metavar="LEVEL",
    default="info",
    help=f"Set the level of system logging output. "
    f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
    type=click.Choice(LOG_LEVEL_NAMES),
)
@click.option("-t", "--timing", type=float, default=0.0)
@click.option("-s", "--serial-no")
@click.option("-n", "--no-reset", "reset", is_flag=True, default=True)
@click.option(
    "-o",
    "--debug-probe-option",
    multiple=True,
    help="This option could be used " "multiply to setup non-standard option for debug probe.",
)
@click.option(
    "--operation-timeout",
    type=int,
    default=4000,
    help="Special option to change the standard operation timeout used"
    " for communication with debugmailbox. Default value is 4000ms.",
)
@click.version_option(spsdk_version, "-v", "--version")
@click.help_option("--help")
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    protocol: str,
    log_level: str,
    timing: float,
    serial_no: str,
    debug_probe_option: List[str],
    reset: bool,
    operation_timeout: int,
) -> int:
    """NXP 'Debug Mailbox'/'Debug Credential file generator' Tool."""
    logging.basicConfig(level=log_level.upper())
    logger.setLevel(level=log_level.upper())

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")

        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
        "protocol": protocol,
        "interface": interface,
        "serial_no": serial_no,
        "debug_probe_params": probe_user_params,
        "timing": timing,
        "reset": reset,
        "operation_timeout": operation_timeout,
    }

    return 0


@main.command()
@click.option("-b", "--beacon", type=int, help="Authentication beacon")
@click.option("-c", "--certificate", help="Path to Debug Credentials.")
@click.option("-k", "--key", help="Path to DCK private key.")
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.pass_obj
def auth(pass_obj: dict, beacon: int, certificate: str, key: str, no_exit: bool) -> None:
    """Perform the Debug Authentication."""
    try:
        logger.info("Starting Debug Authentication")
        with _open_debugmbox(pass_obj) as mail_box:
            with open(certificate, "rb") as f:
                debug_cred_data = f.read()
            debug_cred = DebugCredential.parse(debug_cred_data)
            dac_rsp_len = 30 if debug_cred.HASH_LENGTH == 48 and debug_cred.socc == 4 else 26
            dac_data = dm_commands.DebugAuthenticationStart(dm=mail_box, resplen=dac_rsp_len).run()
            # convert List[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
            logger.debug(f"DAC: \n{dac.info()}")
            dar = DebugAuthenticateResponse.create(
                version=pass_obj["protocol"],
                socc=dac.socc,
                dc=debug_cred,
                auth_beacon=beacon,
                dac=dac,
                dck=key,
            )
            logger.debug(f"DAR:\n{dar.info()}")
            dar_data = dar.export()
            # convert bytes to List[int]
            dar_data_words = list(struct.unpack(f"<{len(dar_data) // 4}I", dar_data))
            dar_response = dm_commands.DebugAuthenticationResponse(
                dm=mail_box, paramlen=len(dar_data_words)
            ).run(dar_data_words)
            logger.debug(f"DAR response: {dar_response}")
            if not no_exit:
                exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                logger.debug(f"Exit response: {exit_response}")
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                # Do test of access to AHB bus
                ahb_access_granted = test_ahb_access(mail_box.debug_probe)
                res_str = (
                    (colorama.Fore.GREEN + "successfully")
                    if ahb_access_granted
                    else (colorama.Fore.RED + "without AHB access")
                )
                logger.info(f"Debug Authentication ends {res_str}{colorama.Fore.RESET}.")
                if not ahb_access_granted:
                    click.get_current_context().exit(1)
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )

    except SPSDKError as e:
        logger.error(f"Start Debug Mailbox failed!\n{e}")
        click.get_current_context().exit(1)


@main.command()
@click.pass_obj
def start(pass_obj: dict) -> None:
    """Start DebugMailBox."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.StartDebugMailbox(dm=mail_box).run()
        result = True
    finally:
        print_output(result, "Start Debug Mailbox")


@main.command()
@click.pass_obj
def exit(pass_obj: dict) -> None:  # pylint: disable=redefined-builtin
    """Exit DebugMailBox."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.ExitDebugMailbox(dm=mail_box).run()
        result = True
    finally:
        print_output(result, "Exit Debug Mailbox")


@main.command()
@click.pass_obj
def erase(pass_obj: dict) -> None:
    """Erase Flash."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.EraseFlash(dm=mail_box).run()
        result = True
    finally:
        print_output(result, "Mass flash erase")


@main.command()
@click.pass_obj
def famode(pass_obj: dict) -> None:
    """Set Fault Analysis Mode."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.SetFaultAnalysisMode(dm=mail_box).run()
        result = True
    finally:
        print_output(result, "Set fault analysis mode")


@main.command()
@click.option("-m", "--mode", type=int, required=True)
@click.pass_obj
def ispmode(pass_obj: dict, mode: int) -> None:
    """Enter ISP Mode."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.EnterISPMode(dm=mail_box).run([mode])
        result = True
    finally:
        print_output(result, "Entering into ISP mode")


@main.command()
@click.option("-f", "--file", type=str, required=True)
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.pass_obj
def blankauth(pass_obj: dict, file: str, no_exit: bool) -> None:
    """Debug Authentication for Blank Device."""
    try:
        token = []
        logger.info("Starting Debug Authentication for Blank Device..")
        with _open_debugmbox(pass_obj) as mail_box:
            with open(file, "rb") as f:
                while True:
                    chunk = f.read(8).strip()
                    if not chunk:
                        break
                    token.append(int(chunk, 16))
                f.close()
            dm_commands.EnterBlankDebugAuthentication(dm=mail_box).run(token)
            if not no_exit:
                exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                logger.debug(f"Exit response: {exit_response}")
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                # Do test of access to AHB bus
                ahb_access_granted = test_ahb_access(mail_box.debug_probe)
                res_str = (
                    (colorama.Fore.GREEN + "successfully")
                    if ahb_access_granted
                    else (colorama.Fore.RED + "without AHB access")
                )
                logger.info(f"Debug Authentication ends {res_str}{colorama.Fore.RESET}.")
                if not ahb_access_granted:
                    click.get_current_context().exit(1)
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )

    except SPSDKError as e:
        logger.error(colorama.Fore.RED + f"Debug authentication for Blank device failed!\n{e}")
        click.get_current_context().exit(1)


@main.command()
@click.pass_obj
def test_connection(pass_obj: dict) -> None:
    """Method just try if the device debug port is opened or not."""
    ahb_access_granted = False
    try:

        interface = pass_obj["interface"]
        serial_no = pass_obj["serial_no"]
        debug_probe_params = pass_obj["debug_probe_params"]
        debug_probe = None

        debug_probes = DebugProbeUtils.get_connected_probes(
            interface=interface, hardware_id=serial_no, user_params=debug_probe_params
        )
        selected_probe = debug_probes.select_probe()
        debug_probe = selected_probe.get_probe(debug_probe_params)
        debug_probe.open()

        debug_probe.enable_memory_interface()
        ahb_access_granted = test_ahb_access(debug_probe)
    except SPSDKError as exc:
        click.echo(str(exc))
    finally:
        if debug_probe:
            debug_probe.close()
            access_str = colorama.Fore.GREEN if ahb_access_granted else colorama.Fore.RED + "not-"
            click.echo(f"The device is {access_str}accessible for debugging.{colorama.Fore.RESET}")


@main.command()
@click.option(
    "-p",
    "--protocol",
    "protocol",
    type=str,
    metavar="VERSION",
    default="1.0",
    help="""\b
        Set the protocol version. Default is 1.0 (RSA).
        NXP Protocol Version    Encryption Type
        1.0                     RSA 2048
        1.1                     RSA 4096
        2.0                     NIST P-256 SECP256R1
        2.1                     NIST P-384 SECP384R1
        2.2                     NIST P-521 SECP521R1
    """,
)
@click.option(
    "-c",
    "--config",
    type=click.File("r"),
    required=True,
    help="Specify YAML credential config file.",
)
@click.option(
    "-e",
    "--elf2sb-config",
    type=click.File("r"),
    required=False,
    help="Specify Root Of Trust from configuration file used by elf2sb tool",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
@click.option(
    "--plugin",
    type=click.Path(exists=True, file_okay=True),
    required=False,
    help="External python file containing a custom SignatureProvider implementation.",
)
@click.argument("dc_file_path", metavar="PATH", type=click.Path(file_okay=True))
def gendc(
    protocol: str,
    plugin: click.Path,
    dc_file_path: str,
    config: click.File,
    elf2sb_config: click.File,
    force: bool,
) -> None:
    """Generate debug certificate (DC).

    \b
    PATH    - path to dc file
    """
    if plugin:
        # if a plugin is present simply load it
        # The SignatureProvider will automatically pick up any implementation(s)
        from importlib.util import (  # pylint: disable=import-outside-toplevel
            module_from_spec,
            spec_from_file_location,
        )

        spec = spec_from_file_location(name="plugin", location=plugin)  # type: ignore
        assert spec
        mod = module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore

    is_rsa = determine_protocol_version(protocol)
    check_destination_dir(dc_file_path, force)
    check_file_exists(dc_file_path, force)

    logger.info("Loading configuration from yml file...")
    yaml_content = load_configuration(config.name)
    if elf2sb_config:
        logger.info("Loading configuration from elf2sb config file...")
        rot_info = RootOfTrustInfo(load_configuration(elf2sb_config.name))  # type: ignore
        yaml_content["rot_meta"] = rot_info.public_keys
        yaml_content["rotk"] = rot_info.private_key
        yaml_content["rot_id"] = rot_info.public_key_index

    # enforcing rot_id presence in yaml config...
    assert "rot_id" in yaml_content, "Config file doesn't contain the 'rot_id' field"

    logger.info(f"Creating {'RSA' if is_rsa else 'ECC'} debug credential object...")
    dc = DebugCredential.create_from_yaml_config(version=protocol, yaml_config=yaml_content)
    dc.sign()
    data = dc.export()
    logger.info("Saving the debug credential to a file...")
    with open(dc_file_path, "wb") as f:
        f.write(data)
    print_output(True, "Creating Debug credential file")


@main.command()
@click.argument("output", metavar="PATH", type=click.Path())
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
def get_cfg_template(output: click.Path, force: bool) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    \b
    PATH    - file name path to write template config file
    """
    check_destination_dir(str(output), force)
    check_file_exists(str(output), force)

    with open(os.path.join(NXPDEBUGMBOX_DATA_FOLDER, "template_config.yml"), "r") as file:
        template = file.read()

    with open(str(output), "w") as file:
        file.write(template)

    click.echo("The configuration template file has been created.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
