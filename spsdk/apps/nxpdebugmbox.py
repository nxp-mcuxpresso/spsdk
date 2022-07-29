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
from spsdk.apps.blhost_helper import progress_bar
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_apps_common_options
from spsdk.apps.utils.utils import (
    INT,
    SPSDKAppError,
    catch_spsdk_error,
    check_destination_dir,
    check_file_exists,
    format_raw_data,
    parse_file_and_size,
    parse_hex_data,
)
from spsdk.dat import DebugAuthenticateResponse, DebugAuthenticationChallenge, dm_commands
from spsdk.dat.debug_credential import DebugCredential
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.debuggers.debug_probe import DebugProbe
from spsdk.debuggers.utils import PROBES, DebugProbeUtils, test_ahb_access
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import find_file, load_configuration, write_file

logger = logging.getLogger(__name__)
colorama.init()
NXPDEBUGMBOX_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpdebugmbox")

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
    :raises SPSDKAppError: Operation failed
    """
    if succeeded:
        click.echo(f"{title} succeeded.")
    else:
        raise SPSDKAppError(f"{title} failed!")


@contextlib.contextmanager
def _open_debug_probe(pass_obj: Dict) -> Iterator[DebugProbe]:
    """Method opens DebugProbe object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active DebugProbe object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    interface = pass_obj["interface"]
    serial_no = pass_obj["serial_no"]
    debug_probe_params = pass_obj["debug_probe_params"]

    debug_probes = DebugProbeUtils.get_connected_probes(
        interface=interface, hardware_id=serial_no, user_params=debug_probe_params
    )
    selected_probe = debug_probes.select_probe()
    debug_probe = selected_probe.get_probe(debug_probe_params)
    debug_probe.open()

    try:
        yield debug_probe
    except SPSDKError as exc:
        raise SPSDKError(f"Failed Debug Probe operation:({str(exc)}).") from exc
    finally:
        debug_probe.close()


@contextlib.contextmanager
def _open_debugmbox(pass_obj: Dict) -> Iterator[DebugMailbox]:
    """Method opens DebugMailbox object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active DebugMailbox object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    timing = pass_obj["timing"]
    reset = pass_obj["reset"]
    operation_timeout = pass_obj["operation_timeout"]

    with _open_debug_probe(pass_obj) as debug_probe:
        dm = DebugMailbox(
            debug_probe=debug_probe, reset=reset, moredelay=timing, op_timeout=operation_timeout
        )
        try:
            yield dm
        except SPSDKError as exc:
            raise SPSDKError(f"Failed Debug Mailbox command:({str(exc)}).") from exc
        finally:
            dm.close()


@click.group(name="nxpdebugmbox", no_args_is_help=True, cls=CommandsTreeGroup)
@click.option(
    "-i",
    "--interface",
    type=click.Choice(list(PROBES.keys())),
    help="Probe interface selection,if not specified, all available debug probe interfaces are used.",
)
@click.option(
    "-s",
    "--serial-no",
    help="Debug probe hardware ID/serial number to select the probe in system.",
)
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
    "-t",
    "--timing",
    type=float,
    default=0.0,
    help="Time of extra delay after reset sequence, defaults to 1.0 second",
)
@click.option(
    "-n",
    "--no-reset",
    "reset",
    is_flag=True,
    default=True,
    help=(
        "Omit reset of debug mailbox during initialization,"
        " default behavior is reset debug mailbox during initialization."
    ),
)
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
    " for communication with debug mailbox. Default value is 4000ms.",
)
@spsdk_apps_common_options
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    protocol: str,
    log_level: int,
    timing: float,
    serial_no: str,
    debug_probe_option: List[str],
    reset: bool,
    operation_timeout: int,
) -> int:
    """Tool for working with Debug Mailbox."""
    logging.basicConfig(level=log_level or logging.WARNING)

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


@main.command(name="auth", no_args_is_help=True)
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
                    raise SPSDKAppError()
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )

    except SPSDKError as e:
        logger.error(f"Start Debug Mailbox failed!\n{e}")
        raise SPSDKAppError() from e


@main.command(name="start")
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


@main.command(name="exit")
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


@main.command(name="erase")
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


@main.command(name="famode")
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


@main.command(name="ispmode", no_args_is_help=True)
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


@main.command(name="blankauth", no_args_is_help=True)
@click.option(
    "-f", "--file", type=click.Path(), required=True, help="Path to token file (string hex format)."
)
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
                    raise SPSDKAppError()
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )

    except SPSDKError as e:
        logger.error(colorama.Fore.RED + f"Debug authentication for Blank device failed!\n{e}")
        raise SPSDKAppError() from e


@main.command(name="get-crp")
@click.pass_obj
def get_crp(pass_obj: dict) -> None:
    """Get CRP level.

    Note: This command should be called after 'start' command and with no-reset '-n' option.
    """
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            crp_level = dm_commands.GetCRPLevel(dm=mail_box).run()[0]
            click.echo(f"CRP level is: {crp_level}.")
        result = True
    finally:
        print_output(result, "Get CRP Level")


@main.command(name="start-debug-session")
@click.pass_obj
def start_debug_session(pass_obj: dict) -> None:
    """Start debug session."""
    result = False
    try:
        with _open_debugmbox(pass_obj) as mail_box:
            dm_commands.StartDebugSession(dm=mail_box).run()
        result = True
    finally:
        print_output(result, "Start debug session")


@main.command(name="test-connection")
@click.pass_obj
def test_connection(pass_obj: dict) -> None:
    """Method just try if the device debug port is opened or not."""
    ahb_access_granted = False
    with _open_debug_probe(pass_obj) as debug_probe:
        try:
            debug_probe.enable_memory_interface()
            ahb_access_granted = test_ahb_access(debug_probe)
        except SPSDKError as exc:
            click.echo(str(exc))
        finally:
            access_str = colorama.Fore.GREEN if ahb_access_granted else colorama.Fore.RED + "not-"
            click.echo(f"The device is {access_str}accessible for debugging.{colorama.Fore.RESET}")


@main.command(name="read-memory", no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.Path(), required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_obj
def read_memory(
    pass_obj: dict,
    address: int,
    byte_count: int,
    out_file: str,
    use_hexdump: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout.

    Returns the contents of memory at the given <ADDRESS>, for a specified <BYTE_COUNT>.
    Data are read by 4 bytes at once and are store in little endian format!
    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout
    """
    bin_image = BinaryImage("memRead", byte_count, offset=address)
    start_addr = bin_image.aligned_start(4)
    length = bin_image.aligned_length(4)

    data = bytes()
    with _open_debug_probe(pass_obj) as debug_probe:
        try:
            debug_probe.enable_memory_interface()
            with progress_bar(
                suppress=logger.getEffectiveLevel() > logging.INFO
            ) as progress_callback:
                for addr in range(start_addr, start_addr + length, 4):
                    progress_callback(addr, start_addr + length)
                    data += debug_probe.mem_reg_read(addr).to_bytes(4, "little")
        except SPSDKError as exc:
            logger.error(str(exc))

    if not data:
        click.echo("The read operation failed.")
        return
    if len(data) != length:
        click.echo(
            f"The memory wasn't read complete. It was read just first {len(data) - (address-start_addr)} Bytes."
        )
    # Shrink start padding data
    data = data[address - start_addr :]
    # Shrink end padding data
    data = data[:byte_count]
    if out_file:
        write_file(data, out_file, mode="wb")
        click.echo(f"The memory has been read and write into {out_file}")
    else:
        click.echo(format_raw_data(data, use_hexdump=use_hexdump))


@main.command(name="write-memory", no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.pass_obj
def write_memory(pass_obj: dict, address: int, data_source: str) -> None:
    """Writes memory from a file or a hex-data.

    Writes memory at <ADDRESS> from <FILE> or <HEX-DATA>
    Writes a provided buffer to a specified <BYTE_COUNT> in memory.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(size)

    byte_count = len(data)
    bin_image = BinaryImage("memRead", byte_count, offset=address)
    start_addr = bin_image.aligned_start(4)
    length = bin_image.aligned_length(4)

    with _open_debug_probe(pass_obj) as debug_probe:
        try:
            debug_probe.enable_memory_interface()
            start_padding = address - start_addr
            align_data = data
            if start_padding:
                align_start_word = debug_probe.mem_reg_read(start_addr).to_bytes(4, "little")
                align_data = align_start_word[:start_padding] + data

            end_padding = length - byte_count - start_padding
            if end_padding:
                align_end_word = debug_probe.mem_reg_read(start_addr + length - 4).to_bytes(
                    4, "little"
                )
                align_data = align_data + align_end_word[4 - end_padding :]

            with progress_bar(
                suppress=logger.getEffectiveLevel() > logging.INFO
            ) as progress_callback:
                for i, addr in enumerate(range(start_addr, start_addr + length, 4)):
                    progress_callback(addr, start_addr + length)
                    to_write = int.from_bytes(align_data[i * 4 : i * 4 + 4], "little")
                    debug_probe.mem_reg_write(addr, to_write)
                    # verify write
                    try:
                        verify_data = debug_probe.mem_reg_read(addr)
                    except SPSDKError as ver_exc:
                        raise SPSDKError("The write verification failed.") from ver_exc
                    if to_write != verify_data:
                        raise SPSDKError(
                            f"Data verification failed! {hex(to_write)} != {hex(verify_data)}"
                        )
        except SPSDKError as exc:
            click.echo(f"The write operation failed. Reason: {str(exc)}")
            return

    click.echo("The memory has been write successfully.")


@main.command(name="gendc", no_args_is_help=True)
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
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Specify YAML credential config file.",
)
@click.option(
    "-e",
    "--elf2sb-config",
    type=click.Path(exists=True, dir_okay=False),
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
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="External python file containing a custom SignatureProvider implementation.",
)
@click.argument("dc_file_path", metavar="PATH", type=click.Path(file_okay=True))
def gendc(
    protocol: str,
    plugin: str,
    dc_file_path: str,
    config: str,
    elf2sb_config: str,
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
    yaml_content = load_configuration(config)
    if elf2sb_config:
        elf2sb_config_dir = os.path.dirname(elf2sb_config)
        logger.info("Loading configuration from elf2sb config file...")
        rot_info = RootOfTrustInfo(
            load_configuration(elf2sb_config), search_paths=[elf2sb_config_dir]
        )
        yaml_content["rot_meta"] = [
            find_file(x, search_paths=[elf2sb_config_dir]) for x in rot_info.public_keys
        ]
        assert rot_info.private_key
        yaml_content["rotk"] = find_file(rot_info.private_key, search_paths=[elf2sb_config_dir])
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


@main.command(name="get-cfg-template", no_args_is_help=True)
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
