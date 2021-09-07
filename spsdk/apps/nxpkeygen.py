#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate public/private key and generating debug credential file."""
import logging
import os
import sys
from typing import List, Tuple

import click
import commentjson as json
import yaml

from spsdk import SPSDK_DATA_FOLDER, SPSDKValueError
from spsdk import __version__ as version
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils import catch_spsdk_error, check_destination_dir, check_file_exists
from spsdk.crypto import (
    ec,
    generate_ecc_private_key,
    generate_ecc_public_key,
    generate_rsa_private_key,
    generate_rsa_public_key,
    save_ecc_private_key,
    save_ecc_public_key,
    save_rsa_private_key,
    save_rsa_public_key,
)
from spsdk.dat import DebugCredential

NXPKEYGEN_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpkeygen")

logger = logging.getLogger(__name__)
LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]
SUPPORTED_PROTOCOLS = ["1.0", "1.1", "2.0", "2.1", "2.2"]


def determine_key_parameters(is_rsa: bool, protocol_version: List[str]) -> object:
    """Determine key parameters based on used protocol.

    :param is_rsa: whether rsa is used or ecc
    :param protocol_version: protocol version string
    :return: string with keys' parameter
    """
    rsa_key_sizes = {"0": 2048, "1": 4096}
    ecc_curves = {"0": "secp256r1", "1": "secp384r1", "2": "secp521r1"}
    key_param = rsa_key_sizes[protocol_version[1]] if is_rsa else ecc_curves[protocol_version[1]]
    return key_param


def determine_protocol_version(protocol: str) -> Tuple[bool, List[str]]:
    """Validate the protocol version correctness, determine whether rsa or ecc is used.

    :param protocol: one of the values: '1.0', '1.1', '2.0', '2.1', '2.2'
    :return: is_rsa (true/false), protocol_version
    :raises SPSDKValueError: In case that protocol is using unsupported key type.
    """
    if not protocol in SUPPORTED_PROTOCOLS:
        raise SPSDKValueError(f"Unsupported protocol '{protocol}' was given.")
    protocol_version = protocol.split(".")
    is_rsa = protocol_version[0] == "1"
    return is_rsa, protocol_version


def get_list_of_supported_keys() -> List[str]:
    """Generate list with list of supported key types.

    :return: List of supported key types.
    """
    ret = ["rsa2048", "rsa3072", "rsa4096"]
    # pylint: disable=protected-access
    ret.extend(ec._CURVE_TYPES.keys())  # type: ignore

    return ret


@click.group(no_args_is_help=True)
@click.option(
    "-d",
    "--debug",
    "log_level",
    metavar="LEVEL",
    default="warning",
    help=f"Set the level of system logging output. "
    f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
    type=click.Choice(LOG_LEVEL_NAMES),
)
@click.version_option(version, "--version")
def main(log_level: str) -> int:
    """NXP Key Generator Tool."""
    logging.basicConfig(level=log_level.upper())
    return 0


@main.command()
@click.option(
    "-k",
    "--key-type",
    type=click.Choice(get_list_of_supported_keys(), case_sensitive=False),
    metavar="KEY-TYPE",
    default="RSA2048",
    help=f"""\b
        Set of the supported key types. Default is RSA2048.

        Note: NXP DAT protocol is using encryption keys by this table:

        NXP Protocol Version                Encryption Type
            1.0                                 RSA 2048
            1.1                                 RSA 4096
            2.0                                 SECP256R1
            2.1                                 SECP384R1
            2.2                                 SECP521R1

        All possible options:
        {", ".join(get_list_of_supported_keys())}.
        """,
)
@click.option(
    "--password",
    "password",
    metavar="PASSWORD",
    help="Password with which the output file will be encrypted. "
    "If not provided, the output will be unencrypted.",
)
@click.argument("path", type=click.Path(file_okay=True))
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file.",
)
def genkey(key_type: str, path: str, password: str, force: bool) -> None:
    """Generate key pair for RoT or DCK.

    \b
    PATH    - output file path, where the key pairs (private and public key) will be stored.
              Each key will be stored in separate file (.pub and .pem).
    """
    key_param = key_type.lower().strip()
    is_rsa = "rsa" in key_param

    check_destination_dir(path, force)
    check_file_exists(path, force)
    pub_key_path = os.path.splitext(path)[0] + ".pub"
    check_file_exists(pub_key_path, force)

    if is_rsa:
        logger.info("Generating RSA private key...")
        priv_key_rsa = generate_rsa_private_key(key_size=int(key_param.replace("rsa", "")))
        logger.info("Generating RSA corresponding public key...")
        pub_key_rsa = generate_rsa_public_key(priv_key_rsa)
        logger.info("Saving RSA key pair...")
        save_rsa_private_key(priv_key_rsa, path, password if password else None)
        save_rsa_public_key(pub_key_rsa, pub_key_path)
    else:
        logger.info("Generating ECC private key...")
        priv_key_ec = generate_ecc_private_key(curve_name=key_param)
        logger.info("Generating ECC public key...")
        pub_key_ec = generate_ecc_public_key(priv_key_ec)
        logger.info("Saving ECC key pair...")
        save_ecc_private_key(priv_key_ec, path, password if password else None)
        save_ecc_public_key(pub_key_ec, pub_key_path)


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
        from importlib.util import module_from_spec, spec_from_file_location

        spec = spec_from_file_location(name="plugin", location=plugin)  # type: ignore
        mod = module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore

    is_rsa = determine_protocol_version(protocol)
    check_destination_dir(dc_file_path, force)
    check_file_exists(dc_file_path, force)

    logger.info("Loading configuration from yml file...")
    yaml_content = yaml.safe_load(config)  # type: ignore
    if elf2sb_config:
        logger.info("Loading configuration from elf2sb config file...")
        rot_info = RootOfTrustInfo(json.load(elf2sb_config))  # type: ignore
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

    with open(os.path.join(NXPKEYGEN_DATA_FOLDER, "template_config.yml"), "r") as file:
        template = file.read()

    with open(str(output), "w") as file:
        file.write(template)

    click.echo("The configuration template file has been created.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
