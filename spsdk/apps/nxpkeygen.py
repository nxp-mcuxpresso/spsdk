#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate public/private key and generating debug credential file."""
import json
import logging
import os
import sys
from typing import List, Tuple

import click
import yaml

from spsdk import __version__ as version
from spsdk.apps.elftosb_helper import RootOfTrustInfo
from spsdk.apps.utils import catch_spsdk_error
from spsdk.crypto import (generate_ecc_private_key, generate_ecc_public_key,
                          generate_rsa_private_key, generate_rsa_public_key,
                          save_ecc_private_key, save_ecc_public_key,
                          save_rsa_private_key, save_rsa_public_key)
from spsdk.dat import DebugCredential

logger = logging.getLogger(__name__)
LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]


@click.group()
@click.option('-p', '--protocol', 'protocol', type=str, metavar='VERSION', default='1.0',
              help='Set the protocol version. Default is 1.0 (RSA). ')
@click.option('-d', '--debug', 'log_level', metavar='LEVEL', default='debug',
              help=f'Set the level of system logging output. '
                   f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
              type=click.Choice(LOG_LEVEL_NAMES))
@click.version_option(version, '--version')
@click.pass_context
def main(ctx: click.Context, protocol: str, log_level: str) -> int:
    """NXP Key Generator Tool."""
    is_rsa, protocol_version = determine_protocol_version(protocol)
    key_param = determine_key_parameters(is_rsa, protocol_version)

    ctx.obj = {
        'is_rsa': is_rsa,
        'key_param': key_param,
        'protocol_version': protocol
    }

    logging.basicConfig(level=log_level.upper())
    return 0


def determine_key_parameters(is_rsa: bool, protocol_version: List[str]) -> object:
    """Determine key parameters based on used protocol.

    :param is_rsa: whether rsa is used or ecc
    :param protocol_version: protocol version string
    :return: string with keys' parameter
    """
    rsa_key_sizes = {
        '0': 2048,
        '1': 4096
    }
    ecc_curves = {
        '0': 'P-256',
        '1': 'P-384',
        '2': 'P-521'
    }
    key_param = rsa_key_sizes[protocol_version[1]] if is_rsa else ecc_curves[protocol_version[1]]
    return key_param


def determine_protocol_version(protocol: str) -> Tuple[bool, List[str]]:
    """Validate the protocol version correctness, determine whether rsa or ecc is used.

    :param protocol: one of the values: '1.0', '1.1', '2.0', '2.1', '2.2'
    :return: is_rsa (true/false), protocol_version
    """
    assert protocol in ['1.0', '1.1', '2.0', '2.1', '2.2'], "Unsupported protocol was given."
    protocol_version = protocol.split(".")
    is_rsa = protocol_version[0] == '1'
    return is_rsa, protocol_version


def check_destination_dir(path: str, create_folder: bool = False) -> None:
    """Checks path's destination dir, optionally create the destination folder.

    :param path: Path to file to create/consider
    :param create_folder: Create destination folder
    """
    dest_dir = os.path.dirname(path)
    if not dest_dir:
        return
    if create_folder:
        os.makedirs(dest_dir, exist_ok=True)
        return
    if not os.path.isdir(dest_dir):
        click.echo(f"Can't create '{path}', folder '{dest_dir}' doesn't exit.")
        sys.exit(1)


def check_file_exists(path: str, force_overwrite: bool = False) -> bool:  # type: ignore
    """Check if file exists, exits if file exists and overwriting is disabled.

    :param path: Path to a file
    :param force_overwrite: allows file overwriting
    :return: if file overwriting is allowed, it return True if file exists
    """
    if force_overwrite:
        return os.path.isfile(path)
    if os.path.isfile(path) and not force_overwrite:
        click.echo(f"File '{path}' already exists. Use --force to overwrite it.")
        sys.exit(1)


@main.command()
@click.option('--password', 'password', metavar='PASSWORD', help='Password with which the output file will be '
                                                                 'encrypted. If not provided, the output will be '
                                                                 'unencrypted.')
@click.argument('path', type=click.Path(file_okay=True))
@click.option('--force', is_flag=True, default=False,
              help="Force overwritting of an existing file. Create destination folder, if doesn't exist already.")
@click.pass_context
def genkey(ctx: click.Context, path: str, password: str, force: bool) -> None:
    """Generate key pair for RoT or DCK.

    \b
    PATH    - path where the key pairs will be stored
    """
    is_rsa = ctx.obj['is_rsa']
    key_param = ctx.obj['key_param']
    check_destination_dir(path, force)
    check_file_exists(path, force)

    if is_rsa:
        logger.info("Generating RSA private key...")
        priv_key_rsa = generate_rsa_private_key(key_size=key_param)
        logger.info("Generating RSA corresponding public key...")
        pub_key_rsa = generate_rsa_public_key(priv_key_rsa)
        logger.info("Saving RSA key pair...")
        save_rsa_private_key(priv_key_rsa, path, password if password else None)
        save_rsa_public_key(pub_key_rsa, os.path.splitext(path)[0] + '.pub')
    else:
        logger.info("Generating ECC private key...")
        priv_key_ec = generate_ecc_private_key(curve_name=key_param)
        logger.info("Generating ECC public key...")
        pub_key_ec = generate_ecc_public_key(priv_key_ec)
        logger.info("Saving ECC key pair...")
        save_ecc_private_key(priv_key_ec, path, password if password else None)
        save_ecc_public_key(pub_key_ec, os.path.splitext(path)[0] + '.pub')


@main.command()
@click.option('-c', '--config', type=click.File('r'), required=True,
              help='Specify YAML credential config file.')
@click.option('-e', '--elf2sb-config', type=click.File('r'), required=False,
              help='Specify Root Of Trust from configuration file used by elf2sb tool')
@click.option('--force', is_flag=True, default=False,
              help="Force overwritting of an existing file. Create destination folder, if doesn't exist already.")
@click.option('--plugin', type=click.Path(exists=True, file_okay=True), required=False,
              help='External python file contaning a custom SignatureProvider implementation.')
@click.argument('dc_file_path', metavar='PATH', type=click.Path(file_okay=True))
@click.pass_context
def gendc(ctx: click.Context, plugin: click.Path, dc_file_path: str, config: click.File,
          elf2sb_config: click.File, force: bool) -> None:
    """Generate debug certificate (DC).

    \b
    PATH    - path to dc file
    """
    if plugin:
        # if a plugin is present simply load it
        # The SignatureProvider will automatically pick up any implementation(s)
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location(name='plugin', location=plugin)  # type: ignore
        mod = module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore

    is_rsa = ctx.obj['is_rsa']
    protocol = ctx.obj['protocol_version']
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
    with open(dc_file_path, 'wb') as f:
        f.write(data)


@catch_spsdk_error
def safe_main() -> int:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
