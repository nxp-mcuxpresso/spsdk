#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate public/private key and generating debug credential file."""
import logging
import os
import sys
from typing import List, Tuple

import click
import yaml

from spsdk import __version__ as version
from spsdk.crypto import generate_rsa_private_key, generate_rsa_public_key, save_rsa_private_key, save_rsa_public_key, \
    generate_ecc_public_key, generate_ecc_private_key, save_ecc_public_key, save_ecc_private_key
from spsdk.dat import DebugCredentialECC, DebugCredentialRSA

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


@main.command()
@click.option('--password', 'password', metavar='PASSWORD', help='Password with which the output file will be '
                                                                 'encrypted. If not provided, the output will be '
                                                                 'unencrypted.')
@click.argument('path', type=click.Path())
@click.pass_context
def genkey(ctx: click.Context, path: str, password: str) -> None:
    """Generate key pair for RoT or DCK.

    \b
    PATH_WHERE_TO_SAVE_KEYS    - path where the key pairs will be stored
    """
    is_rsa = ctx.obj['is_rsa']
    key_param = ctx.obj['key_param']

    assert os.path.isdir(os.path.dirname(path)), f"The target directory '{os.path.dirname(path)}' does not exist."
    if is_rsa:
        logger.info("Generating RSA private key...")
        priv_key_rsa = generate_rsa_private_key(key_size=key_param)
        logger.info("Generating RSA corresponding public key...")
        pub_key_rsa = generate_rsa_public_key(priv_key_rsa)
        logger.info("Saving RSA key pair...")
        save_rsa_private_key(priv_key_rsa, path, password if password else None)
        save_rsa_public_key(pub_key_rsa, path[:-3] + 'pub')
    else:
        logger.info("Generating ECC private key...")
        priv_key_ec = generate_ecc_private_key(curve_name=key_param)
        logger.info("Generating ECC public key...")
        pub_key_ec = generate_ecc_public_key(priv_key_ec)
        logger.info("Saving ECC key pair...")
        save_ecc_private_key(priv_key_ec, path, password if password else None)
        save_ecc_public_key(pub_key_ec, path[:-3] + 'pub')


@main.command()
@click.option('-c', '--config', metavar='PATH', help='Specify YAML credential config file.')
@click.argument('dc_file_path', metavar='PATH', type=click.Path())
@click.pass_context
def gendc(ctx: click.Context, dc_file_path: str, config: str) -> None:
    """Generate debug certificate (DC).

    \b
    PATH_TO_DC_FILE     - path to dc file
    """
    is_rsa = ctx.obj['is_rsa']
    protocol = ctx.obj['protocol_version']
    assert os.path.isdir(os.path.dirname(config)), \
        f"The target directory '{os.path.dirname(config)}' does not exist."
    logger.info("Loading configuration from yml file...")
    with open(config, 'r') as stream:
        yaml_content = yaml.safe_load(stream)
    if is_rsa:
        logger.info("Creating debug credential RSA object from yml file...")
        dc = DebugCredentialRSA.from_yaml_config(version=protocol, yaml_config=yaml_content)
    else:
        logger.info("Creating debug credential ECC object from yml file...")
        dc = DebugCredentialECC.from_yaml_config(version=protocol, yaml_config=yaml_content)
    data = dc.export()
    logger.info("Saving the debug credential to a file...")
    with open(dc_file_path, 'wb') as f:
        f.write(data)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover   # pylint: disable=no-value-for-parameter
