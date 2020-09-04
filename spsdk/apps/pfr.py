#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import json
import sys
# no_type_check decorator is used to suppress mypy's confusion in Click and cryptography libraries
from typing import Iterable, List, Mapping, Optional, Type, Union, Tuple, no_type_check

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from cryptography.x509 import load_pem_x509_certificate
from jinja2 import Environment, FileSystemLoader

from spsdk import crypto
from spsdk import SPSDK_DATA_FOLDER
from spsdk import __version__ as spsdk_version
from spsdk.image import pfr
from spsdk.image.misc import dict_diff

HTMLDataElement = Mapping[str, Union[str, Iterable[dict]]]
HTMLData = List[HTMLDataElement]
PFRArea = Union[Type[pfr.CMPA], Type[pfr.CFPA]]

@no_type_check
def _store_output(data: str, path: Optional[click.Path], mode: str = 'w') -> None:
    """Store the output data; either on stdout or into file if it's provided."""
    if path is None:
        click.echo(data)
    else:
        with open(path, mode) as f:
            f.write(data)


def _get_pfr_class(area_name: str) -> PFRArea:
    """Return CMPA/CFPA class based on the name."""
    return getattr(pfr, area_name.upper())


@no_type_check
def _load_user_config(user_config_file: click.File) -> Optional[dict]:
    """Load user JSON configuration file."""
    if user_config_file is None:
        return None
    return json.load(user_config_file)


@no_type_check
def _extract_public_key(file_path: str, password: Optional[str]) -> crypto.RSAPublicKey:
    cert_candidate = crypto.load_certificate(file_path)
    if cert_candidate:
        return cert_candidate.public_key()
    private_candidate = crypto.load_private_key(file_path, password.encode() if password else None)
    if private_candidate:
        return private_candidate.public_key()
    public_candidate = crypto.load_public_key(file_path)
    if public_candidate:
        return public_candidate
    assert False, f"Unable to load secret file '{file_path}'."


@no_type_check
def _extract_public_keys(secret_files: Tuple[str], password: Optional[str]) -> List[RSAPublicKey]:
    """Extract RSAPublic key from a file that contains Certificate, Private Key o Public Key."""
    return [
        _extract_public_key(file_path=source, password=password)
        for source in secret_files
    ]


@no_type_check
def _get_data_for_html(area: PFRArea) -> HTMLData:
    """Gather XML data and transform them into format used by template."""
    data: HTMLData = []
    for reg in area._get_registers():
        element: HTMLDataElement = {
            'name': reg.attrib['name'],
            'desc': reg.attrib['description'],
            'width': reg.attrib['width'],
            'offset': reg.attrib['offset'],
            'bitfields': []
        }
        for reg_bitfield in area._get_bitfields(reg.attrib['name']):
            if reg_bitfield.attrib['name'] == 'FIELD':
                continue
            bitfield = {
                'name': reg_bitfield.attrib['name'],
                'desc': reg_bitfield.attrib['description'],
                'width': reg_bitfield.attrib['width'],
                'offset': reg_bitfield.attrib['offset'],
                'bit_values': {}
            }
            for bf_value in reg_bitfield.findall('bit_field_value'):
                bitfield['bit_values'][bf_value.attrib['value']] = bf_value.attrib['description']
            element['bitfields'].append(bitfield)
        data.append(element)
    return data


def _generate_html(area_name: str, data: List[dict]) -> str:
    """Generate HTML content."""
    jinja_env = Environment(loader=FileSystemLoader(SPSDK_DATA_FOLDER))
    template = jinja_env.get_template("pfr_desc_template.html")
    return template.render(area_name=area_name, data=data)


@click.group()
@click.version_option(spsdk_version, '-v', '--version')
def main() -> int:
    """Utility for generating and parsing Protected Flash Region data (CMPA, CFPA)."""
    return 0


@main.command()
def devices() -> None:
    """List supported devices."""
    click.echo('\n'.join(pfr.CMPA.devices()))


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specivfied, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-f', '--full', is_flag=True, help="Show full config, including computed values")
def user_config(device: str, revision: str, area: str, output: click.Path, full: bool) -> None:
    """Generate user configuration."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    data = pfr_obj.generate_config(not full)
    json_data = json.dumps(data, indent=2)
    _store_output(json_data, output)


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specivfied, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-b', '--binary', type=click.File('rb'), required=True, help="Binary to parse")
@click.option('-c', '--show-calc', is_flag=True, help="Show also the calculated fields")
@click.option('-f', '--show-diff', is_flag=True, help="Show differences comparing to defaults")
def parse(device: str, revision: str, area: str, output: click.Path, binary: click.File,
          show_calc: bool, show_diff: bool) -> None:
    """Parse binary a extract configuration."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    data = binary.read()    # type: ignore
    parsed = pfr_obj.parse(data, exclude_computed=False)
    if show_diff:
        parsed = dict_diff(
            pfr_obj.generate_config(exclude_computed=not show_calc),
            parsed)
    json_data = json.dumps(parsed, indent=2)
    _store_output(json_data, output)


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specivfied, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=True,
              help="Save the output into a file instead of console")
@click.option('-c', '--user-config', 'user_config_file', type=click.File('r'), required=True,
              help="JSON file with user configuration")
@click.option('-a', '--add-hash', is_flag=True,
              help="Add HASH digest at the end. CAUTION!!! It locks the device")
@click.option('-i', '--calc-inverse', is_flag=True,
              help="Calculate the INVERSE values CAUTION!!! It locks the settings")
@click.option('-f', '--secret-file', type=click.Path(exists=True), multiple=True, required=False,
              help="Secret file (certificate, public key, private key); can be defined multiple times")
@click.option('-p', '--password', help="Password when using Encrypted private keys as --secret-file")
def generate(device: str, revision: str, area: str, output: click.Path, user_config_file: click.File,
             add_hash: bool, calc_inverse: bool, secret_file: Tuple[str], password: str) -> None:
    """Generate binary data."""
    if area == 'cmpa' and not secret_file:
        click.echo('Error: CMPA page requires --secret-file(s)')
        sys.exit(1)
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_obj.keys = _extract_public_keys(secret_file, password)
    pfr_obj.user_config = _load_user_config(user_config_file)
    data = pfr_obj.export(add_hash=add_hash, compute_inverses=calc_inverse)
    _store_output(data, output, 'wb')


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specivfied, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=True,
              help="Save the output into a file instead of console")
@click.option('-p', '--open', 'open_result', is_flag=True, help="Open the generated description file")
def info(device: str, revision: str, area: str, output: click.Path, open_result: bool) -> None:
    """Generate HTML page with brief descrition of CMPA/CFPA sonfiguration fields."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    data = _get_data_for_html(pfr_obj)
    html_output = _generate_html(pfr_obj.__class__.__name__, data)
    _store_output(html_output, output)
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f'{output}')


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
