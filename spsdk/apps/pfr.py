#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import json
import sys
import io
# no_type_check decorator is used to suppress mypy's confusion in Click and cryptography libraries
from typing import (List, Optional, Tuple, Type, Union, no_type_check)

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup
from ruamel.yaml import YAML

from spsdk import __version__ as spsdk_version
from spsdk import pfr, SPSDK_YML_INDENT
from spsdk.crypto import (
    RSAPublicKey,
    load_certificate,
    load_private_key,
    load_public_key
)
from spsdk.apps.utils import catch_spsdk_error

from spsdk.apps.elftosb_helper import RootOfTrustInfo

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
def _extract_public_key(file_path: str, password: Optional[str]) -> RSAPublicKey:
    cert_candidate = load_certificate(file_path)
    if cert_candidate:
        return cert_candidate.public_key()
    private_candidate = load_private_key(file_path, password.encode() if password else None)
    if private_candidate:
        return private_candidate.public_key()
    public_candidate = load_public_key(file_path)
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


@click.group()
@click.version_option(spsdk_version, '-v', '--version')
def main() -> int:
    """Utility for generating and parsing Protected Flash Region data (CMPA, CFPA)."""
    return 0


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specified, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-f', '--full', is_flag=True, help="Show full config, including computed values")
def get_cfg_template(device: str, revision: str, area: str, output: click.Path, full: bool) -> None:
    """Generate user configuration template file."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    yaml = YAML(pure=True)
    yaml.indent(sequence=SPSDK_YML_INDENT*2, offset=SPSDK_YML_INDENT)
    data = pfr_obj.get_yaml_config(not full)
    stream = io.StringIO()
    yaml.dump(data, stream)
    yaml_data = stream.getvalue()
    _store_output(yaml_data, output)


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specified, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-b', '--binary', type=click.File('rb'), required=True, help="Binary to parse")
@click.option('-f', '--show-diff', is_flag=True, help="Show differences comparing to defaults")
@click.option('-c', '--show-calc', is_flag=True, help="Show also calculated fields when displaying difference to "
                                                      "defaults (--show-diff)")
def parse_binary(device: str, revision: str, area: str, output: click.Path, binary: click.File,
                 show_calc: bool, show_diff: bool) -> None:
    """Parse binary a extract configuration."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    data = binary.read()  # type: ignore
    pfr_obj.parse(data, exclude_computed=False)
    parsed = pfr_obj.get_yaml_config(exclude_computed=not show_calc, diff=show_diff)
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    stream = io.StringIO()
    yaml.dump(parsed, stream)
    yaml_data = stream.getvalue()
    _store_output(yaml_data, output)


@main.command()
@optgroup.group('Root Of Trust Configuration', cls=MutuallyExclusiveOptionGroup)
@optgroup.option('-e', '--elf2sb-config', type=click.File('r'),
                 help='Specify Root Of Trust from configuration file used by elf2sb tool')
@optgroup.option('-f', '--secret-file', type=click.Path(exists=True), multiple=True,
                 help="Secret file (certificate, public key, private key); can be defined multiple times")
@click.option('-c', '--user-config', 'user_config_file', type=click.Path(), required=True,
              help="YAML/JSON file with user configuration")
@click.option('-o', '--output', type=click.Path(), required=True,
              help="Save the output into a file instead of console")
@click.option('-a', '--add-seal', is_flag=True,
              help="Add seal mark digest at the end.")
@click.option('-i', '--calc-inverse', is_flag=True,
              help="Calculate the INVERSE values CAUTION!!! It locks the settings")
@click.option('-p', '--password', help="Password when using Encrypted private keys as --secret-file")
def generate_binary(output: click.Path, user_config_file: click.Path, add_seal: bool, calc_inverse: bool,
                    elf2sb_config: click.File, secret_file: Tuple[str], password: str) -> None:
    """Generate binary data."""
    pfr_config = pfr.PfrConfiguration(str(user_config_file))
    root_of_trust = None
    keys = None
    if elf2sb_config:
        public_keys = RootOfTrustInfo(json.load(elf2sb_config)).public_keys  # type: ignore
        root_of_trust = tuple(public_keys)
    if secret_file:
        root_of_trust = secret_file
    area = pfr_config.type
    if area.lower() == 'cmpa' and root_of_trust:
        keys = _extract_public_keys(root_of_trust, password)
    pfr_obj = _get_pfr_class(area)(device=pfr_config.device, revision=pfr_config.revision)
    pfr_obj.set_config(pfr_config, raw=not calc_inverse)

    data = pfr_obj.export(add_seal=add_seal, keys=keys)
    _store_output(data, output, 'wb')


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specified, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=True,
              help="Save the output into a file instead of console")
@click.option('-p', '--open', 'open_result', is_flag=True, help="Open the generated description file")
def info(device: str, revision: str, area: str, output: click.Path, open_result: bool) -> None:
    """Generate HTML page with brief description of CMPA/CFPA configuration fields."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    html_output = pfr_obj.registers.generate_html(
        f"{device.upper()} - {area.upper()}",
        pfr_obj.DESCRIPTION,
        regs_exclude=["SHA256_DIGEST"],
        fields_exclude=["FIELD"]
    )
    _store_output(html_output, output)
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f'{output}')


@main.command()
def devices() -> None:
    """List supported devices."""
    click.echo('\n'.join(pfr.CMPA.devices()))


#########################################################################################
#
#   Depreciated commands part
#
#########################################################################################


def echo_deprecated() -> None:
    """Print message about deprecated functions."""
    click.secho(f"You are using deprecated function of SPSDK PFR tool.\n"+ \
                f"There is list of deprecated function successors:\n" + \
                f"  - user-config -> get-cfg-template\n" + \
                f"  - parse -> parse-binary\n" + \
                f"  - generate -> generate-binary\n",
                fg="yellow")


@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specified, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-f', '--full', is_flag=True, help="Show full config, including computed values")
@click.pass_context
def user_config(ctx: click.Context, device: str, revision: str, area: str, output: click.Path, full: bool) -> None:
    """This is depreciated command for get-cfg-template."""
    echo_deprecated()
    ctx.invoke(get_cfg_template, device=device, revision=revision, area=area, output=output, full=full)


@main.command()
@click.option('-c', '--user-config', 'user_config_file', type=click.Path(), required=True,
              help="YAML/JSON file with user configuration")
@click.option('-o', '--output', type=click.Path(), required=True,
              help="Save the output into a file instead of console")
@click.option('-a', '--add-seal', is_flag=True,
              help="Add seal mark digest at the end.")
@click.option('-i', '--calc-inverse', is_flag=True,
              help="Calculate the INVERSE values CAUTION!!! It locks the settings")
@click.option('-e', '--elf2sb-config', type=click.File('r'), required=False,
              help='Specify Root Of Trust from configuration file used by elf2sb tool')
@click.option('-f', '--secret-file', type=click.Path(exists=True), multiple=True, required=False,
              help="Secret file (certificate, public key, private key); can be defined multiple times")
@click.option('-p', '--password', help="Password when using Encrypted private keys as --secret-file")
@click.pass_context
def generate(ctx: click.Context, output: click.Path, user_config_file: click.Path, add_seal: bool, calc_inverse: bool,
             elf2sb_config: click.File, secret_file: Tuple[str], password: str) -> None:
    """This is depreciated command for generate-binary."""
    echo_deprecated()
    ctx.invoke(generate_binary, output=output, user_config_file=user_config_file, add_seal=add_seal,
               calc_inverse=calc_inverse, elf2sb_config=elf2sb_config, secret_file=secret_file, password=password)

@main.command()
@click.option('-d', '--device', type=click.Choice(pfr.CMPA.devices()), help="Device to use", required=True)
@click.option('-r', '--revision', help="Chip revision; if not specified, most recent one will be used")
@click.option('-t', '--type', 'area', required=True, type=click.Choice(['cmpa', 'cfpa']),
              help='Select PFR partition')
@click.option('-o', '--output', type=click.Path(), required=False,
              help="Save the output into a file instead of console")
@click.option('-b', '--binary', type=click.File('rb'), required=True, help="Binary to parse")
@click.option('-f', '--show-diff', is_flag=True, help="Show differences comparing to defaults")
@click.option('-c', '--show-calc', is_flag=True, help="Show also calculated fields when displaying difference to "
                                                      "defaults (--show-diff)")
@click.pass_context
def parse(ctx: click.Context, device: str, revision: str, area: str, output: click.Path, binary: click.File,
          show_calc: bool, show_diff: bool) -> None:
    """This is depreciated command for parse-binary."""
    echo_deprecated()
    ctx.invoke(parse_binary, device=device, revision=revision, area=area,
               output=output, binary=binary, show_calc=show_calc, show_diff=show_diff)

@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
