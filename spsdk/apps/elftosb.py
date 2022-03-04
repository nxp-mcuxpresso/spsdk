#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Elf2SB."""
import os
import sys
from typing import Dict, List

import click
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

import spsdk.apps.elftosb_utils.sb_21_helper as elf2sb_helper21
import spsdk.apps.elftosb_utils.sly_bd_parser as bd_parser
from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import catch_spsdk_error, load_configuration
from spsdk.crypto import load_certificate_as_bytes
from spsdk.exceptions import SPSDKError
from spsdk.image import SB3_SCH_FILE, TrustZone, get_mbi_class
from spsdk.image.mbimg import mbi_generate_config_templates
from spsdk.sbfile.sb2.images import BootImageV21, BootSectionV2
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.crypto import CertBlockV2, Certificate
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.schema_validator import ValidationSchemas, check_config

SUPPORTED_FAMILIES = [
    "lpc55xx",
    "lpc55s0x",
    "lpc55s1x",
    "lpc55s2x",
    "lpc55s6x",
    "lpc55s3x",
    "rt5xx",
    "rt6xx",
]


def generate_trustzone_binary(tzm_conf: click.File) -> None:
    """Generate TrustZone binary from json configuration file."""
    config_data = load_configuration(tzm_conf.name)
    check_config(config_data, TrustZone.get_validation_schemas_family())
    check_config(config_data, TrustZone.get_validation_schemas(config_data["family"]))
    trustzone = TrustZone.from_config(config_data)
    tz_data = trustzone.export()
    output_file = config_data["tzpOutputFile"]
    write_file(tz_data, output_file, mode="wb")
    click.echo(f"Success. (Trustzone binary: {output_file} created.)")


def generate_config_templates(family: str, output_folder: str) -> None:
    """Generate all possible configuration for selected family."""
    if not family:
        raise SPSDKError("The chip family must be specified.")

    templates: Dict[str, str] = {}
    # 1: Generate all configuration for MBI
    templates.update(mbi_generate_config_templates(family))
    # 2: Optionally add TrustZone Configuration file
    templates.update(TrustZone.generate_config_template(family))
    # 3: Optionally add Secure Binary v3.1 Configuration file
    templates.update(SecureBinary31.generate_config_template(family))

    # And generate all config templates files
    for key, val in templates.items():
        file_name = f"{key}.yml"
        if os.path.isfile(output_folder):
            raise SPSDKError(f"The specified path {output_folder} is file.")
        if not os.path.isdir(output_folder):
            os.mkdir(output_folder)
        full_file_name = os.path.join(output_folder, file_name)
        if not os.path.isfile(full_file_name):
            click.echo(f"Creating {file_name} template file.")
            with open(full_file_name, "w") as f:
                f.write(val)
        else:
            click.echo(f"Skip creating {file_name}, this file already exists.")


def generate_master_boot_image(image_conf: click.File) -> None:
    """Generate MasterBootImage from json configuration file.

    :param image_conf: master boot image json configuration file.
    """
    config_data = load_configuration(image_conf.name)
    mbi_cls = get_mbi_class(config_data)
    check_config(config_data, mbi_cls.get_validation_schemas())
    mbi = mbi_cls()
    mbi.load_from_config(config_data)
    mbi_data = mbi.export()

    mbi_output_file_path = config_data["masterBootOutputFile"]
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


def generate_secure_binary_21(
    bd_file_path: click.Path,
    output_file_path: click.Path,
    key_file_path: click.Path,
    private_key_file_path: click.Path,
    signing_certificate_file_paths: List[click.Path],
    root_key_certificate_paths: List[click.Path],
    hoh_out_path: click.Path,
    external_files: List[click.Path],
) -> None:
    """Generate SecureBinary image from BD command file.

    :param bd_file_path: path to BD file.
    :param output_file_path: output path to generated secure binary file.
    :param key_file_path: path to key file.
    :param private_key_file_path: path to private key file for signing. This key
    relates to last certificate from signing certificate chain.
    :param signing_certificate_file_paths: signing certificate chain.
    :param root_key_certificate_paths: paths to root key certificate(s) for
    verifying other certificates. Only 4 root key certificates are allowed,
    others are ignored. One of the certificates must match the first certificate
    passed in signing_certificate_file_paths.
    :param hoh_out_path: output path to hash of hashes of root keys. If set to
    None, 'hash.bin' is created under working directory.
    :param external_files: external files referenced from BD file.

    :raises SPSDKError: If incorrect bf file is provided
    """
    # Create lexer and parser, load the BD file content and parse it for
    # further execution - the parsed BD file is a dictionary in JSON format
    with open(str(bd_file_path)) as bd_file:
        bd_file_content = bd_file.read()

    parser = bd_parser.BDParser()

    parsed_bd_file = parser.parse(text=bd_file_content, extern=external_files)
    if parsed_bd_file is None:
        raise SPSDKError("Invalid bd file, secure binary file generation terminated")

    # The dictionary contains following content:
    # {
    #   options: {
    #       opt1: value,...
    #   },
    #   sections: [
    #       {section_id: value, options: {}, commands: {}},
    #       {section_id: value, options: {}, commands: {}}
    #   ]
    # }
    # TODO check, that section_ids differ in sections???

    # we need to encrypt and sign the image, let's check, whether we have
    # everything we need
    # It appears, that flags option in BD file are irrelevant for 2.1 secure
    # binary images regarding encryption/signing - SB 2.1 must be encrypted
    # and signed.
    # However, bit 15 represents, whether the final SB 2.1 must include a
    # SHA-256 of the botable section.
    flags = parsed_bd_file["options"].get(
        "flags", BootImageV21.FLAGS_SHA_PRESENT_BIT | BootImageV21.FLAGS_ENCRYPTED_SIGNED_BIT
    )
    if (
        private_key_file_path is None
        or signing_certificate_file_paths is None
        or root_key_certificate_paths is None
    ):
        click.echo(
            "error: Signed image requires private key with -s option, "
            "one or more certificate(s) using -S option and one or more root key "
            "certificates using -R option"
        )
        sys.exit(1)

    # Versions and build number are up to the user. If he doesn't provide any,
    # we set these to following values.
    product_version = parsed_bd_file["options"].get("productVersion", "")
    component_version = parsed_bd_file["options"].get("componentVersion", "")
    build_number = parsed_bd_file["options"].get("buildNumber", -1)

    if not product_version:
        product_version = "1.0.0"
        click.echo("warning: production version not defined, defaults to '1.0.0'")

    if not component_version:
        component_version = "1.0.0"
        click.echo("warning: component version not defined, defaults to '1.0.0'")

    if build_number == -1:
        build_number = 1
        click.echo("warning: build number not defined, defaults to '1.0.0'")

    if key_file_path is None:
        # Legacy elf2sb doesn't report no key provided, but this should
        # be definitely reported to tell the user, what kind of key is being
        # used
        click.echo("warning: no KEK key provided, using a zero KEK key")
        sb_kek = bytes.fromhex("0" * 64)
    else:
        with open(str(key_file_path)) as kek_key_file:
            # TODO maybe we should validate the key length and content, to make
            # sure the key provided in the file is valid??
            sb_kek = bytes.fromhex(kek_key_file.readline())

    # validate keyblobs and perform appropriate actions
    keyblobs = parsed_bd_file.get("keyblobs", [])

    # Based on content of parsed BD file, create a BootSectionV2 and assign
    # commands to them.
    # The content of section looks like this:
    # sections: [
    #   {
    #       section_id: <number>,
    #       options: {}, this is left empty for now...
    #       commands: [
    #           {<cmd1>: {<param1>: value, ...}},
    #           {<cmd2>: {<param1>: value, ...}},
    #           ...
    #       ]
    #   },
    #   {
    #       section_id: <number>,
    #       ...
    #   }
    # ]
    sb_sections = []
    bd_sections = parsed_bd_file["sections"]
    for bd_section in bd_sections:
        section_id = bd_section["section_id"]
        commands = []
        for cmd in bd_section["commands"]:
            for key, value in cmd.items():
                # we use a helper function, based on the key ('load', 'erase'
                # etc.) to create a command object. The helper function knows
                # how to handle the parameters of each command.
                # TODO Only load, fill, erase and enable commands are supported
                # for now. But there are few more to be supported...
                cmd_fce = elf2sb_helper21.get_command(key)
                if key in ("keywrap", "encrypt"):
                    keyblob = {"keyblobs": keyblobs}
                    value.update(keyblob)
                cmd = cmd_fce(value)
                commands.append(cmd)

        sb_sections.append(BootSectionV2(section_id, *commands))

    # We have a list of sections and their respective commands, lets create
    # a boot image v2.1 object
    secure_binary = BootImageV21(
        sb_kek,
        *sb_sections,
        product_version=product_version,
        component_version=component_version,
        build_number=build_number,
        flags=flags,
    )

    # create certificate block
    cert_block = CertBlockV2(build_number=build_number)
    for cert_path in signing_certificate_file_paths:
        cert_data = load_certificate_as_bytes(str(cert_path))
        cert_block.add_certificate(cert_data)
    for cert_idx, cert_path in enumerate(root_key_certificate_paths):
        cert_data = load_certificate_as_bytes(str(cert_path))
        cert_block.set_root_key_hash(cert_idx, Certificate(cert_data))

    # We have our secure binary, now we attach to it the certificate block and
    # the private key content
    # TODO legacy elf2sb doesn't require you to use certificates and private key,
    # so maybe we should make sure this is not necessary???
    # The -s/-R/-S are mandatory, 2.0 format not supported!!!
    secure_binary.cert_block = cert_block
    secure_binary.private_key_pem_data = load_binary(str(private_key_file_path))

    if hoh_out_path is None:
        hoh_out_path = os.path.join(os.getcwd(), "hash.bin")

    with open(str(hoh_out_path), "wb") as rkht_file:
        rkht_file.write(secure_binary.cert_block.rkht)

    with open(str(output_file_path), "wb") as sb_file_output:
        sb_file_output.write(secure_binary.export())

    click.echo(f"Success. (Secure binary 2.1: {output_file_path} created.)")


def generate_secure_binary_31(container_conf: click.File) -> None:
    """Geneate SecureBinary image from json configuration file.

    :param container_conf: configuration file
    :raises SPSDKError: Raised when there is no signing key
    """
    config_data = load_configuration(container_conf.name)
    schemas = SecureBinary31.get_validation_schemas(include_test_configuration=True)
    schemas.append(ValidationSchemas.get_schema_file(SB3_SCH_FILE)["sb3_output"])
    check_config(config_data, schemas)
    sb3 = SecureBinary31.load_from_config(config_data)
    sb3_data = sb3.export()

    sb3_output_file_path = config_data["containerOutputFile"]
    write_file(sb3_data, sb3_output_file_path, mode="wb")

    click.echo(f"Success. (Secure binary 3.1: {sb3_output_file_path} created.)")


@click.command(no_args_is_help=True)
@optgroup.group("Output file type generation selection.", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-c",
    "--command",
    type=click.Path(exists=True),
    help="BD configuration file to produce secure binary v2.x",
)
@optgroup.option(
    "-J",
    "--image-conf",
    type=click.File("r"),
    help="YAML/JSON image configuration file to produce master boot image",
)
@optgroup.option(
    "-j",
    "--container-conf",
    type=click.File("r"),
    help="YAML/JSON  container configuration file to produce secure binary v3.x",
)
@optgroup.option(
    "-T",
    "--tzm-conf",
    type=click.File("r"),
    help="YAML/JSON trust zone configuration file to produce trust zone binary",
)
@optgroup.option(
    "-Y",
    "--config-template",
    type=click.Path(dir_okay=True, file_okay=False),
    help="Path to store all configuration templates for selected family",
)
@click.option(
    "-f",
    "--chip-family",
    default="lpc55s3x",
    help="Select the chip family (default is lpc55s3x), this field is used with -Y/--config_template option only.",
    type=click.Choice(SUPPORTED_FAMILIES, case_sensitive=False),
)
@optgroup.group("Command file options (SB2.x file format only)")
@optgroup.option("-o", "--output", type=click.Path(), help="Output file path.")
@optgroup.option(
    "-k", "--key", type=click.Path(exists=True), help="Add a key file and enable encryption."
)
@optgroup.option(
    "-s", "--pkey", type=click.Path(exists=True), help="Path to private key for signing."
)
@optgroup.option(
    "-S",
    "--cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to certificate files for signing. The first certificate will be \
the self signed root key certificate.",
)
@optgroup.option(
    "-R",
    "--root-key-cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to root key certificate file(s) for verifying other certificates. \
Only 4 root key certificates are allowed, others are ignored. \
One of the certificates must match the first certificate passed \
with -S/--cert arg.",
)
@optgroup.option(
    "-h",
    "--hash-of-hashes",
    type=click.Path(),
    help="Path to output hash of hashes of root keys. If argument is not \
provided, then by default the tool creates hash.bin in the working directory.",
)
@click.version_option(spsdk_version, "-v", "--version")
@click.help_option("--help")
@click.argument("external", type=click.Path(), nargs=-1)
def main(
    chip_family: str,
    command: click.Path,
    output: click.Path,
    key: click.Path,
    pkey: click.Path,
    cert: List[click.Path],
    root_key_cert: List[click.Path],
    image_conf: click.File,
    container_conf: click.File,
    tzm_conf: click.File,
    config_template: click.Path,
    hash_of_hashes: click.Path,
    external: List[click.Path],
) -> None:
    """Tool for generating TrustZone, MasterBootImage and SecureBinary images."""
    if command:
        if output is None:
            click.echo("Error: no output file was specified")
            sys.exit(1)
        generate_secure_binary_21(
            bd_file_path=command,
            output_file_path=output,
            key_file_path=key,
            private_key_file_path=pkey,
            signing_certificate_file_paths=cert,
            root_key_certificate_paths=root_key_cert,
            hoh_out_path=hash_of_hashes,
            external_files=external,
        )

    if image_conf:
        generate_master_boot_image(image_conf)

    if container_conf:
        generate_secure_binary_31(container_conf)

    if tzm_conf:
        generate_trustzone_binary(tzm_conf)

    if config_template:
        generate_config_templates(chip_family, str(config_template))


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
