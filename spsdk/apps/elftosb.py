#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Elf2SB."""
import os
import sys
from datetime import datetime
from typing import List, Union

import click
import commentjson as json
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

import spsdk.apps.elftosb_utils.sb_21_helper as elf2sb_helper21
import spsdk.apps.elftosb_utils.sly_bd_parser as bd_parser
from spsdk import __version__ as spsdk_version
from spsdk.apps.elftosb_utils import sb_31_helper as elftosb_helper
from spsdk.apps.utils import catch_spsdk_error
from spsdk.crypto import SignatureProvider, load_certificate_as_bytes
from spsdk.exceptions import SPSDKError
from spsdk.image import MasterBootImage, MasterBootImageN4Analog, MasterBootImageType, TrustZone
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.sbfile.images import BootImageV21, BootSectionV2
from spsdk.sbfile.sb31.images import SecureBinary31Commands, SecureBinary31Header
from spsdk.utils.crypto import CertBlockV2, CertBlockV31, Certificate
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.utils.misc import load_binary, load_text, write_file

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
    config_data = json.load(tzm_conf)
    config = elftosb_helper.TrustZoneConfig(config_data)
    trustzone = TrustZone.custom(
        family=config.family, revision=config.revision, customizations=config.presets
    )
    tz_data = trustzone.export()
    write_file(tz_data, config.output_file, mode="wb")

    click.echo(f"Success. (Trustzone binary: {config.output_file} created.)")


def _get_trustzone(
    config: Union[
        elftosb_helper.MasterBootImageConfigGroup3, elftosb_helper.MasterBootImageConfigGroup4
    ]
) -> TrustZone:
    """Create appropriate TrustZone instance."""
    family = config.family.lower()

    if family in ["lpc55s3x"]:
        if not config.trustzone_preset_file:
            return TrustZone.enabled()

    if family in [
        "lpc55xx",
        "lpc55s0x",
        "lpc55s1x",
        "lpc552x",
        "lpc55s2x",
        "lpc55s6x",
        "rt5xx",
        "rt6xx",
    ]:
        if config.enable_trustzone is False:  # type: ignore
            # we don't care about preset data file, just "disable" TZ-M
            return TrustZone.disabled()

        if not config.trustzone_preset_file:
            # TZ-M is left enabled, but no data provided
            return TrustZone.enabled()

    try:
        tz_config_data = json.loads(load_text(config.trustzone_preset_file))
        tz_config = elftosb_helper.TrustZoneConfig(tz_config_data)
        return TrustZone.custom(
            family=tz_config.family,
            revision=tz_config.revision,
            customizations=tz_config.presets,
        )
    except ValueError:
        tz_raw_data = load_binary(config.trustzone_preset_file)
        revision = getattr(config, "revision", None)
        return TrustZone.from_binary(family=config.family, revision=revision, raw_data=tz_raw_data)


def _get_cert_block_v2(cert_config: elftosb_helper.CertificateBlockConfigGroup3) -> CertBlockV2:
    cert_block = CertBlockV2(build_number=cert_config.image_build_number)

    # add whole certificate chain used for image signing
    for cert_path in cert_config.root_certificates[cert_config.main_cert_chain_id]:
        cert_data = load_certificate_as_bytes(str(cert_path))
        cert_block.add_certificate(cert_data)
    # set root key hash of each root certificate
    for cert_idx, cert_path in enumerate(cert_config.root_certificates):
        cert_data = load_certificate_as_bytes(str(cert_path[0]))
        cert_block.set_root_key_hash(cert_idx, Certificate(cert_data))

    return cert_block


def _get_cert_block_v31(cert_config: elftosb_helper.CertificateBlockConfigGroup4) -> CertBlockV31:
    root_certs = [load_binary(cert_file) for cert_file in cert_config.root_certs]  # type: ignore
    user_data = None
    if cert_config.use_isk and cert_config.isk_sign_data_path:
        user_data = load_binary(cert_config.isk_sign_data_path)
    isk_private_key = None
    if cert_config.use_isk:
        assert cert_config.main_root_private_key_file
        isk_private_key = load_binary(cert_config.main_root_private_key_file)
    isk_cert = None
    if cert_config.use_isk:
        assert cert_config.isk_certificate
        isk_cert = load_binary(cert_config.isk_certificate)

    cert_block = CertBlockV31(
        root_certs=root_certs,
        used_root_cert=cert_config.main_root_cert_id,
        user_data=user_data,
        constraints=cert_config.isk_constraint,
        isk_cert=isk_cert,
        ca_flag=not cert_config.use_isk,
        isk_private_key=isk_private_key,
    )
    return cert_block


def generate_master_boot_image(image_conf: click.File) -> None:
    """Generate MasterBootImage from json configuration file.

    :param image_conf: master boot image json configuration file.
    :raises SPSDKError: Raised when signing private key path is not set
    :raises SPSDKError: on unsupported family.
    """
    config_data = json.load(image_conf)
    family = config_data.get("family")

    if family in [
        "lpc55xx",
        "lpc55s0x",
        "lpc55s1x",
        "lpc552x",
        "lpc55s2x",
        "lpc55s6x",
        "rt5xx",
        "rt6xx",
    ]:
        mbi = __create_mbi_group3(config_data)
    elif family in ["lpc55s3x"]:
        mbi = __create_mbi_group4(config_data)
    else:
        raise SPSDKError(f"Generating Master Boot Image failed. Family {family} is not supported.")

    mbi_data = mbi.export()

    mbi_output_file_path = config_data["masterBootOutputFile"]
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


def __create_mbi_group3(config_data: dict) -> MasterBootImage:
    """Create master boot image for group 3 devices.

    Into group 3 belongs LPC55xx (LPC552x/S2x, LPC55S6x), LPC55S0x, LPC55S1x, RT5xx, RT6xx.

    :param config: master boot image configuration data. Consult the content with elftosb user guide.
    :return: master boot image fro group 3 devices.
    :raises SPSDKError: if keystore size is of invalid size.
    :raises SPSDKError: if keystore file path is invalid.
    """
    config = elftosb_helper.MasterBootImageConfigGroup3(config_data)

    app = load_binary(config.input_image_file)
    load_addr = config.output_image_exec_address
    trustzone = _get_trustzone(config)
    image_type = config.image_type
    enable_hw_user_mode_keys = config.enable_hw_user_mode_keys

    # Create certificate block, if image is signed
    cert_block = None
    private_key_pem_data = None
    if MasterBootImageType.is_signed(image_type):
        cert_block = _get_cert_block_v2(config.certificate_block_config)
        private_key_pem_data = load_binary(
            config.certificate_block_config.main_cert_private_key_file
        )

    key_store = None
    hmac_key = None
    key_source = KeySourceType.get(config.device_key_source)
    if key_source in [KeySourceType.OTP, KeySourceType.KEYSTORE]:
        with open(config.output_image_encryption_key_file, "r") as f:
            hmac_key = f.read()

        if config.use_key_store and key_source == KeySourceType.KEYSTORE:
            try:
                if config.key_store_file.strip():
                    key_store_data = load_binary(config.key_store_file)
                    if len(key_store_data) != KeyStore.KEY_STORE_SIZE:
                        raise SPSDKError(
                            f'Expected keystore size is "{KeyStore.KEY_STORE_SIZE}", got "{len(key_store_data)}".'
                        )
                else:
                    key_store_data = bytes(KeyStore.KEY_STORE_SIZE)
            except OSError:
                raise SPSDKError(
                    f'Invalid keystore file "{config.key_store_file}" in Master Boot Image configuration file.'
                )

            key_store = KeyStore(key_source=key_source, key_store=key_store_data)  # type: ignore

    # app_table: Optional[MultipleImageTable] = None,
    # ctr_init_vector: bytes = None,
    mbi = MasterBootImage(
        app=app,
        load_addr=load_addr,
        image_type=image_type,
        trust_zone=trustzone,
        app_table=None,
        cert_block=cert_block,
        priv_key_pem_data=private_key_pem_data,
        hmac_key=hmac_key,
        key_store=key_store,
        enable_hw_user_mode_keys=enable_hw_user_mode_keys,
        # ctr_init_vector=None, # commented out due to testing purposes
    )
    return mbi


def __create_mbi_group4(config_data: dict) -> MasterBootImageN4Analog:
    """Create master boot image for group 4 devices.

    Into group 4 devices belongs LPC55S3x.

    :param config: master boot image configuration data. Consult the content with elftosb user guide.
    :return: master boot image group 4 devices.
    :raises SPSDKError: signing private key file path not set in configuration file.
    """
    config = elftosb_helper.MasterBootImageConfigGroup4(config_data)

    app = load_binary(config.input_image_file)
    load_addr = config.output_image_exec_address
    trustzone = _get_trustzone(config)
    image_type = config.image_type
    firmware_version = config.firmware_version

    cert_block = None
    signature_provider = None
    if MasterBootImageType.is_signed(image_type):
        cert_block = _get_cert_block_v31(config.certificate_block_config)
        if config.certificate_block_config.use_isk:
            signing_private_key_path = config.certificate_block_config.isk_private_key_file
        else:
            signing_private_key_path = config.certificate_block_config.main_root_private_key_file
        if not signing_private_key_path:
            raise SPSDKError("Signing private key path is not set.")
        signature_provider = SignatureProvider.create(
            f"type=file;file_path={signing_private_key_path}"
        )

    mbi = MasterBootImageN4Analog(
        app=app,
        load_addr=load_addr,
        image_type=image_type,
        trust_zone=trustzone,
        firmware_version=firmware_version,
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    return mbi


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
        hoh_out_path = os.getcwd()
        os.path.join(hoh_out_path, "hash.bin")

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
    config_data = json.load(container_conf)
    config = elftosb_helper.SB31Config(config_data)
    timestamp = config.timestamp
    if timestamp is None:
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        timestamp = int((datetime.now() - datetime(2000, 1, 1)).total_seconds())
    if isinstance(timestamp, str):
        timestamp = int(timestamp, 0)

    final_data = bytes()
    assert isinstance(config.main_curve_name, str)
    # COMMANDS
    pck = None
    if config.is_encrypted:
        assert isinstance(config.container_keyblob_enc_key_path, str)
        pck = bytes.fromhex(load_text(config.container_keyblob_enc_key_path))
    sb_cmd_block = SecureBinary31Commands(
        curve_name=config.main_curve_name,
        is_encrypted=config.is_encrypted,
        kdk_access_rights=config.kdk_access_rights,
        pck=pck,
        timestamp=timestamp,
    )
    commands = elftosb_helper.get_cmd_from_json(config)
    sb_cmd_block.set_commands(commands)

    commands_data = sb_cmd_block.export()

    # CERTIFICATE BLOCK
    cert_block = _get_cert_block_v31(config.certificate_block_config)
    data_cb = cert_block.export()

    # SB FILE HEADER
    sb_header = SecureBinary31Header(
        firmware_version=config.firmware_version,
        description=config.description,
        curve_name=config.main_curve_name,
        timestamp=timestamp,
        is_nxp_container=config.is_nxp_container,
    )
    sb_header.block_count = sb_cmd_block.block_count
    sb_header.image_total_length += len(sb_cmd_block.final_hash) + len(data_cb)
    # TODO: use proper signature len calculation
    sb_header.image_total_length += 2 * len(sb_cmd_block.final_hash)
    sb_header_data = sb_header.export()
    final_data += sb_header_data

    # HASH OF PREVIOUS BLOCK
    final_data += sb_cmd_block.final_hash
    final_data += data_cb

    # SIGNATURE
    if not config.main_signing_key:
        raise SPSDKError("There is no signing key")
    assert isinstance(config.main_signing_key, str)
    private_key_data = load_binary(config.main_signing_key)
    data_to_sign = final_data
    signature = internal_backend.ecc_sign(private_key_data, data_to_sign)
    assert internal_backend.ecc_verify(private_key_data, signature, data_to_sign)
    final_data += signature
    final_data += commands_data

    write_file(final_data, config.container_output, mode="wb")

    click.echo(f"Success. (Secure binary 3.1: {config.container_output} created.)")


@click.command(no_args_is_help=True)  # type: ignore
@click.option(
    "-f",
    "--chip-family",
    default="lpc55s3x",
    help="Select the chip family (default is lpc55s3x)",
    type=click.Choice(SUPPORTED_FAMILIES, case_sensitive=False),
)
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
    help="Json image configuration file to produce master boot image",
)
@optgroup.option(
    "-j",
    "--container-conf",
    type=click.File("r"),
    help="json container configuration file to produce secure binary v3.x",
)
@optgroup.option(
    "-T",
    "--tzm-conf",
    type=click.File("r"),
    help="json trust zone configuration file to produce trust zone binary",
)
@optgroup.group("Command file options")
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
    hash_of_hashes: click.Path,
    external: List[click.Path],
) -> None:
    """Tool for generating TrustZone, MasterBootImage and SecureBinary images."""
    if command:
        if output is None:
            click.echo("error: no output file was specified")
            sys.exit(1)
        if chip_family is None:
            click.echo("error")
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

    if chip_family not in SUPPORTED_FAMILIES:
        click.echo(f"Family '{chip_family}' is not supported")
        sys.exit(1)

    if image_conf:
        generate_master_boot_image(image_conf)

    if container_conf:
        generate_secure_binary_31(container_conf)

    if tzm_conf:
        generate_trustzone_binary(tzm_conf)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
